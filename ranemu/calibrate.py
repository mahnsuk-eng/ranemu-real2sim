#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.calibrate — 수동 측정 프로브의 오차 특성화와 보정 검증.

실험 설계
=========
    ① 에뮬레이터가 트래픽을 주입하며 **무손실 정답 pcap** 을 기록한다
       (정답 처리량 R_true 는 manifest 에서 바이트/시간으로 확정)
              │
    ② 정답 pcap 에 **알려진 손상**(포화 tail-drop / 균등손실 / 합침 / 중복 / 절단)을 주입
              │
    ③ 손상된 pcap 을 **기존 프로브(dpi_engine)** 로 분석 → 보고값 R_probe
              │
    ④ 같은 pcap 을 **보정 추정기**로 분석 → 보정값 R_corr
              │
    ⑤ |R_probe − R_true| 와 |R_corr − R_true| 를 비교

손상량을 우리가 정하므로 정답을 알고, 프로브가 얼마나 틀리는지와 보정이 그 오차를
얼마나 회수하는지를 통제된 조건에서 잴 수 있다. 실 코어 없이 성립하는 실험이다.
"""
from __future__ import annotations

import json
import os
import statistics
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .estimator import estimate_from_pcap
from .impair import ImpairmentConfig, apply_to_pcap
from .util import get_logger

log = get_logger("ranemu.calibrate")

SOLUTION_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_dpi():
    if SOLUTION_DIR not in sys.path:
        sys.path.insert(0, SOLUTION_DIR)
    try:
        import dpi_engine
        return dpi_engine
    except Exception as e:  # noqa: BLE001
        log.warning("dpi_engine 로드 실패: %s", e)
        return None


def probe_measure(pcap: str, link_mbps: float = 1000.0) -> Dict[str, Any]:
    """기존 프로브(dpi_engine)로 단말별 처리량을 측정한다."""
    dpi = _load_dpi()
    if dpi is None:
        return {"ok": False, "error": "dpi_engine 없음", "by_ue": []}
    try:
        res = dpi.analyze_pcap(pcap, dedup=True, link_mbps=link_mbps,
                               fast=True, udpq=False)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"분석 실패: {e}", "by_ue": []}
    by_ue = (res.get("summary") or {}).get("by_ue") or []
    return {"ok": True, "by_ue": by_ue, "meta": res.get("meta", {})}


def _probe_ul_bps(rec: Dict[str, Any]) -> Optional[float]:
    """프로브 레코드에서 상향 대표 처리량(bps)."""
    for key in ("ul_sustained_bps", "avg_ul_bps"):
        v = rec.get(key)
        if v:
            return float(v)
    return None


@dataclass
class CalibrationPoint:
    """손상 조건 하나에 대한 결과."""
    label: str
    params: Dict[str, Any]
    actual_loss: float = 0.0
    coalescing_ratio: float = 0.0
    packets_kept: int = 0
    truth_mbps: float = 0.0
    probe_mbps: Optional[float] = None
    corrected_mbps: Optional[float] = None
    estimated_loss: Optional[float] = None

    @property
    def probe_error_pct(self) -> Optional[float]:
        if self.probe_mbps is None or self.truth_mbps <= 0:
            return None
        return (self.probe_mbps - self.truth_mbps) / self.truth_mbps * 100.0

    @property
    def corrected_error_pct(self) -> Optional[float]:
        if self.corrected_mbps is None or self.truth_mbps <= 0:
            return None
        return (self.corrected_mbps - self.truth_mbps) / self.truth_mbps * 100.0

    @property
    def loss_estimate_error(self) -> Optional[float]:
        if self.estimated_loss is None:
            return None
        return (self.estimated_loss - self.actual_loss) * 100.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label, "params": self.params,
            "actual_loss_pct": round(self.actual_loss * 100, 3),
            "estimated_loss_pct": (round(self.estimated_loss * 100, 3)
                                   if self.estimated_loss is not None else None),
            "loss_estimate_error_pp": (round(self.loss_estimate_error, 3)
                                       if self.loss_estimate_error is not None else None),
            "coalescing_ratio": round(self.coalescing_ratio, 4),
            "truth_mbps": round(self.truth_mbps, 4),
            "probe_mbps": (round(self.probe_mbps, 4) if self.probe_mbps else None),
            "corrected_mbps": (round(self.corrected_mbps, 4)
                               if self.corrected_mbps else None),
            "probe_error_pct": (round(self.probe_error_pct, 3)
                                if self.probe_error_pct is not None else None),
            "corrected_error_pct": (round(self.corrected_error_pct, 3)
                                    if self.corrected_error_pct is not None else None),
        }


def truth_from_pcap(pcap: str) -> Tuple[float, int]:
    """정답 pcap 자체에서 (처리량 Mb/s, 패킷수) 를 구한다.

    manifest 의 주입 통계와 독립적인 두 번째 기준선이다(둘이 일치해야 한다).
    """
    est = estimate_from_pcap(pcap)
    if not est.flows:
        return 0.0, 0
    total_bps = sum(f.measured_bps for f in est.flows)
    return total_bps / 1e6, est.gtpu_packets


def sweep(truth_pcap: str, conditions: List[Tuple[str, ImpairmentConfig]], *,
          workdir: Optional[str] = None, link_mbps: float = 1000.0,
          run_probe: bool = True) -> List[CalibrationPoint]:
    """손상 조건 목록에 대해 프로브 오차와 보정 오차를 측정한다."""
    truth_mbps, truth_pkts = truth_from_pcap(truth_pcap)
    log.info("정답: %.3f Mb/s, %d 패킷", truth_mbps, truth_pkts)

    tmp = workdir or tempfile.mkdtemp(prefix="ranemu-cal-")
    os.makedirs(tmp, exist_ok=True)
    points: List[CalibrationPoint] = []

    for label, cfg in conditions:
        dst = os.path.join(tmp, f"imp_{label.replace('/', '_').replace(' ', '')}.pcap")
        st = apply_to_pcap(truth_pcap, dst, cfg)
        pt = CalibrationPoint(
            label=label,
            params={k: v for k, v in cfg.__dict__.items() if v not in (0, 0.0, None, 1.0)},
            actual_loss=st.loss_rate_actual,
            coalescing_ratio=st.coalescing_ratio,
            packets_kept=st.packets_out,
            truth_mbps=truth_mbps)

        # 보정 추정기
        est = estimate_from_pcap(dst)
        if est.flows:
            pt.estimated_loss = est.aggregate_loss_rate
            pt.corrected_mbps = sum(f.corrected_bps for f in est.flows) / 1e6

        # 기존 프로브
        if run_probe:
            pm = probe_measure(dst, link_mbps=link_mbps)
            if pm.get("ok") and pm["by_ue"]:
                total = 0.0
                for rec in pm["by_ue"]:
                    v = _probe_ul_bps(rec)
                    if v:
                        total += v
                pt.probe_mbps = total / 1e6 if total else None
        points.append(pt)
        log.info("%-22s 손실 실제 %5.1f%% 추정 %5.1f%% | 프로브 %8.2f (%+6.1f%%) "
                 "| 보정 %8.2f (%+5.1f%%) Mb/s", label,
                 pt.actual_loss * 100,
                 (pt.estimated_loss or 0) * 100,
                 pt.probe_mbps or 0, pt.probe_error_pct or 0,
                 pt.corrected_mbps or 0, pt.corrected_error_pct or 0)
    return points


def default_conditions(seed: int = 42) -> List[Tuple[str, ImpairmentConfig]]:
    """논문 실험용 표준 손상 조건."""
    conds: List[Tuple[str, ImpairmentConfig]] = [("clean", ImpairmentConfig(seed=seed))]
    for p in (2, 5, 10, 20, 30, 40, 50, 60):
        conds.append((f"loss{p}", ImpairmentConfig(loss_rate=p / 100.0, seed=seed)))
    # 포화 조건은 실제 주입률 주변이어야 의미가 있다(용량이 트래픽보다 크면 손실 0)
    for cap in (300, 250, 200, 150, 100, 50):
        conds.append((f"sat{cap}", ImpairmentConfig(capacity_mbps=float(cap), seed=seed)))
    conds.append(("coalesce4", ImpairmentConfig(coalesce_batch=4.0, seed=seed)))
    conds.append(("dup30", ImpairmentConfig(duplicate_rate=0.30, seed=seed)))
    conds.append(("snap128", ImpairmentConfig(snaplen=128, seed=seed)))
    conds.append(("loss20+dup20", ImpairmentConfig(loss_rate=0.20, duplicate_rate=0.20,
                                                   seed=seed)))
    conds.append(("loss30+coal4", ImpairmentConfig(loss_rate=0.30, coalesce_batch=4.0,
                                                   seed=seed)))
    conds.append(("sat500+coal4+dup20",
                  ImpairmentConfig(capacity_mbps=500.0, coalesce_batch=4.0,
                                   duplicate_rate=0.20, seed=seed)))
    return conds


def summarize(points: List[CalibrationPoint]) -> Dict[str, Any]:
    """스윕 결과 요약: 보정이 오차를 얼마나 줄였는가."""
    lossy = [p for p in points if p.actual_loss > 0.01]
    loss_err = [abs(p.loss_estimate_error) for p in points
                if p.loss_estimate_error is not None]
    out: Dict[str, Any] = {
        "n_conditions": len(points),
        "n_lossy": len(lossy),
        "loss_estimate_max_error_pp": round(max(loss_err), 3) if loss_err else None,
        "loss_estimate_mean_error_pp": (round(statistics.mean(loss_err), 3)
                                        if loss_err else None),
    }

    # 보정 정확도는 프로브 실행 여부와 무관하게 산출한다
    ce = [abs(p.corrected_error_pct) for p in lossy
          if p.corrected_error_pct is not None]
    if ce:
        out["corrected_mean_abs_error_pct"] = round(statistics.mean(ce), 3)
        out["corrected_max_abs_error_pct"] = round(max(ce), 3)

    # 프로브 대비 개선은 두 값이 모두 있는 조건에서만
    paired = [p for p in lossy
              if p.probe_error_pct is not None and p.corrected_error_pct is not None]
    if paired:
        pe = [abs(p.probe_error_pct) for p in paired]
        pce = [abs(p.corrected_error_pct) for p in paired]
        out.update({
            "n_paired": len(paired),
            "probe_mean_abs_error_pct": round(statistics.mean(pe), 3),
            "probe_max_abs_error_pct": round(max(pe), 3),
            "paired_corrected_mean_abs_error_pct": round(statistics.mean(pce), 3),
            "error_reduction_factor": (round(statistics.mean(pe) / statistics.mean(pce), 2)
                                       if statistics.mean(pce) > 1e-9 else None),
        })
    return out


def render_table(points: List[CalibrationPoint]) -> str:
    hdr = (f"{'조건':<20}{'실손실%':>8}{'추정%':>8}{'정답':>9}{'프로브':>9}"
           f"{'오차%':>8}{'보정':>9}{'오차%':>8}")
    lines = [hdr, "─" * len(hdr)]
    for p in points:
        lines.append(
            f"{p.label:<20}{p.actual_loss*100:>8.1f}"
            f"{(p.estimated_loss or 0)*100:>8.1f}"
            f"{p.truth_mbps:>9.2f}"
            f"{(p.probe_mbps or 0):>9.2f}"
            f"{(p.probe_error_pct or 0):>8.1f}"
            f"{(p.corrected_mbps or 0):>9.2f}"
            f"{(p.corrected_error_pct or 0):>8.1f}")
    return "\n".join(lines)


def selftest(verbose: bool = False) -> bool:
    """소규모 정답 pcap 으로 교정 파이프라인 전체를 점검."""
    from .pcapio import GtpuFramer, PcapWriter
    from .transport.gtpu import Ipv4UdpTemplate, encode, MSG_GPDU

    ok = True
    with tempfile.TemporaryDirectory(prefix="ranemu-calst-") as td:
        src = os.path.join(td, "truth.pcap")
        fr = GtpuFramer("10.1.16.52", "10.1.16.60")
        tmpl = Ipv4UdpTemplate("10.45.0.7", "8.8.8.8", 40000, 33434, payload_len=1372)
        n, gap = 4000, 1e-4
        with PcapWriter(src) as w:
            for i in range(n):
                w.write(1700000000.0 + i * gap,
                        fr.frame(encode(MSG_GPDU, 0x2001, tmpl.build(i & 0xFFFF),
                                        sequence=i & 0xFFFF, qfi=1)))

        tm, tp = truth_from_pcap(src)
        if tp != n or tm <= 0:
            ok = False
            print(f"  [CAL] 정답 산출 오류: {tm} Mb/s, {tp} 패킷")
        elif verbose:
            print(f"  [CAL] 정답 pcap {tp}패킷 {tm:.2f} Mb/s OK")

        conds = [("clean", ImpairmentConfig()),
                 ("loss20", ImpairmentConfig(loss_rate=0.2, seed=3)),
                 ("loss50", ImpairmentConfig(loss_rate=0.5, seed=3))]
        pts = sweep(src, conds, workdir=td, run_probe=False)
        if len(pts) != 3:
            ok = False
            print("  [CAL] 스윕 결과 수 불일치")
        for p in pts[1:]:
            if p.corrected_error_pct is None or abs(p.corrected_error_pct) > 2.0:
                ok = False
                print(f"  [CAL] {p.label} 보정 오차 과다: {p.corrected_error_pct}")
        if ok and verbose:
            print(f"  [CAL] 손상 스윕 3조건 보정 오차 "
                  f"{[round(abs(p.corrected_error_pct or 0),2) for p in pts]}% OK")

        s = summarize(pts)
        if (s["n_conditions"] != 3 or s["n_lossy"] != 2
                or s.get("corrected_max_abs_error_pct") is None):
            ok = False
            print(f"  [CAL] 요약 생성 실패: {s}")
        elif verbose:
            print(f"  [CAL] 요약: 손실조건 {s['n_lossy']}개, 손실추정 최대오차 "
                  f"{s['loss_estimate_max_error_pp']}pp, 보정 최대오차 "
                  f"{s['corrected_max_abs_error_pct']}% OK")
        try:
            render_table(pts)
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  [CAL] 표 렌더링 실패: {e}")
    return ok


if __name__ == "__main__":
    print("CALIBRATE selftest:", "PASS" if selftest(verbose=True) else "FAIL")
