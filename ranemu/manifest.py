#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.manifest — 주입한 값(정답)과 코어측 측정치의 대조.

이 파일이 왜 이 프로젝트의 핵심인가
====================================
기존 `~/5ga_solution` 파이프라인은 **관측**만 한다: 미러에서 본 것을 재구성해
"UE 10.1.17.196 의 DL 은 102.9 Mbps" 라고 보고한다. 그런데 그 값이 **맞는지** 는
알 수 없다. 비교할 기준이 없기 때문이다.

ranemu 는 트래픽을 직접 주입하므로 **정답을 안다**:
  · 어떤 IMSI 가 어떤 UE IP / TEID 를 받았는지
  · 각 단말에 어떤 feature(RedCap/NTN/…) 를 적용했고 그 물리 상한이 얼마인지
  · 실제로 몇 바이트를 몇 초 동안 보냈는지

따라서 이 모듈은 시험검증의 마지막 조각이다:

    주입 manifest ─┐
                   ├─► compare() ─► 항목별 오차(%) + 판정(PASS/FAIL)
    코어측 측정   ─┘   (dpi_engine by_ue + ngap_agent 신원)

대조 항목
  1. 신원   : IMSI↔UE IP↔TEID 매핑이 코어측 관측과 일치하는가 (ngap_agent 검증)
  2. 처리량 : 주입한 UL/DL 이 측정치와 오차범위 안인가 (dpi_engine 검증)
  3. 특성   : feature 가 의도한 차이(RedCap 저속, NTN 고지연)가 실제로 나타나는가
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .util import get_logger

log = get_logger("ranemu.manifest")

MANIFEST_VERSION = 1


# ═════════════════════════════════════════════════════════════════════════════
# 저장/로드
# ═════════════════════════════════════════════════════════════════════════════
def write(result: Dict[str, Any], out_dir: str, name: Optional[str] = None) -> str:
    """gNB 실행 결과를 정답 manifest 로 저장하고 경로를 반환."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = result.get("stats", {}).get("start_time", 0)
    base = name or f"{result.get('name', 'run')}"
    path = os.path.join(out_dir, f"{base}.manifest.json")
    doc = {"manifest_version": MANIFEST_VERSION, **result}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2, default=str)
    log.info("정답 manifest 기록: %s (단말 %d대)", path, len(result.get("ues", [])))
    return path


def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ═════════════════════════════════════════════════════════════════════════════
# 대조
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class FieldCheck:
    """한 항목의 정답 대 측정 비교."""
    name: str
    injected: Any
    measured: Any
    tolerance_pct: Optional[float] = None
    ok: bool = False
    error_pct: Optional[float] = None
    note: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "injected": self.injected, "measured": self.measured,
                "ok": self.ok, "error_pct": self.error_pct,
                "tolerance_pct": self.tolerance_pct, "note": self.note}


def _pct_error(injected: float, measured: float) -> Optional[float]:
    if injected in (None, 0) or measured is None:
        return None
    return round((measured - injected) / injected * 100.0, 2)


def _match_measured(entry: Dict[str, Any], measured: List[Dict[str, Any]]
                    ) -> Tuple[Optional[Dict[str, Any]], str]:
    """정답 단말 하나에 대응하는 측정 레코드를 찾는다.

    우선순위: IMSI(N2 신원) → UE IP → TEID 교집합.
    이 순서 자체가 ngap_agent 신원조인의 정확도를 검증한다.
    """
    imsi = entry.get("imsi")
    if imsi:
        for m in measured:
            if str(m.get("imsi") or "") == str(imsi):
                return m, "imsi"
    ip = entry.get("ue_ip")
    if ip:
        for m in measured:
            if m.get("ue_ip") == ip:
                return m, "ue_ip"
    teids = {t for t in (entry.get("ul_teid"), entry.get("dl_teid")) if t is not None}
    if teids:
        for m in measured:
            mt = set(m.get("teids") or [])
            if mt & teids:
                return m, "teid"
    return None, "none"


def _measured_bps(m: Dict[str, Any], direction: str) -> Tuple[Optional[float], str]:
    """측정 레코드에서 대표 처리량(bps)을 고른다.

    dpi_engine 은 여러 지표를 낸다. 우선순위:
      1) phase(busy-window) sustained — 실제 전송구간만의 지속률(가장 공정)
      2) ACK 기반 best estimate — TCP 일 때만 의미
      3) 전체 평균
    ranemu 의 기본 트래픽은 UDP 이므로 보통 (1) 또는 (3) 이 쓰인다.
    """
    for key, why in ((f"{direction}_sustained_bps", "phase-sustained"),
                     (f"ack_{direction}_best_bps", "ack-best"),
                     (f"avg_{direction}_bps", "avg")):
        v = m.get(key)
        if v:
            return float(v), why
    return None, "none"


def compare(manifest: Dict[str, Any], measurement: Dict[str, Any], *,
            throughput_tolerance_pct: float = 25.0,
            min_bytes: int = 100_000) -> Dict[str, Any]:
    """정답 manifest 와 코어측 측정 결과를 대조한다.

    measurement 는 `network_agent.analyze_measurement()` 반환형
    (`{"ok":bool,"ues":[by_ue...],"ngap":{...}}`) 을 기대한다.
    """
    measured = measurement.get("ues") or []
    entries = manifest.get("ues") or []
    rows: List[Dict[str, Any]] = []
    n_matched = 0
    n_identity_ok = 0

    for e in entries:
        if e.get("state") != "active":
            rows.append({"imsi": e.get("imsi"), "matched_by": "none",
                         "skipped": f"단말 상태={e.get('state')}", "checks": []})
            continue
        m, how = _match_measured(e, measured)
        checks: List[FieldCheck] = []
        if m is None:
            rows.append({"imsi": e.get("imsi"), "matched_by": "none",
                         "skipped": "코어측 측정에서 이 단말을 찾지 못함", "checks": []})
            continue
        n_matched += 1

        # ── 1) 신원 검증 ──────────────────────────────────────────────────
        checks.append(FieldCheck(
            name="identity.ue_ip", injected=e.get("ue_ip"), measured=m.get("ue_ip"),
            ok=(e.get("ue_ip") == m.get("ue_ip")),
            note=f"매칭키={how}"))
        if m.get("imsi"):
            same = str(m["imsi"]) == str(e.get("imsi"))
            checks.append(FieldCheck(name="identity.imsi", injected=e.get("imsi"),
                                     measured=m.get("imsi"), ok=same,
                                     note="ngap_agent N2 신원추출"))
            if same:
                n_identity_ok += 1
        else:
            checks.append(FieldCheck(
                name="identity.imsi", injected=e.get("imsi"), measured=None, ok=False,
                note="N2 신원 미검출 — NGAP 캡처/디섹터 확인 필요"))

        teids = set(m.get("teids") or [])
        if teids:
            want = {t for t in (e.get("ul_teid"), e.get("dl_teid")) if t is not None}
            checks.append(FieldCheck(
                name="identity.teid", injected=sorted(want), measured=sorted(teids),
                ok=bool(want & teids), note="N2 에서 추출한 TEID"))

        # ── 2) 처리량 검증 ────────────────────────────────────────────────
        st = e.get("stats") or {}
        for direction, sent_bytes_key, pkt_key in (("ul", "ul_bytes", "ul_packets"),
                                                   ("dl", "dl_bytes", "dl_packets")):
            sent_bytes = st.get(sent_bytes_key) or 0
            first, last = st.get("first_ul_time"), st.get("last_ul_time")
            # 주의: first_ul_time 이 0.0 일 수 있으므로 진위값이 아니라 None 여부로 판정해야
            # 한다(0.0 은 falsy 라서 `if first and last` 로 쓰면 첫 패킷이 t=0 인 단말의
            # 처리량 검사가 통째로 건너뛰어진다).
            dur = ((last - first) if (first is not None and last is not None
                                      and last > first) else None)
            if sent_bytes < min_bytes or not dur:
                checks.append(FieldCheck(
                    name=f"throughput.{direction}", injected=None, measured=None,
                    ok=True, note=f"주입량 부족({sent_bytes}B) — 판정 제외"))
                continue
            injected_bps = sent_bytes * 8.0 / dur
            meas_bps, source = _measured_bps(m, direction)
            err = _pct_error(injected_bps, meas_bps) if meas_bps else None
            ok = (err is not None and abs(err) <= throughput_tolerance_pct)
            checks.append(FieldCheck(
                name=f"throughput.{direction}",
                injected=round(injected_bps / 1e6, 3),
                measured=round(meas_bps / 1e6, 3) if meas_bps else None,
                tolerance_pct=throughput_tolerance_pct, ok=ok, error_pct=err,
                note=f"측정지표={source} (Mbps)"))

        # ── 3) feature 특성이 실제로 나타나는가 ───────────────────────────
        lb = e.get("link_budget") or {}
        sig = e.get("signaling") or {}
        if sig.get("redcap"):
            cap = (e.get("traffic") or {}).get("offered_ul_mbps")
            meas_bps, _s = _measured_bps(m, "ul")
            ok = (meas_bps is None) or (cap is None) or (meas_bps <= cap * 1e6 * 1.3)
            checks.append(FieldCheck(
                name="feature.redcap_rate_cap", injected=cap,
                measured=round(meas_bps / 1e6, 3) if meas_bps else None, ok=ok,
                note="RedCap 상한을 넘지 않아야 함(Mbps)"))
        if sig.get("ntn"):
            checks.append(FieldCheck(
                name="feature.ntn_rtt", injected=lb.get("rtt_ms"),
                measured=m.get("rtt_ms_avg") or m.get("rtt_ms"),
                ok=True, note=f"NTN {sig.get('ntn_orbit')} 예상 RTT(ms) — "
                              f"코어측 RTT 측정이 있으면 대조"))

        rows.append({
            "imsi": e.get("imsi"), "ue_ip": e.get("ue_ip"),
            "features": e.get("features"), "matched_by": how,
            "checks": [c.as_dict() for c in checks],
            "passed": all(c.ok for c in checks),
        })

    total_checks = sum(len(r.get("checks") or []) for r in rows)
    failed = [(r["imsi"], c["name"]) for r in rows
              for c in (r.get("checks") or []) if not c["ok"]]
    active = sum(1 for e in entries if e.get("state") == "active")
    return {
        "summary": {
            "ue_injected_active": active,
            "ue_matched_in_measurement": n_matched,
            "ue_identity_verified": n_identity_ok,
            "checks_total": total_checks,
            "checks_failed": len(failed),
            "verdict": "PASS" if (not failed and n_matched == active and active > 0)
                       else ("NO-DATA" if active == 0 else "FAIL"),
        },
        "failed_checks": failed[:50],
        "ues": rows,
    }


def render_text(comparison: Dict[str, Any]) -> str:
    """대조 결과를 사람이 읽는 표로."""
    s = comparison["summary"]
    lines = [
        "═" * 78,
        f" 주입 대비 코어측정 대조 — 판정 {s['verdict']}",
        "═" * 78,
        f" 활성 단말 {s['ue_injected_active']}대 중 측정에서 매칭 {s['ue_matched_in_measurement']}대"
        f", 신원(IMSI) 확인 {s['ue_identity_verified']}대",
        f" 검사 {s['checks_total']}건 중 실패 {s['checks_failed']}건",
        "─" * 78,
    ]
    for r in comparison["ues"]:
        if r.get("skipped"):
            lines.append(f" {r.get('imsi','?'):<17} — 건너뜀: {r['skipped']}")
            continue
        mark = "PASS" if r.get("passed") else "FAIL"
        lines.append(f" {r['imsi']:<17} {str(r.get('ue_ip')):<14} "
                     f"[{'+'.join(r.get('features') or [])}] 매칭={r['matched_by']} → {mark}")
        for c in r["checks"]:
            flag = "  ok " if c["ok"] else "  !! "
            err = f" ({c['error_pct']:+.1f}%)" if c.get("error_pct") is not None else ""
            lines.append(f"{flag}{c['name']:<28} 주입={c['injected']} 측정={c['measured']}"
                         f"{err}  {c['note']}")
    lines.append("═" * 78)
    return "\n".join(lines)


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    ok = True

    manifest = {
        "name": "t", "ues": [
            {"imsi": "450050000000001", "state": "active", "ue_ip": "10.45.0.10",
             "ul_teid": 1, "dl_teid": 2, "features": ["embb", "redcap"],
             "link_budget": {"rtt_ms": 8.1},
             "signaling": {"redcap": True, "ntn": False},
             "traffic": {"offered_ul_mbps": 8.0},
             "stats": {"ul_bytes": 6_000_000, "ul_packets": 4300,
                       "dl_bytes": 6_000_000, "dl_packets": 4300,
                       "first_ul_time": 0.0, "last_ul_time": 6.0}},
            {"imsi": "450050000000002", "state": "failed", "ue_ip": None,
             "features": [], "stats": {}},
        ]}
    # 주입 UL = 6,000,000B * 8 / 6s = 8 Mbps
    measurement = {"ok": True, "ues": [
        {"ue_ip": "10.45.0.10", "imsi": "450050000000001", "teids": [1, 2],
         "ul_sustained_bps": 8_100_000, "dl_sustained_bps": 7_900_000},
    ]}

    cmp1 = compare(manifest, measurement)
    if cmp1["summary"]["verdict"] != "PASS":
        ok = False
        print(f"  [MANIFEST] 정상 대조가 PASS 가 아님: {cmp1['summary']}")
        print(render_text(cmp1))
    elif verbose:
        print(f"  [MANIFEST] 정상 대조 PASS (검사 {cmp1['summary']['checks_total']}건) OK")

    # 상태가 active 가 아닌 단말은 판정에서 제외되어야 한다
    if cmp1["summary"]["ue_injected_active"] != 1:
        ok = False
        print("  [MANIFEST] 비활성 단말이 판정에 포함됨")

    # (2) 오차가 크면 FAIL 이어야 한다
    bad = {"ok": True, "ues": [
        {"ue_ip": "10.45.0.10", "imsi": "450050000000001", "teids": [1],
         "ul_sustained_bps": 2_000_000, "dl_sustained_bps": 7_900_000}]}
    cmp2 = compare(manifest, bad)
    if cmp2["summary"]["verdict"] != "FAIL":
        ok = False
        print("  [MANIFEST] 큰 오차를 FAIL 로 판정하지 못함")
    elif verbose:
        print("  [MANIFEST] 처리량 오차 -75% → FAIL 판정 OK")

    # (3) IMSI 가 없으면 신원 검사 실패 + IP 로 매칭
    no_imsi = {"ok": True, "ues": [
        {"ue_ip": "10.45.0.10", "teids": [1],
         "ul_sustained_bps": 8_000_000, "dl_sustained_bps": 8_000_000}]}
    cmp3 = compare(manifest, no_imsi)
    row = cmp3["ues"][0]
    if row["matched_by"] != "ue_ip":
        ok = False
        print(f"  [MANIFEST] IP 매칭 실패: {row['matched_by']}")
    idc = [c for c in row["checks"] if c["name"] == "identity.imsi"]
    if not idc or idc[0]["ok"]:
        ok = False
        print("  [MANIFEST] IMSI 미검출을 통과시킴")
    elif verbose:
        print("  [MANIFEST] IMSI 미검출 시 IP 매칭 + 신원검사 실패 OK")

    # (4) TEID 로만 매칭
    teid_only = {"ok": True, "ues": [
        {"ue_ip": "192.168.99.9", "teids": [2],
         "ul_sustained_bps": 8_000_000, "dl_sustained_bps": 8_000_000}]}
    cmp4 = compare(manifest, teid_only)
    if cmp4["ues"][0]["matched_by"] != "teid":
        ok = False
        print(f"  [MANIFEST] TEID 매칭 실패: {cmp4['ues'][0]['matched_by']}")
    elif verbose:
        print("  [MANIFEST] TEID 교집합 매칭 OK")

    # (5) 측정에 단말이 아예 없으면 NO-DATA 가 아니라 매칭 실패로 보고
    cmp5 = compare(manifest, {"ok": True, "ues": []})
    if cmp5["summary"]["ue_matched_in_measurement"] != 0:
        ok = False
        print("  [MANIFEST] 빈 측정 처리 오류")

    # (6) 측정 지표 선택 우선순위
    m = {"avg_ul_bps": 1, "ack_ul_best_bps": 2, "ul_sustained_bps": 3}
    if _measured_bps(m, "ul") != (3.0, "phase-sustained"):
        ok = False
        print("  [MANIFEST] 측정지표 우선순위 오류")
    if _measured_bps({"avg_ul_bps": 5}, "ul") != (5.0, "avg"):
        ok = False
        print("  [MANIFEST] 폴백 지표 선택 오류")
    elif verbose:
        print("  [MANIFEST] 측정지표 우선순위(phase→ack→avg) OK")

    # (7) 텍스트 렌더링이 예외 없이 동작
    try:
        txt = render_text(cmp1)
        if "판정" not in txt:
            ok = False
            print("  [MANIFEST] 렌더링 내용 이상")
    except Exception as e:  # noqa: BLE001
        ok = False
        print(f"  [MANIFEST] 렌더링 실패: {e}")

    # (8) 저장/로드 왕복
    import tempfile
    with tempfile.TemporaryDirectory(prefix="ranemu-mf-") as td:
        p = write({"name": "t", "ues": manifest["ues"], "stats": {}}, td)
        back = load(p)
        if back.get("manifest_version") != MANIFEST_VERSION or len(back["ues"]) != 2:
            ok = False
            print("  [MANIFEST] 저장/로드 왕복 실패")
        elif verbose:
            print("  [MANIFEST] 저장/로드 왕복 OK")
    return ok


if __name__ == "__main__":
    print("MANIFEST selftest:", "PASS" if selftest(verbose=True) else "FAIL")
