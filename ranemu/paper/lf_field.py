#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.paper.lf_field — 실측 N3 미러 캡처에서 단말별 부하계수 분포를 뽑는다.

왜 필요한가
===========
Real2Sim 의 전제는 "벤더 데이터시트가 아니라 **운영자 자신이 측정한 부하분포**로
보정한다" 는 것이다. 그런데 그 분포를 합성 트래픽으로 대신하면 전제가 비어 버린다.
이 모듈은 실제 사설 5G 망에서 받은 N3 미러 캡처를 그대로 읽어

    (단말, 방향, 5초 창) → 처리량 → LF = clip(R/P, LF_min, LF_max)

를 만들고, 그 **실제 운영점 분포 위에서** 오차예산(lf_bridge 의 증폭계수 A)을
평가한다. 논문이 쓰는 "A ≈ 1.6" 같은 값이 임의로 고른 LF=0.65 에서가 아니라
실측 분포에서 나오게 하기 위한 것이다.

미러 캡처의 두 가지 함정(이 코드가 다루는 것)
--------------------------------------------
1. **중복.** 같은 사용자평면 패킷이 N3 양단(및 N6)에서 여러 번 잡힌다. 실측
   중복배수는 1.5~2.0배다. 그냥 바이트를 더하면 처리량이 그만큼 부풀려지고, LF 도
   부풀려지고, 예측 이득도 부풀려진다. TCP 는 (흐름, 시퀀스, 길이) 동일성으로,
   UDP 는 (5-튜플, ip.id, 길이) 동일성으로 전역 중복을 제거한다.
2. **포화 손실.** 1 GbE 미러는 피크에서 tail-drop 한다. 이것은 여기서 고칠 수 없고,
   바로 그 오차가 lf_bridge 가 정량화하는 대상이다. 여기서는 창별로 링크율 대비
   점유율을 남겨 어느 창이 포화 위험 구간인지 표시만 한다.

재현:
    python3 -m ranemu.paper.lf_field --pcap real_dataset/250826/250826_1030_1130.pcap \
        --out ranemu/paper/v4
"""
from __future__ import annotations

import argparse
import json
import math
import os
import statistics
import subprocess
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .lf_bridge import FEATURES, amplification, load_factor
from ..util import get_logger

log = get_logger("ranemu.paper.lffield")

V4 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v4")

#: GERI 테스트베드 단일 UE 정격 피크. 출처: imsi_450001020001436_260430_0557.pcap
#: (Ookla Speedtest 단일 UE 측정) — 제출본 §4.1 의 NOKIA_PEAKS 와 같은 값.
PEAK_DL_MBPS = 914.0
PEAK_UL_MBPS = 80.7

#: tshark 로 뽑을 필드. `-E occurrence=l` 이 GTP-U/VLAN 의 **안쪽** 계층을 준다.
_FIELDS = ["frame.time_epoch", "ip.src", "ip.dst", "ip.len", "ip.proto",
           "ip.id", "tcp.seq", "tcp.len", "tcp.srcport", "tcp.dstport",
           "udp.srcport", "udp.dstport"]


def _tshark(pcap: str, limit: int = 0) -> Any:
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "occurrence=l",
           "-E", "separator=\t"]
    for f in _FIELDS:
        cmd += ["-e", f]
    if limit:
        cmd += ["-c", str(limit)]
    log.info("tshark 추출: %s", os.path.basename(pcap))
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, text=True, bufsize=1 << 20)
    assert p.stdout is not None
    for line in p.stdout:
        yield line.rstrip("\n").split("\t")
    p.wait()


def _is_private(ip: str) -> bool:
    """RFC 1918 사설 주소인가 — 단말 측 후보."""
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except ValueError:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


def extract_windows(pcap: str, *, window_s: float = 5.0,
                    ue_subnet: Optional[str] = None,
                    min_peers: int = 20,
                    limit: int = 0) -> Dict[str, Any]:
    """캡처를 (단말, 방향, 창) 별 고유 바이트로 접는다.

    **단말 식별이 이 함수의 핵심이다.** 처음에는 "하향 바이트를 가장 많이 내보내는
    주소가 서버" 라고 가정하고 그 서버와 오간 것만 셌는데, 실제 운용 캡처는 단말
    하나가 수백 개 인터넷 서버와 통신하는 구조라 대부분의 트래픽을 버렸다(그래서
    처리량과 부하계수가 과소평가됐다). 서버는 하나가 아니다 — **단말이 하나(소수)다.**

    그래서 단말 쪽을 식별한다. 명시된 서브넷이 있으면 그것을 쓰고, 없으면 사설
    주소이면서 **서로 다른 피어 수가 많은** 호스트를 단말로 본다(단말은 여러
    서버와 통신하고, 서버는 단말 몇 대와만 통신한다). 방향은 단말 기준으로
    정한다: 단말→ 무엇이든 = UL, 무엇이든 →단말 = DL.
    """
    peers: Dict[str, set] = defaultdict(set)
    rows: List[Tuple[float, str, str, int, str]] = []
    seen_tcp: set = set()
    seen_udp: set = set()
    naive_bytes = 0
    dup_bytes = 0
    n_pkt = 0

    for r in _tshark(pcap, limit):
        if len(r) < len(_FIELDS):
            continue
        ts_s, src, dst, iplen, proto, ipid, tseq, tlen, tsp, tdp, usp, udp_p = r[:12]
        if not src or not dst or not iplen:
            continue
        try:
            ts = float(ts_s)
            nbytes = int(iplen)
        except ValueError:
            continue
        n_pkt += 1
        naive_bytes += nbytes
        # ── 전역 중복 제거 ────────────────────────────────────────────────
        if proto == "6" and tseq:
            key = (src, dst, tsp, tdp, tseq, tlen or "0")
            if key in seen_tcp:
                dup_bytes += nbytes
                continue
            seen_tcp.add(key)
        elif proto == "17":
            key = (src, dst, usp, udp_p, ipid, iplen)
            if key in seen_udp:
                dup_bytes += nbytes
                continue
            seen_udp.add(key)
        peers[src].add(dst)
        peers[dst].add(src)
        rows.append((ts, src, dst, nbytes, proto))

    if not rows:
        return {"error": "패킷 없음", "pcap": pcap}

    if ue_subnet:
        pfx = ue_subnet.rsplit(".", 1)[0] + "."      # 예: "10.1.17.0/24" → "10.1.17."
        pfx = pfx.replace("/24", "")
        ues = {h for h in peers if h.startswith(pfx)}
        how = f"subnet {ue_subnet}"
    else:
        ues = {h for h, ps in peers.items()
               if _is_private(h) and len(ps) >= min_peers}
        how = f"auto (private, >={min_peers} peers)"
    if not ues:                                       # 마지막 수단
        ues = {max(peers.items(), key=lambda kv: len(kv[1]))[0]}
        how = "auto (max peers)"
    t0 = min(r[0] for r in rows)

    # (ue, dir, win) → bytes
    cells: Dict[Tuple[str, str, int], int] = defaultdict(int)
    dropped = 0
    for ts, src, dst, nb, _proto in rows:
        s_ue, d_ue = src in ues, dst in ues
        if s_ue and not d_ue:
            ue, direction = src, "UL"
        elif d_ue and not s_ue:
            ue, direction = dst, "DL"
        else:
            dropped += nb                  # 단말↔단말 또는 단말 무관 트래픽
            continue
        cells[(ue, direction, int((ts - t0) // window_s))] += nb

    return {
        "pcap": os.path.basename(pcap),
        "ues": sorted(ues),
        "ue_selection": how,
        "peer_counts": {u: len(peers[u]) for u in sorted(ues)},
        "bytes_unattributed": dropped,
        "window_s": window_s,
        "packets": n_pkt,
        "naive_bytes": naive_bytes,
        "duplicate_bytes": dup_bytes,
        "duplication_factor": (round(naive_bytes / (naive_bytes - dup_bytes), 4)
                               if naive_bytes > dup_bytes else 1.0),
        "cells": cells,
        "t0": t0,
    }


def load_factor_distribution(ext: Dict[str, Any], *,
                             peak_dl: float = PEAK_DL_MBPS,
                             peak_ul: float = PEAK_UL_MBPS,
                             lf_min: float = 0.30, lf_max: float = 1.00,
                             active: Sequence[str] = ("SBFD", "MIMO-adv",
                                                      "EN-DC"),
                             min_windows: int = 3) -> Dict[str, Any]:
    """(단말, 방향, 창) 처리량 → LF 분포 → 그 분포 위의 오차 증폭계수."""
    cells: Dict[Tuple[str, str, int], int] = ext["cells"]
    win = ext["window_s"]
    by_name = {f.name: f for f in FEATURES}
    feats = [by_name[n] for n in active if n in by_name]

    per_ue: Dict[Tuple[str, str], List[float]] = defaultdict(list)
    for (ue, direction, _w), nb in cells.items():
        per_ue[(ue, direction)].append(nb * 8.0 / win / 1e6)     # Mb/s

    ue_rows: List[Dict[str, Any]] = []
    lf_all: Dict[str, List[float]] = {"DL": [], "UL": []}
    lf_raw: Dict[str, List[float]] = {"DL": [], "UL": []}
    for (ue, direction), mbps in sorted(per_ue.items()):
        if len(mbps) < min_windows:
            continue
        peak = peak_dl if direction == "DL" else peak_ul
        raw = [m / peak for m in mbps]
        lfs = [load_factor(m, peak, lf_min, lf_max) for m in mbps]
        lf_all[direction].extend(lfs)
        lf_raw[direction].extend(raw)
        ue_rows.append({
            "ue_ip": ue, "direction": direction, "n_windows": len(mbps),
            "mean_mbps": round(statistics.mean(mbps), 4),
            "max_mbps": round(max(mbps), 4),
            "cv": (round(statistics.pstdev(mbps) / statistics.mean(mbps), 4)
                   if statistics.mean(mbps) > 0 else None),
            "lf_raw_mean": round(statistics.mean(raw), 5),
            "lf_used_mean": round(statistics.mean(lfs), 5),
            "clipped_frac": round(sum(1 for x in raw if x < lf_min)
                                  / len(raw), 4),
        })

    def q(v: List[float], p: float) -> Optional[float]:
        if not v:
            return None
        s = sorted(v)
        i = min(len(s) - 1, max(0, int(round(p * (len(s) - 1)))))
        return round(s[i], 5)

    dist: Dict[str, Any] = {}
    for d in ("DL", "UL"):
        used, raw = lf_all[d], lf_raw[d]
        if not used:
            dist[d] = None
            continue
        amps = [amplification(feats, x) for x in used]
        dist[d] = {
            "n_windows": len(used),
            "lf_used": {"mean": round(statistics.mean(used), 5),
                        "p05": q(used, 0.05), "p50": q(used, 0.50),
                        "p95": q(used, 0.95), "max": q(used, 1.0)},
            "lf_raw": {"mean": round(statistics.mean(raw), 5),
                       "p05": q(raw, 0.05), "p50": q(raw, 0.50),
                       "p95": q(raw, 0.95), "max": q(raw, 1.0)},
            # 실측 부하의 대부분이 클립 아래라면, 이득 예측이 자기 측정값과
            # 무관해진다는 뜻이다 — 논문이 반드시 밝혀야 하는 사실.
            "clipped_frac": round(sum(1 for x in raw if x < lf_min) / len(raw), 4),
            "saturated_frac": round(sum(1 for x in raw if x >= lf_max) / len(raw), 4),
            "amplification": {"mean": round(statistics.mean(amps), 4),
                              "p05": q(amps, 0.05), "p50": q(amps, 0.50),
                              "p95": q(amps, 0.95), "max": q(amps, 1.0)},
            # 운영자용 역산: 예측을 5 % 안에 넣으려면 캡처를 몇 % 안에서 재야 하나
            "capture_budget_for_5pct": round(
                5.0 / max(amps), 4) if amps else None,
            # 전수 클립이면 "예외가 없다" 를 통계로 말해야 한다. 실패 0건의
            # 95 % 상한은 3/N(rule of three) 이다.
            "unclipped_frac_upper95": (
                round(3.0 / len(raw), 5)
                if all(x < lf_min for x in raw) else None),
        }

    # ── 대안 분모: 단말 자신이 실제로 낸 최고치 ──────────────────────────
    # 벤더 단일단말 피크는 셀을 공유하는 단말에게 결코 주어지지 않는 양이라
    # 실측에서 LF 를 바닥에 붙여 버린다. "이 단말이 이 조건에서 낼 수 있었던 만큼"
    # 을 분모로 쓰면 동적범위가 살아나는지 같은 데이터로 확인한다.
    alt: Dict[str, Any] = {}
    for d in ("DL", "UL"):
        vals: List[float] = []
        for (ue, direction), mbps in per_ue.items():
            if direction != d or len(mbps) < min_windows:
                continue
            own = max(mbps)
            if own > 0:
                vals.extend(min(1.0, m / own) for m in mbps)
        if not vals:
            alt[d] = None
            continue
        amps = [amplification(feats, x) for x in vals]
        alt[d] = {
            "n_windows": len(vals),
            "lf": {"mean": round(statistics.mean(vals), 5),
                   "p05": q(vals, 0.05), "p50": q(vals, 0.50),
                   "p95": q(vals, 0.95), "max": q(vals, 1.0)},
            "clipped_frac": round(sum(1 for x in vals if x < lf_min)
                                  / len(vals), 4),
            "amplification": {"mean": round(statistics.mean(amps), 4),
                              "p50": q(amps, 0.50), "max": q(amps, 1.0)},
        }

    return {
        "meta": {
            "pcap": ext["pcap"], "ues": ext.get("ues"),
            "ue_selection": ext.get("ue_selection"),
            "peer_counts": ext.get("peer_counts"),
            "bytes_unattributed": ext.get("bytes_unattributed"),
            "window_s": win, "packets": ext["packets"],
            "duplication_factor": ext["duplication_factor"],
            "peak_dl_mbps": peak_dl, "peak_ul_mbps": peak_ul,
            "lf_min": lf_min, "lf_max": lf_max,
            "active_features": list(active),
            "n_ue_directions": len(ue_rows),
        },
        "per_ue": ue_rows,
        "distribution": dist,
        "distribution_own_peak": alt,
    }


def selftest(verbose: bool = False) -> bool:
    """중복제거와 LF 분포 산출이 말이 되는지 — 캡처 없이 합성 셀로."""
    ok = True
    # 창 2개, 단말 2대. DL 은 피크의 절반, UL 은 피크의 1 %(클립 대상).
    win = 5.0
    dl_bytes = int(PEAK_DL_MBPS * 0.5 * 1e6 * win / 8)
    ul_bytes = int(PEAK_UL_MBPS * 0.01 * 1e6 * win / 8)
    cells = {}
    for w in range(4):
        cells[("10.0.0.1", "DL", w)] = dl_bytes
        cells[("10.0.0.1", "UL", w)] = ul_bytes
    ext = {"pcap": "t", "ues": ["10.0.0.1"], "window_s": win,
           "packets": 8, "naive_bytes": 0, "duplicate_bytes": 0,
           "duplication_factor": 1.0, "cells": cells, "t0": 0.0}
    r = load_factor_distribution(ext)
    dl, ul = r["distribution"]["DL"], r["distribution"]["UL"]
    if abs(dl["lf_raw"]["mean"] - 0.5) > 0.01:
        ok = False
        print(f"  [LFF] DL LF 계산 오류: {dl['lf_raw']['mean']}")
    if dl["clipped_frac"] != 0.0:
        ok = False
        print("  [LFF] DL 이 클립됐다고 나옴")
    if ul["clipped_frac"] != 1.0 or abs(ul["lf_used"]["mean"] - 0.30) > 1e-6:
        ok = False
        print(f"  [LFF] UL 클립 처리 오류: {ul['clipped_frac']} {ul['lf_used']}")
    # 증폭계수는 LF 에 대해 단조증가 — DL(0.5) 이 UL(클립 0.3) 보다 커야 한다
    if not (dl["amplification"]["mean"] > ul["amplification"]["mean"]):
        ok = False
        print("  [LFF] 증폭계수가 LF 에 단조가 아님")
    if ok and verbose:
        print(f"  [LFF] DL LF {dl['lf_raw']['mean']} A={dl['amplification']['mean']} | "
              f"UL 클립 {ul['clipped_frac']*100:.0f}% A={ul['amplification']['mean']}")
    return ok


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="실측 캡처 → 단말별 부하계수 분포")
    ap.add_argument("--pcap", action="append", required=True,
                    help="실측 N3 미러 캡처(여러 개 지정 가능)")
    ap.add_argument("--out", default=V4)
    ap.add_argument("--window", type=float, default=5.0)
    ap.add_argument("--limit", type=int, default=0, help="패킷 수 제한(시험용)")
    ap.add_argument("--ue-subnet", default=None,
                    help="단말 서브넷(예: 10.1.17.0/24). 없으면 자동 판별")
    a = ap.parse_args(argv)

    import logging
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname).1s [%(name)s] %(message)s",
                        datefmt="%H:%M:%S")
    os.makedirs(a.out, exist_ok=True)

    results = []
    series = []
    for pcap in a.pcap:
        ext = extract_windows(pcap, window_s=a.window,
                              ue_subnet=a.ue_subnet, limit=a.limit)
        if ext.get("error"):
            log.error("%s: %s", pcap, ext["error"])
            continue
        res = load_factor_distribution(ext)
        results.append(res)
        series.append((ext, res))
        d = res["distribution"]
        log.info("%s: 단말 %d대(%s), 단말·방향 %d, 중복배수 %.2fx",
                 os.path.basename(pcap), len(res["meta"].get("ues") or []),
                 res["meta"].get("ue_selection"),
                 res["meta"]["n_ue_directions"], res["meta"]["duplication_factor"])
        for k in ("DL", "UL"):
            if d.get(k):
                log.info("  %s LF p50=%.4f 클립비율 %.1f%% A p50=%.3f", k,
                         d[k]["lf_raw"]["p50"], d[k]["clipped_frac"] * 100,
                         d[k]["amplification"]["p50"])

    path = os.path.join(a.out, "M_lf_field.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"captures": results}, f, indent=1, ensure_ascii=False)
    print(f"저장: {path}")

    # 파생 시계열 — 원본 캡처는 운용 트래픽이라 공개할 수 없지만 분석이 실제로
    # 소비하는 것은 이 창별 처리량이다. 논문 Data availability 가 약속하는 파일이므로
    # 항상 함께 떨어뜨린다(개인식별 정보 없음: 단말 IP 는 사설 주소, 페이로드 없음).
    csv_path = os.path.join(a.out, "M_lf_series.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("capture,ue_ip,direction,window_index,window_s,"
                "throughput_mbps,lf_raw,lf_used\n")
        for ext, res in series:
            m = res["meta"]
            peak = {"DL": m["peak_dl_mbps"], "UL": m["peak_ul_mbps"]}
            for (ue, d, w), nb in sorted(ext["cells"].items()):
                mbps = nb * 8.0 / ext["window_s"] / 1e6
                raw = mbps / peak[d]
                used = max(m["lf_min"], min(m["lf_max"], raw))
                f.write(f"{m['pcap']},{ue},{d},{w},{ext['window_s']:g},"
                        f"{mbps:.6f},{raw:.8f},{used:.5f}\n")
    print(f"저장: {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
