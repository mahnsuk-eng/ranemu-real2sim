#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.e2e — 스텁 코어를 상대로 한 전 경로(End-to-End) 검증.

실코어에 붙이기 전에 이것이 통과해야 한다. 여기서 실패하면 문제는 에뮬레이터 안에
있고, 여기서 통과했는데 실코어에서 실패하면 문제는 코어 연동(주소/PLMN/SIM/정책)에 있다.
그 분리가 이 모듈의 목적이다.

검증 항목
  1. NGAP N2 수립 (NGSetupRequest/Response)
  2. 5G-AKA 인증 (RES* == XRES*)
  3. NAS 보안 (SecurityModeCommand/Complete, 암호화+무결성)
  4. 등록 완료 (RegistrationAccept/Complete)
  5. PDU 세션 수립 (UE IP 배정, N3 터널 양방향 TEID 교환)
  6. 사용자평면 (실제 GTP-U 패킷이 UPF 에 도달)
  7. feature 별 특성 분화 (RedCap 저속 / NTN 고지연 / eMBB 고속)
  8. 주입값 == 실측값 (쉐이퍼가 의도한 속도를 실제로 냈는가)
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from .config import RunConfig, loads
from .core import StubCore
from .gnb import Gnb
from .util import get_logger

log = get_logger("ranemu.e2e")

_KEY = "465b5ce8b199b49faa5f0a2ee238a6bc"
_OPC = "cd63cb71954a9f4e48a5994e37a02baf"


def build_config(amf_addr: str, amf_port: int, upf_addr: str, upf_port: int,
                 duration: float = 5.0) -> RunConfig:
    """검증용 4단말 구성: RedCap ×2, NTN(LEO) ×1, eMBB ×1."""
    return loads({
        "name": "ranemu-e2e", "seed": 42,
        "core": {"kind": "stub", "amf_addr": amf_addr, "amf_port": amf_port,
                 "upf_addr": upf_addr, "upf_port": upf_port},
        "gnb": {"name": "ranemu-e2e-gnb", "mcc": "450", "mnc": "05", "gnb_id": 1,
                "tac": 1, "n2_local_addr": "127.0.0.1",
                "n3_local_addr": "127.0.0.1", "n3_local_port": 0,
                "n3_advertise_addr": "127.0.0.1"},
        "security": {"key": _KEY, "opc": _OPC, "amf": "8000"},
        "ue_groups": [
            {"name": "redcap", "count": 2, "imsi_start": "450050000000001",
             "features": ["redcap"], "traffic": "fullbuffer"},
            {"name": "ntn-leo", "count": 1, "imsi_start": "450050000000011",
             "features": ["ntn"], "feature_params": {"ntn": {"orbit": "leo"}},
             "traffic": "fullbuffer"},
            {"name": "embb", "count": 1, "imsi_start": "450050000000021",
             "features": [], "traffic": "fullbuffer"},
        ],
        "traffic": {"duration": duration, "dest_addr": "8.8.8.8",
                    "downlink_mode": "loopback", "packet_size": 1400,
                    "offered_ul_mbps": 500.0, "offered_dl_mbps": 1000.0},
    })


def run(duration: float = 5.0, verbose: bool = False
        ) -> Tuple[bool, Dict[str, Any]]:
    """스텁 코어를 띄우고 전 경로를 돌린 뒤 (성공여부, 결과) 반환."""
    core = StubCore(key=bytes.fromhex(_KEY), opc=bytes.fromhex(_OPC),
                    amf_addr="127.0.0.1", amf_port=0,
                    upf_addr="127.0.0.1", upf_port=0,
                    mcc="450", mnc="05", downlink_mode="loopback")
    amf_a, amf_p, upf_a, upf_p = core.start()
    cfg = build_config(amf_a, amf_p, upf_a, upf_p, duration)
    errs = [e for e in cfg.validate() if "downlink_mode" not in e]
    if errs:
        core.stop()
        return False, {"error": f"설정 검증 실패: {errs}"}

    gnb = Gnb(cfg)
    try:
        result = gnb.run()
    finally:
        gnb.close()
        core.stop()
    result["core_summary"] = core.summary()
    return True, result


def check(result: Dict[str, Any], verbose: bool = False) -> bool:  # noqa: C901
    """E2E 결과를 항목별로 판정."""
    ok = True
    core = result.get("core_summary", {})
    cstats = core.get("stats", {})
    summary = result.get("summary", {})
    ues = result.get("ues", [])

    def _fail(msg: str) -> None:
        nonlocal ok
        ok = False
        print(f"  [E2E] {msg}")

    # 1) N2 수립
    if not result.get("gnb", {}).get("ng_setup_ok"):
        _fail("NGSetup 실패")
    elif verbose:
        print("  [E2E] 1. NGAP N2 수립 OK")

    # 2~4) 등록(인증+보안+수락)
    if summary.get("ue_registered", 0) != summary.get("ue_total", 0):
        _fail(f"등록 실패 단말 존재: {summary}")
    elif verbose:
        print(f"  [E2E] 2-4. 5G-AKA 인증+NAS보안+등록 {summary['ue_registered']}/"
              f"{summary['ue_total']}대 OK")
    if cstats.get("registrations", 0) != summary.get("ue_total", 0):
        _fail(f"코어측 등록 수 불일치: {cstats.get('registrations')}")
    if core.get("errors"):
        _fail(f"스텁 코어가 오류 보고: {core['errors'][:3]}")

    # 5) PDU 세션 + 터널
    if summary.get("ue_active", 0) != summary.get("ue_total", 0):
        _fail(f"활성화 실패 단말 존재: active={summary.get('ue_active')}")
    elif verbose:
        print(f"  [E2E] 5. PDU 세션 + N3 터널 {summary['ue_active']}대 OK")
    for u in ues:
        if u["state"] == "active" and not (u.get("ue_ip") and u.get("ul_teid") is not None
                                           and u.get("dl_teid") is not None):
            _fail(f"{u['imsi']}: IP/TEID 누락 {u.get('ue_ip')}/{u.get('ul_teid')}")

    # 6) 사용자평면이 실제로 흘렀는가 (코어가 받은 것으로 확인)
    if cstats.get("ul_packets", 0) < 100:
        _fail(f"코어가 받은 상향 패킷이 너무 적음: {cstats.get('ul_packets')}")
    elif verbose:
        print(f"  [E2E] 6. 사용자평면 GTP-U: 코어 수신 {cstats['ul_packets']}패킷 / "
              f"{cstats['ul_bytes']/1e6:.1f} MB OK")
    if cstats.get("dl_packets", 0) < 100:
        _fail(f"하향(loopback) 패킷이 너무 적음: {cstats.get('dl_packets')}")

    # 7) feature 별 특성 분화
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for u in ues:
        by_group.setdefault(u["group"], []).append(u)
    rates = {g: (sum((x["traffic"]["offered_ul_mbps"] or 0) for x in v) / len(v))
             for g, v in by_group.items()}
    rtts = {g: (sum(x["link_budget"]["rtt_ms"] for x in v) / len(v))
            for g, v in by_group.items()}
    if "redcap" in rates and "embb" in rates:
        if not (rates["redcap"] < rates["embb"] * 0.5):
            _fail(f"RedCap 이 eMBB 보다 충분히 느리지 않음: {rates}")
        elif verbose:
            print(f"  [E2E] 7. RedCap {rates['redcap']:.1f} < eMBB {rates['embb']:.1f} Mbps OK")
    if "ntn-leo" in rtts and "embb" in rtts:
        if not (rtts["ntn-leo"] > rtts["embb"] * 3):
            _fail(f"NTN 이 지상망보다 충분히 느리지(지연) 않음: {rtts}")
        elif verbose:
            print(f"  [E2E] 7. NTN LEO RTT {rtts['ntn-leo']:.0f} ms > "
                  f"지상 {rtts['embb']:.1f} ms OK")

    # 8) 주입 목표 대비 실측 (쉐이퍼 정확도)
    for u in ues:
        if u["state"] != "active":
            continue
        st = u["stats"]
        first, last = st.get("first_ul_time"), st.get("last_ul_time")
        if first is None or last is None or last - first < 1.0:
            continue
        measured = st["ul_bytes"] * 8 / (last - first) / 1e6
        target = u["traffic"]["offered_ul_mbps"] or 0
        if target <= 0:
            continue
        err = abs(measured - target) / target * 100
        if err > 20.0:
            _fail(f"{u['imsi']}: 목표 {target:.1f} vs 실측 {measured:.1f} Mbps "
                  f"({err:.0f}% 오차)")
        elif verbose:
            print(f"  [E2E] 8. {u['imsi']} 목표 {target:.1f} → 실측 {measured:.1f} Mbps "
                  f"({err:.1f}% 오차) OK")
    return ok


def selftest(verbose: bool = False, duration: float = 5.0) -> bool:
    started, result = run(duration=duration, verbose=verbose)
    if not started:
        print(f"  [E2E] 실행 실패: {result.get('error')}")
        return False
    if result.get("failed"):
        print(f"  [E2E] 시험 중단: {result['failed']}")
        return False
    return check(result, verbose=verbose)


if __name__ == "__main__":
    print("E2E:", "PASS" if selftest(verbose=True) else "FAIL")
