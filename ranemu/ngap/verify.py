#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.ngap.verify — tshark 의 NGAP 디섹터를 **독립 오라클**로 삼는 인코딩 검증.

왜 필요한가
===========
NGAP 은 ASN.1 APER 라 한 비트만 어긋나도 코어가 전혀 다른 필드로 해석한다. 자체 왕복
테스트(내 인코더 → 내 디코더)는 같은 오해를 공유하므로 이런 오류를 못 잡는다.
실제로 이 검증으로 `UserLocationInformation` CHOICE 에 확장비트를 넣으면 안 된다는
사실을 찾아냈다(넣으면 코어가 EUTRA 위치정보로 오독).

방법
====
    NGAP PDU → scapy 로 SCTP(PPID=60) 패킷 → pcap → tshark -Y ngap → 필드 대조

tshark 나 scapy 가 없으면 검증을 건너뛰고 그 사실을 보고한다(조용히 통과시키지 않는다).
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from . import messages as m


def tools_available() -> Tuple[bool, str]:
    if shutil.which("tshark") is None:
        return False, "tshark 없음"
    try:
        import scapy  # noqa: F401
    except ImportError:
        return False, "scapy 없음"
    return True, ""


def write_ngap_pcap(pdus: List[bytes], path: str,
                    src: str = "10.0.0.1", dst: str = "10.0.0.2") -> None:
    """NGAP PDU 목록을 SCTP(PPID 60) 패킷으로 pcap 에 기록."""
    import warnings
    warnings.filterwarnings("ignore")
    from scapy.all import Ether, IP, wrpcap                     # type: ignore
    from scapy.layers.sctp import SCTP, SCTPChunkData           # type: ignore

    pkts = []
    for i, pdu in enumerate(pdus):
        pkts.append(
            Ether() / IP(src=src, dst=dst) /
            SCTP(sport=50000, dport=38412) /
            SCTPChunkData(beginning=1, ending=1, tsn=i, proto_id=60, data=pdu))
    wrpcap(path, pkts)


def dissect(pdus: List[bytes], fields: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """PDU 목록을 tshark 로 파싱해 프레임별 필드 dict 반환."""
    fields = fields or ["_ws.col.info"]
    with tempfile.TemporaryDirectory(prefix="ranemu-ngap-") as td:
        pcap = os.path.join(td, "ngap.pcap")
        write_ngap_pcap(pdus, pcap)
        cmd = ["tshark", "-r", pcap, "-Y", "ngap", "-T", "fields",
               "-E", "separator=\x1f", "-E", "occurrence=a", "-E", "aggregator=,"]
        for f in fields:
            cmd += ["-e", f]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    rows: List[Dict[str, str]] = []
    for line in out.stdout.strip().splitlines():
        vals = line.split("\x1f")
        rows.append({f: (vals[i] if i < len(vals) else "") for i, f in enumerate(fields)})
    return rows


def dissect_verbose(pdus: List[bytes]) -> str:
    """tshark -V 전체 트리(진단용)."""
    with tempfile.TemporaryDirectory(prefix="ranemu-ngap-") as td:
        pcap = os.path.join(td, "ngap.pcap")
        write_ngap_pcap(pdus, pcap)
        out = subprocess.run(["tshark", "-r", pcap, "-V"],
                             capture_output=True, text=True, timeout=120)
    return out.stdout


# ═════════════════════════════════════════════════════════════════════════════
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    """gNB 가 보내는 모든 메시지를 tshark 로 대조 검증."""
    avail, why = tools_available()
    if not avail:
        print(f"  [NGAP-VERIFY] 건너뜀 — {why} (실코어 연동 전 반드시 재검증하십시오)")
        return True

    ok = True
    plmn = bytes.fromhex("54f050")           # MCC 450 / MNC 05
    tac = 1
    nci = (1 << 12) | 3
    gnb_addr = "10.1.16.52"
    gnb_teid = 0x11223344

    from ..nas import nas5gs as n
    nas = n.encode_registration_request(
        mobile_identity=n.enc_suci_imsi("450050000000001"),
        enc_algs=[0, 2], int_algs=[0, 2], requested_nssai=[(1, None)])

    transfer = m.enc_pdu_session_resource_setup_response_transfer(gnb_addr, gnb_teid, [1])
    pdus = [
        ("NGSetupRequest", m.ng_setup_request(
            plmn=plmn, gnb_id=0xABCDE, gnb_id_bits=24, tac=tac,
            slices=[(1, None), (2, "000001")], ran_node_name="ranemu-gnb-1",
            paging_drx="v128")),
        ("InitialUEMessage", m.initial_ue_message(
            ran_ue_ngap_id=1, nas_pdu=nas, plmn=plmn, nr_cell_identity=nci, tac=tac,
            rrc_cause="mo-Data", ue_context_request=True)),
        ("UplinkNASTransport", m.uplink_nas_transport(
            amf_ue_ngap_id=7, ran_ue_ngap_id=1, nas_pdu=nas, plmn=plmn,
            nr_cell_identity=nci, tac=tac)),
        ("InitialContextSetupResponse", m.initial_context_setup_response(
            amf_ue_ngap_id=7, ran_ue_ngap_id=1, setup_items=[(5, transfer)])),
        ("PDUSessionResourceSetupResponse", m.pdu_session_resource_setup_response(
            amf_ue_ngap_id=7, ran_ue_ngap_id=1, setup_items=[(5, transfer)])),
        ("UEContextReleaseRequest", m.ue_context_release_request(
            amf_ue_ngap_id=7, ran_ue_ngap_id=1)),
        ("UEContextReleaseComplete", m.ue_context_release_complete(
            amf_ue_ngap_id=7, ran_ue_ngap_id=1)),
    ]
    names = [nm for nm, _ in pdus]
    blobs = [p for _, p in pdus]

    rows = dissect(blobs, ["_ws.col.info", "ngap.procedureCode", "_ws.expert.severity"])
    if len(rows) != len(pdus):
        ok = False
        print(f"  [NGAP-VERIFY] tshark 가 {len(rows)}/{len(pdus)} 프레임만 NGAP 으로 인식")

    for i, (name, _pdu) in enumerate(pdus):
        if i >= len(rows):
            break
        info = rows[i].get("_ws.col.info", "")
        if name not in info:
            ok = False
            print(f"  [NGAP-VERIFY] {name}: tshark 가 '{info}' 로 해석")
        elif verbose:
            print(f"  [NGAP-VERIFY] {name} → tshark '{info}' OK")

    # ── 상세 필드 대조 ────────────────────────────────────────────────────
    checks: List[Tuple[str, List[str], Dict[str, Any]]] = [
        # NGSetupRequest: PLMN/gNB-ID/TAC/슬라이스/DRX
        ("NGSetupRequest",
         ["ngap.pLMNIdentity", "ngap.gNB_ID", "ngap.tAC", "ngap.sST", "ngap.sD",
          "ngap.PagingDRX"],
         {"ngap.gNB_ID": "abcde", "ngap.tAC": "1", "ngap.PagingDRX": "2"}),
        # InitialUEMessage: RAN-UE-NGAP-ID / RRC 확립사유 / NR 위치정보 / NAS 안의 SUCI
        ("InitialUEMessage",
         ["ngap.RAN_UE_NGAP_ID", "ngap.RRCEstablishmentCause",
          "ngap.NRCellIdentity", "ngap.tAC", "nas-5gs.mm.suci.msin",
          "nas-5gs.mm.suci.scheme_id", "_ws.col.info"],
         {"ngap.RAN_UE_NGAP_ID": "1",
          "ngap.RRCEstablishmentCause": "4",          # mo-Data
          "ngap.tAC": "1",
          "nas-5gs.mm.suci.msin": "0000000001",       # IMSI 450 05 0000000001
          "_ws.col.info": "Registration request"}),
        # UplinkNASTransport: 두 ID 모두
        ("UplinkNASTransport",
         ["ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID"],
         {"ngap.AMF_UE_NGAP_ID": "7", "ngap.RAN_UE_NGAP_ID": "1"}),
        # PDUSessionResourceSetupResponse: N3 터널(주소/TEID) — 가장 중요
        ("PDUSessionResourceSetupResponse",
         ["ngap.pDUSessionID", "ngap.TransportLayerAddressIPv4", "ngap.gTP_TEID",
          "ngap.qosFlowIdentifier"],
         {"ngap.pDUSessionID": "5", "ngap.TransportLayerAddressIPv4": gnb_addr,
          "ngap.gTP_TEID": "11223344", "ngap.qosFlowIdentifier": "1"}),
        # UEContextReleaseRequest: Cause 가 radioNetwork 로 해석되어야
        ("UEContextReleaseRequest",
         ["ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID", "ngap.Cause"],
         {"ngap.AMF_UE_NGAP_ID": "7"}),
    ]
    for name, fields, expect in checks:
        idx = names.index(name)
        row = dissect([blobs[idx]], fields)
        if not row:
            ok = False
            print(f"  [NGAP-VERIFY] {name}: 필드 추출 실패")
            continue
        got = row[0]
        for key, want in expect.items():
            have = got.get(key, "")
            # 다중 출현은 콤마로 합쳐지므로 포함 여부로 판정
            if str(want).lower() not in str(have).lower():
                ok = False
                print(f"  [NGAP-VERIFY] {name}.{key}: 기대 {want!r}, tshark {have!r}")
        if verbose:
            shown = {k: v for k, v in got.items() if v}
            print(f"  [NGAP-VERIFY] {name} 필드 {shown}")

    # ── 오류(Malformed) 가 하나도 없어야 한다 ─────────────────────────────
    tree = dissect_verbose(blobs)
    if "Malformed Packet: NGAP" in tree:
        ok = False
        bad = [ln.strip() for ln in tree.splitlines() if "Malformed" in ln]
        print(f"  [NGAP-VERIFY] tshark 가 Malformed 보고: {bad[:3]}")
    elif verbose:
        print("  [NGAP-VERIFY] tshark Malformed 0건 OK")

    # ── 자체 왕복(파서) 검증 ──────────────────────────────────────────────
    for name, pdu in pdus:
        try:
            parsed = m.parse_pdu(pdu)
        except Exception as e:  # noqa: BLE001
            ok = False
            print(f"  [NGAP-VERIFY] {name} 자체 파싱 실패: {e}")
            continue
        if parsed.name not in name:
            ok = False
            print(f"  [NGAP-VERIFY] {name} 자체 파싱 절차명 불일치: {parsed.name}")

    # PDUSessionResourceSetupResponse 의 터널 정보를 자체 디코더로 되읽기
    info = m.find_gtp_tunnel(m.enc_gtp_tunnel(gnb_addr, gnb_teid))
    if not info or info["addr"] != gnb_addr or info["teid"] != gnb_teid:
        ok = False
        print(f"  [NGAP-VERIFY] GTPTunnel 자체 왕복 실패: {info}")
    elif verbose:
        print(f"  [NGAP-VERIFY] GTPTunnel 자체 왕복 {info} OK")

    # IPv6 터널도 왕복되어야 함
    v6 = m.find_gtp_tunnel(m.enc_gtp_tunnel("2001:db8::1", 0xAABBCCDD))
    if not v6 or v6["addr"] != "2001:db8::1":
        ok = False
        print(f"  [NGAP-VERIFY] IPv6 GTPTunnel 왕복 실패: {v6}")
    return ok


if __name__ == "__main__":
    print("NGAP-VERIFY:", "PASS" if selftest(verbose=True) else "FAIL")
