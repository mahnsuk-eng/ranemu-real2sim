#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.ngap.messages — NGAP (TS 38.413) 메시지 인코더/디코더.

구조
====
모든 NGAP PDU 는 다음 골격을 공유한다.

    NGAP-PDU ::= CHOICE { initiatingMessage, successfulOutcome, unsuccessfulOutcome, ... }
      → 확장비트(1) + 인덱스(2비트) → 옥텟정렬
    <XxxMessage> ::= SEQUENCE { procedureCode, criticality, value(open type) }
      → procedureCode(1옥텟) + criticality(2비트+패딩=1옥텟) + open type
    value ::= SEQUENCE { protocolIEs ProtocolIE-Container, ... }
      → 확장비트(1)+패딩 + IE개수(2옥텟) + [ProtocolIE-Field ...]
    ProtocolIE-Field ::= SEQUENCE { id(2옥텟), criticality(1옥텟), value(open type) }

따라서 바이트열은 항상
    [00|20|40] [proc] [crit] [len] [00] [cnt_hi cnt_lo] ( [id_hi id_lo][crit][len][content] )*
형태가 된다. 이 규칙성이 인코더/디코더를 단순하게 만든다.

검증
====
`ranemu.ngap.verify` 가 여기서 만든 PDU 를 pcap 으로 써서 **tshark 의 NGAP 디섹터**로
파싱시켜 독립 대조한다. IE ID/구조가 틀리면 tshark 가 다르게 해석하므로 바로 드러난다.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .aper import AperError, BitReader, BitWriter

# ═════════════════════════════════════════════════════════════════════════════
# 상수
# ═════════════════════════════════════════════════════════════════════════════
PDU_INITIATING = 0
PDU_SUCCESSFUL = 1
PDU_UNSUCCESSFUL = 2

CRIT_REJECT = 0
CRIT_IGNORE = 1
CRIT_NOTIFY = 2

# 절차 코드 (TS 38.413 §9.3.1.2)
PROC_AMF_CONFIGURATION_UPDATE = 0
PROC_DOWNLINK_NAS_TRANSPORT = 4
PROC_ERROR_INDICATION = 9
PROC_INITIAL_CONTEXT_SETUP = 14
PROC_INITIAL_UE_MESSAGE = 15
PROC_NG_RESET = 20
PROC_NG_SETUP = 21
PROC_PAGING = 24
PROC_PDU_SESSION_RESOURCE_MODIFY = 26
PROC_PDU_SESSION_RESOURCE_RELEASE = 28
PROC_PDU_SESSION_RESOURCE_SETUP = 29
PROC_RAN_CONFIGURATION_UPDATE = 35
PROC_UE_CONTEXT_RELEASE = 41
PROC_UE_CONTEXT_RELEASE_REQUEST = 42
PROC_UPLINK_NAS_TRANSPORT = 46

PROC_NAMES = {
    0: "AMFConfigurationUpdate", 4: "DownlinkNASTransport", 9: "ErrorIndication",
    14: "InitialContextSetup", 15: "InitialUEMessage", 20: "NGReset", 21: "NGSetup",
    24: "Paging", 26: "PDUSessionResourceModify", 28: "PDUSessionResourceRelease",
    29: "PDUSessionResourceSetup", 35: "RANConfigurationUpdate",
    40: "UEContextModification", 41: "UEContextRelease",
    42: "UEContextReleaseRequest", 46: "UplinkNASTransport",
    43: "UERadioCapabilityCheck", 44: "UERadioCapabilityInfoIndication",
}

# ProtocolIE-ID (TS 38.413 §9.3.1.x)
IE_ALLOWED_NSSAI = 0
IE_AMF_NAME = 1
IE_AMF_UE_NGAP_ID = 10
IE_CAUSE = 15
IE_CRITICALITY_DIAGNOSTICS = 19
IE_DEFAULT_PAGING_DRX = 21
IE_FIVEG_S_TMSI = 26
IE_GLOBAL_RAN_NODE_ID = 27
IE_GUAMI = 28
IE_NAS_PDU = 38
IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_CXT_RES = 54
IE_PDU_SESSION_RESOURCE_FAILED_TO_SETUP_SU_RES = 58
IE_PDU_SESSION_RESOURCE_LIST_CXT_REL_CPL = 60
IE_PDU_SESSION_RESOURCE_RELEASED_LIST_REL_RES = 70
IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ = 71
IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES = 72
IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ = 74
IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES = 75
IE_PDU_SESSION_RESOURCE_TO_RELEASE_LIST_REL_CMD = 79
IE_PLMN_SUPPORT_LIST = 80
IE_RAN_NODE_NAME = 82
IE_RAN_UE_NGAP_ID = 85
IE_RELATIVE_AMF_CAPACITY = 86
IE_RRC_ESTABLISHMENT_CAUSE = 90
IE_SECURITY_KEY = 94
IE_SERVED_GUAMI_LIST = 96
IE_SUPPORTED_TA_LIST = 102
IE_TIME_TO_WAIT = 107
IE_UE_AGGREGATE_MAXIMUM_BIT_RATE = 110
IE_UE_CONTEXT_REQUEST = 112
IE_UE_NGAP_IDS = 114
IE_UE_SECURITY_CAPABILITIES = 119
IE_USER_LOCATION_INFORMATION = 121
IE_UL_NGU_UP_TNL_INFORMATION = 139
IE_PDU_SESSION_TYPE = 134
IE_QOS_FLOW_SETUP_REQUEST_LIST = 136
IE_PDU_SESSION_AGGREGATE_MAXIMUM_BIT_RATE = 130

IE_NAMES = {
    0: "AllowedNSSAI", 1: "AMFName", 10: "AMF-UE-NGAP-ID", 15: "Cause",
    19: "CriticalityDiagnostics", 21: "DefaultPagingDRX", 26: "FiveG-S-TMSI",
    27: "GlobalRANNodeID", 28: "GUAMI", 38: "NAS-PDU",
    54: "PDUSessionResourceFailedToSetupListCxtRes",
    58: "PDUSessionResourceFailedToSetupListSURes",
    60: "PDUSessionResourceListCxtRelCpl",
    70: "PDUSessionResourceReleasedListRelRes",
    71: "PDUSessionResourceSetupListCxtReq", 72: "PDUSessionResourceSetupListCxtRes",
    74: "PDUSessionResourceSetupListSUReq", 75: "PDUSessionResourceSetupListSURes",
    79: "PDUSessionResourceToReleaseListRelCmd",
    80: "PLMNSupportList", 82: "RANNodeName", 85: "RAN-UE-NGAP-ID",
    86: "RelativeAMFCapacity", 90: "RRCEstablishmentCause", 94: "SecurityKey",
    96: "ServedGUAMIList", 102: "SupportedTAList", 107: "TimeToWait",
    110: "UEAggregateMaximumBitRate", 112: "UEContextRequest", 114: "UE-NGAP-IDs",
    119: "UESecurityCapabilities", 121: "UserLocationInformation",
    130: "PDUSessionAggregateMaximumBitRate", 134: "PDUSessionType",
    136: "QosFlowSetupRequestList", 139: "UL-NGU-UP-TNLInformation",
}

# RRCEstablishmentCause ENUMERATED (10개 루트값 + 확장)
RRC_CAUSES = ["emergency", "highPriorityAccess", "mt-Access", "mo-Signalling",
              "mo-Data", "mo-VoiceCall", "mo-VideoCall", "mo-SMS",
              "mps-PriorityAccess", "mcs-PriorityAccess"]

# PagingDRX ENUMERATED {v32, v64, v128, v256, ...}
PAGING_DRX = ["v32", "v64", "v128", "v256"]

# 최대치 (TS 38.413 §9.4)
MAX_PROTOCOL_IES = 65535
MAX_TACS = 256
MAX_BPLMNS = 12
MAX_SLICE_ITEMS = 1024
MAX_PDU_SESSIONS = 256
MAX_QOS_FLOWS = 64


class NgapError(ValueError):
    """NGAP 인코딩/디코딩 오류."""


# ═════════════════════════════════════════════════════════════════════════════
# 공통 골격
# ═════════════════════════════════════════════════════════════════════════════
def _ie_field(w: BitWriter, ie_id: int, criticality: int, content: bytes) -> None:
    """ProtocolIE-Field 하나를 기록."""
    w.constrained_int(ie_id, 0, MAX_PROTOCOL_IES)
    w.enumerated(criticality, 3)
    w.align()
    w.open_type(content)


def build_pdu(pdu_type: int, procedure_code: int, criticality: int,
              ies: List[Tuple[int, int, bytes]]) -> bytes:
    """NGAP PDU 조립.

    ies: [(ProtocolIE-ID, criticality, 값 옥텟), ...]
    """
    # 메시지 값(= SEQUENCE { protocolIEs })
    inner = BitWriter()
    inner.sequence_preamble(True, [])          # 확장비트 0
    inner.align()
    inner.sequence_of_count(len(ies), 0, MAX_PROTOCOL_IES)
    for ie_id, crit, content in ies:
        _ie_field(inner, ie_id, crit, content)
    value = inner.bytes()

    w = BitWriter()
    w.choice_index(pdu_type, 3)                # NGAP-PDU CHOICE
    w.constrained_int(procedure_code, 0, 255)  # procedureCode (1옥텟, 정렬)
    w.enumerated(criticality, 3)               # criticality (2비트)
    w.align()
    w.open_type(value)
    return w.bytes()


@dataclass
class NgapPdu:
    """디코딩된 NGAP PDU."""
    pdu_type: int
    procedure_code: int
    criticality: int
    name: str
    #: ProtocolIE-ID → 값 옥텟 (중복 시 마지막)
    ies: Dict[int, bytes] = field(default_factory=dict)
    #: 등장 순서대로 (id, criticality, 값)
    ie_list: List[Tuple[int, int, bytes]] = field(default_factory=list)
    raw: bytes = b""

    @property
    def type_name(self) -> str:
        return {0: "initiatingMessage", 1: "successfulOutcome",
                2: "unsuccessfulOutcome"}.get(self.pdu_type, "?")

    def __repr__(self) -> str:  # pragma: no cover
        ies = ", ".join(IE_NAMES.get(i, str(i)) for i in self.ies)
        return f"<NGAP {self.type_name}/{self.name} IEs=[{ies}]>"


def parse_pdu(data: bytes) -> NgapPdu:
    """NGAP PDU 골격 파싱(IE 값은 옥텟 그대로 보관)."""
    r = BitReader(data)
    try:
        pdu_type = r.choice_index(3)
        proc = r.constrained_int(0, 255)
        crit = r.enumerated(3)
        r.align()
        value = r.open_type()
    except AperError as e:
        raise NgapError(f"NGAP PDU 골격 파싱 실패: {e}") from e

    pdu = NgapPdu(pdu_type=pdu_type, procedure_code=proc, criticality=crit,
                  name=PROC_NAMES.get(proc, f"proc-{proc}"), raw=data)
    pdu.ie_list = parse_ie_container(value)
    for ie_id, _c, content in pdu.ie_list:
        pdu.ies[ie_id] = content
    return pdu


def parse_ie_container(value: bytes) -> List[Tuple[int, int, bytes]]:
    """ProtocolIE-Container 파싱 → [(id, criticality, 값 옥텟)]."""
    r = BitReader(value)
    r.sequence_preamble(True, 0)
    r.align()
    count = r.sequence_of_count(0, MAX_PROTOCOL_IES)
    out: List[Tuple[int, int, bytes]] = []
    for _ in range(count):
        if r.remaining_bits < 24:
            break
        ie_id = r.constrained_int(0, MAX_PROTOCOL_IES)
        crit = r.enumerated(3)
        r.align()
        content = r.open_type()
        out.append((ie_id, crit, content))
    return out


# ═════════════════════════════════════════════════════════════════════════════
# IE 값 인코더
# ═════════════════════════════════════════════════════════════════════════════
def enc_ran_ue_ngap_id(value: int) -> bytes:
    """RAN-UE-NGAP-ID ::= INTEGER (0..4294967295)."""
    return BitWriter().constrained_int(value, 0, 4294967295).bytes()


def enc_amf_ue_ngap_id(value: int) -> bytes:
    """AMF-UE-NGAP-ID ::= INTEGER (0..1099511627775)."""
    return BitWriter().constrained_int(value, 0, 1099511627775).bytes()


def dec_ran_ue_ngap_id(data: bytes) -> int:
    return BitReader(data).constrained_int(0, 4294967295)


def dec_amf_ue_ngap_id(data: bytes) -> int:
    return BitReader(data).constrained_int(0, 1099511627775)


def enc_nas_pdu(nas: bytes) -> bytes:
    """NAS-PDU ::= OCTET STRING (비제약)."""
    return BitWriter().octet_string(nas).bytes()


def dec_nas_pdu(data: bytes) -> bytes:
    return BitReader(data).octet_string()


def _w_plmn(w: BitWriter, plmn: bytes) -> None:
    w.octet_string(plmn, 3, 3)


def enc_global_gnb_id(plmn: bytes, gnb_id: int, gnb_id_bits: int = 24) -> bytes:
    """GlobalRANNodeID ::= CHOICE { globalGNB-ID GlobalGNB-ID, ... }."""
    w = BitWriter()
    w.choice_index(0, 3)                     # globalGNB-ID
    w.sequence_preamble(True, [False])       # GlobalGNB-ID: iE-Extensions 없음
    _w_plmn(w, plmn)
    w.choice_index(0, 1)                     # GNB-ID CHOICE (대안 1개 → 인덱스 0비트)
    w.bit_string(gnb_id, gnb_id_bits, 22, 32)
    return w.bytes()


def enc_supported_ta_list(tac: int, plmn: bytes,
                          slices: List[Tuple[int, Optional[str]]]) -> bytes:
    """SupportedTAList — TAC 1개 + BroadcastPLMN 1개 + 슬라이스 목록."""
    w = BitWriter()
    w.sequence_of_count(1, 1, MAX_TACS)                       # SupportedTAItem 1개
    w.sequence_preamble(True, [False])                        # SupportedTAItem
    w.octet_string(tac.to_bytes(3, "big"), 3, 3)              # TAC
    w.sequence_of_count(1, 1, MAX_BPLMNS)                     # BroadcastPLMNItem 1개
    w.sequence_preamble(True, [False])                        # BroadcastPLMNItem
    _w_plmn(w, plmn)
    w.sequence_of_count(len(slices), 1, MAX_SLICE_ITEMS)      # SliceSupportList
    for sst, sd in slices:
        w.sequence_preamble(True, [False])                    # SliceSupportItem
        _w_s_nssai(w, sst, sd)
    return w.bytes()


def _w_s_nssai(w: BitWriter, sst: int, sd: Optional[str]) -> None:
    """S-NSSAI ::= SEQUENCE { sST(1옥텟), sD(3옥텟) OPTIONAL, iE-Ext OPTIONAL, ... }."""
    has_sd = sd not in (None, "", "null")
    w.sequence_preamble(True, [has_sd, False])
    w.octet_string(bytes([sst & 0xFF]), 1, 1)
    if has_sd:
        w.octet_string(bytes.fromhex(str(sd).zfill(6)), 3, 3)


def enc_s_nssai(sst: int, sd: Optional[str] = None) -> bytes:
    w = BitWriter()
    _w_s_nssai(w, sst, sd)
    return w.bytes()


def enc_paging_drx(name: str = "v128") -> bytes:
    idx = PAGING_DRX.index(name) if name in PAGING_DRX else 2
    return BitWriter().enumerated(idx, len(PAGING_DRX), extensible=True).bytes()


def enc_ran_node_name(name: str) -> bytes:
    """RANNodeName ::= PrintableString (SIZE(1..150,...))."""
    return BitWriter().printable_string(name, 1, 150, extensible=True).bytes()


def enc_rrc_establishment_cause(cause: str = "mo-Data") -> bytes:
    idx = RRC_CAUSES.index(cause) if cause in RRC_CAUSES else RRC_CAUSES.index("mo-Data")
    return BitWriter().enumerated(idx, len(RRC_CAUSES), extensible=True).bytes()


def enc_ue_context_request(requested: bool = True) -> bytes:
    """UEContextRequest ::= ENUMERATED { requested, ... } — 루트값 1개."""
    return BitWriter().enumerated(0, 1, extensible=True).bytes()


def enc_user_location_information_nr(plmn: bytes, nr_cell_identity: int,
                                     tac: int) -> bytes:
    """UserLocationInformation ::= CHOICE { eUTRA, NR, N3IWF }.

    주의: 이 CHOICE 는 **확장 마커가 없다**(확장비트를 쓰면 안 됨). tshark 대조로 확인:
    확장비트를 넣으면 코어가 userLocationInformationEUTRA 로 오독한다.
    """
    w = BitWriter()
    w.choice_index(1, 3, extensible=False)          # userLocationInformationNR
    w.sequence_preamble(True, [False, False])       # timeStamp/iE-Ext 없음
    # NR-CGI
    w.sequence_preamble(True, [False])
    _w_plmn(w, plmn)
    w.bit_string(nr_cell_identity, 36, 36, 36)
    # TAI
    w.sequence_preamble(True, [False])
    _w_plmn(w, plmn)
    w.octet_string(tac.to_bytes(3, "big"), 3, 3)
    return w.bytes()


def _w_transport_layer_address(w: BitWriter, addr: str) -> None:
    """TransportLayerAddress ::= BIT STRING (SIZE(1..160,...))."""
    ip = ipaddress.ip_address(addr)
    raw = ip.packed
    nbits = len(raw) * 8
    w.bit_string(int.from_bytes(raw, "big"), nbits, 1, 160, extensible=True)


def _w_gtp_tunnel(w: BitWriter, addr: str, teid: int) -> None:
    """UPTransportLayerInformation 을 **기존 비트스트림에 이어서** 기록.

    주의: 하위 구조를 따로 인코딩해 바이트로 붙이면 안 된다. APER 의 옥텟정렬은
    바깥 구조의 비트오프셋을 기준으로 하므로, 독립 인코딩한 바이트를 비정렬 위치에
    붙이면 전체가 시프트된다(tshark 대조로 확인: 주소·TEID 가 1비트씩 밀림).
    """
    w.choice_index(0, 1)                            # gTPTunnel
    w.sequence_preamble(True, [False])              # GTPTunnel: iE-Ext 없음
    _w_transport_layer_address(w, addr)
    w.octet_string(teid.to_bytes(4, "big"), 4, 4)


def enc_gtp_tunnel(addr: str, teid: int) -> bytes:
    """독립(옥텟정렬) UPTransportLayerInformation — IE 값(open type)으로 쓸 때만."""
    w = BitWriter()
    _w_gtp_tunnel(w, addr, teid)
    return w.bytes()


def dec_gtp_tunnel(data: bytes) -> Dict[str, Any]:
    """GTPTunnel 디코딩 → {addr, teid}."""
    r = BitReader(data)
    r.choice_index(1)                               # gTPTunnel
    r.sequence_preamble(True, 1)
    val, nbits = r.bit_string(1, 160, extensible=True)
    raw = val.to_bytes(nbits // 8, "big") if nbits % 8 == 0 else None
    if raw is None:
        raise NgapError(f"TransportLayerAddress 비트수가 옥텟 배수가 아님: {nbits}")
    addr = str(ipaddress.ip_address(raw))
    teid = int.from_bytes(r.octet_string(4, 4), "big")
    return {"addr": addr, "teid": teid, "addr_bits": nbits}


def enc_pdu_session_resource_setup_response_transfer(
        gnb_addr: str, gnb_teid: int, qfis: List[int]) -> bytes:
    """PDUSessionResourceSetupResponseTransfer — gNB 측 N3 종단을 코어에 알린다."""
    w = BitWriter()
    # ext(1) + optional 4개(additionalDL/securityResult/qosFlowFailed/iE-Ext)
    w.sequence_preamble(True, [False, False, False, False])
    # QosFlowPerTNLInformation
    w.sequence_preamble(True, [False])
    _w_gtp_tunnel(w, gnb_addr, gnb_teid)             # 인라인 기록(정렬 기준 유지)
    # AssociatedQosFlowList
    w.sequence_of_count(len(qfis) or 1, 1, MAX_QOS_FLOWS)
    for qfi in (qfis or [1]):
        # AssociatedQosFlowItem 의 OPTIONAL 은 3개다:
        #   qosFlowMappingIndication / currentQoSParaSetIndex(Rel-16 추가) / iE-Extensions
        # 2개로 쓰면 QFI 가 1비트 밀린다(tshark 대조로 확인).
        w.sequence_preamble(True, [False, False, False])
        w.constrained_int(qfi, 0, 63)
    return w.bytes()


def enc_pdu_session_resource_setup_list_su_res(
        items: List[Tuple[int, bytes]]) -> bytes:
    """PDUSessionResourceSetupListSURes ::= SEQUENCE OF { pDUSessionID, transfer }."""
    w = BitWriter()
    w.sequence_of_count(len(items), 1, MAX_PDU_SESSIONS)
    for pdu_session_id, transfer in items:
        w.sequence_preamble(True, [False])           # iE-Extensions 없음
        w.constrained_int(pdu_session_id, 0, 255)
        w.octet_string(transfer)                     # OCTET STRING (비제약)
    return w.bytes()


#: ListCxtRes 도 동일 구조(항목 이름만 다름)
enc_pdu_session_resource_setup_list_cxt_res = enc_pdu_session_resource_setup_list_su_res


def enc_cause_radio(value: int = 0) -> bytes:
    """Cause ::= CHOICE { radioNetwork, transport, nas, protocol, misc, ... }.

    radioNetwork 는 확장가능 ENUMERATED(루트 값이 많음). 여기서는 대표값만 쓴다.
    value 0 = unspecified.
    """
    w = BitWriter()
    w.choice_index(0, 5)                             # radioNetwork
    w.enumerated(value, 48, extensible=True)         # CauseRadioNetwork 루트 48개
    return w.bytes()


def enc_ue_ngap_id_pair(amf_id: int, ran_id: int) -> bytes:
    """UE-NGAP-IDs ::= CHOICE { uE-NGAP-ID-pair, aMF-UE-NGAP-ID, ... }."""
    w = BitWriter()
    w.choice_index(0, 2)                             # uE-NGAP-ID-pair
    w.sequence_preamble(True, [False])
    w.constrained_int(amf_id, 0, 1099511627775)
    w.constrained_int(ran_id, 0, 4294967295)
    return w.bytes()


# ═════════════════════════════════════════════════════════════════════════════
# 메시지 인코더 (gNB → AMF)
# ═════════════════════════════════════════════════════════════════════════════
def ng_setup_request(*, plmn: bytes, gnb_id: int, gnb_id_bits: int, tac: int,
                     slices: List[Tuple[int, Optional[str]]],
                     ran_node_name: Optional[str] = None,
                     paging_drx: str = "v128") -> bytes:
    """NGSetupRequest — gNB 가 AMF 와 N2 연결을 수립한다."""
    ies: List[Tuple[int, int, bytes]] = [
        (IE_GLOBAL_RAN_NODE_ID, CRIT_REJECT, enc_global_gnb_id(plmn, gnb_id, gnb_id_bits)),
    ]
    if ran_node_name:
        ies.append((IE_RAN_NODE_NAME, CRIT_IGNORE, enc_ran_node_name(ran_node_name)))
    ies.append((IE_SUPPORTED_TA_LIST, CRIT_REJECT,
                enc_supported_ta_list(tac, plmn, slices)))
    ies.append((IE_DEFAULT_PAGING_DRX, CRIT_IGNORE, enc_paging_drx(paging_drx)))
    return build_pdu(PDU_INITIATING, PROC_NG_SETUP, CRIT_REJECT, ies)


def initial_ue_message(*, ran_ue_ngap_id: int, nas_pdu: bytes, plmn: bytes,
                       nr_cell_identity: int, tac: int,
                       rrc_cause: str = "mo-Data",
                       ue_context_request: bool = True) -> bytes:
    """InitialUEMessage — 단말의 첫 NAS 메시지를 코어로 올린다."""
    ies = [
        (IE_RAN_UE_NGAP_ID, CRIT_REJECT, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
        (IE_NAS_PDU, CRIT_REJECT, enc_nas_pdu(nas_pdu)),
        (IE_USER_LOCATION_INFORMATION, CRIT_REJECT,
         enc_user_location_information_nr(plmn, nr_cell_identity, tac)),
        (IE_RRC_ESTABLISHMENT_CAUSE, CRIT_IGNORE, enc_rrc_establishment_cause(rrc_cause)),
    ]
    if ue_context_request:
        ies.append((IE_UE_CONTEXT_REQUEST, CRIT_IGNORE, enc_ue_context_request()))
    return build_pdu(PDU_INITIATING, PROC_INITIAL_UE_MESSAGE, CRIT_IGNORE, ies)


def uplink_nas_transport(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int, nas_pdu: bytes,
                         plmn: bytes, nr_cell_identity: int, tac: int) -> bytes:
    """UplinkNASTransport — 등록 이후의 NAS 메시지 전달."""
    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_REJECT, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_REJECT, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
        (IE_NAS_PDU, CRIT_REJECT, enc_nas_pdu(nas_pdu)),
        (IE_USER_LOCATION_INFORMATION, CRIT_IGNORE,
         enc_user_location_information_nr(plmn, nr_cell_identity, tac)),
    ]
    return build_pdu(PDU_INITIATING, PROC_UPLINK_NAS_TRANSPORT, CRIT_IGNORE, ies)


def initial_context_setup_response(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                                   setup_items: Optional[List[Tuple[int, bytes]]] = None
                                   ) -> bytes:
    """InitialContextSetupResponse — 컨텍스트 수립 완료(+ PDU 세션 결과)."""
    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_IGNORE, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_IGNORE, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
    ]
    if setup_items:
        ies.append((IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES, CRIT_IGNORE,
                    enc_pdu_session_resource_setup_list_cxt_res(setup_items)))
    return build_pdu(PDU_SUCCESSFUL, PROC_INITIAL_CONTEXT_SETUP, CRIT_REJECT, ies)


def pdu_session_resource_setup_response(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                                        setup_items: List[Tuple[int, bytes]]) -> bytes:
    """PDUSessionResourceSetupResponse — gNB N3 종단(TEID/주소)을 코어에 통보."""
    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_IGNORE, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_IGNORE, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
    ]
    if setup_items:
        ies.append((IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES, CRIT_IGNORE,
                    enc_pdu_session_resource_setup_list_su_res(setup_items)))
    return build_pdu(PDU_SUCCESSFUL, PROC_PDU_SESSION_RESOURCE_SETUP, CRIT_REJECT, ies)


def ue_context_release_request(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                               cause: int = 0) -> bytes:
    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_REJECT, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_REJECT, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
        (IE_CAUSE, CRIT_IGNORE, enc_cause_radio(cause)),
    ]
    return build_pdu(PDU_INITIATING, PROC_UE_CONTEXT_RELEASE_REQUEST, CRIT_IGNORE, ies)


def ue_context_release_complete(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int) -> bytes:
    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_IGNORE, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_IGNORE, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
    ]
    return build_pdu(PDU_SUCCESSFUL, PROC_UE_CONTEXT_RELEASE, CRIT_REJECT, ies)


# ═════════════════════════════════════════════════════════════════════════════
# 메시지 인코더 (AMF → gNB) — 스텁 코어용
# ═════════════════════════════════════════════════════════════════════════════
def ng_setup_response(*, amf_name: str = "ranemu-stub-amf",
                      plmn: bytes = b"\x54\xf0\x50",
                      relative_capacity: int = 255,
                      slices: Optional[List[Tuple[int, Optional[str]]]] = None) -> bytes:
    """NGSetupResponse (스텁 AMF)."""
    slices = slices or [(1, None)]
    # ServedGUAMIList
    w = BitWriter()
    w.sequence_of_count(1, 1, 256)
    w.sequence_preamble(True, [False, False])        # backupAMFName/iE-Ext 없음
    # GUAMI ::= SEQUENCE { pLMNIdentity, aMFRegionID(BIT STRING 8), aMFSetID(10), aMFPointer(6), iE-Ext OPT }
    w.sequence_preamble(True, [False])
    _w_plmn(w, plmn)
    w.bit_string(0x02, 8, 8, 8)
    w.bit_string(0x001, 10, 10, 10)
    w.bit_string(0x00, 6, 6, 6)
    served_guami = w.bytes()

    # PLMNSupportList
    w = BitWriter()
    w.sequence_of_count(1, 1, 12)
    w.sequence_preamble(True, [False])
    _w_plmn(w, plmn)
    w.sequence_of_count(len(slices), 1, MAX_SLICE_ITEMS)
    for sst, sd in slices:
        w.sequence_preamble(True, [False])
        _w_s_nssai(w, sst, sd)
    plmn_support = w.bytes()

    ies = [
        (IE_AMF_NAME, CRIT_REJECT,
         BitWriter().printable_string(amf_name, 1, 150, extensible=True).bytes()),
        (IE_SERVED_GUAMI_LIST, CRIT_REJECT, served_guami),
        (IE_RELATIVE_AMF_CAPACITY, CRIT_IGNORE,
         BitWriter().constrained_int(relative_capacity, 0, 255).bytes()),
        (IE_PLMN_SUPPORT_LIST, CRIT_REJECT, plmn_support),
    ]
    return build_pdu(PDU_SUCCESSFUL, PROC_NG_SETUP, CRIT_REJECT, ies)


def downlink_nas_transport(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                           nas_pdu: bytes) -> bytes:
    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_REJECT, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_REJECT, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
        (IE_NAS_PDU, CRIT_REJECT, enc_nas_pdu(nas_pdu)),
    ]
    return build_pdu(PDU_INITIATING, PROC_DOWNLINK_NAS_TRANSPORT, CRIT_IGNORE, ies)


def enc_pdu_session_resource_setup_request_transfer(
        upf_addr: str, upf_teid: int, qfis: Optional[List[int]] = None,
        pdu_session_type: int = 0) -> bytes:
    """PDUSessionResourceSetupRequestTransfer (스텁 SMF/UPF 용).

    코어가 gNB 에게 "상향 트래픽은 이 UPF 주소/TEID 로 보내라" 고 알리는 구조.
    """
    qfis = qfis or [1]
    # UL-NGU-UP-TNLInformation
    tnl = enc_gtp_tunnel(upf_addr, upf_teid)
    # PDUSessionType ::= ENUMERATED { ipv4, ipv6, ipv4v6, ethernet, unstructured, ... }
    pst = BitWriter().enumerated(pdu_session_type, 5, extensible=True).bytes()
    # QosFlowSetupRequestList
    w = BitWriter()
    w.sequence_of_count(len(qfis), 1, MAX_QOS_FLOWS)
    for qfi in qfis:
        # QosFlowSetupRequestItem: ext + e-RAB-ID/iE-Ext optional
        w.sequence_preamble(True, [False, False])
        w.constrained_int(qfi, 0, 63)
        # QosFlowLevelQosParameters ::= SEQUENCE {
        #   qosCharacteristics CHOICE{nonDynamic5QI, dynamic5QI,...},
        #   allocationAndRetentionPriority, gBR-QosInformation OPT,
        #   reflectiveQosAttribute OPT, additionalQosFlowInformation OPT, iE-Ext OPT, ... }
        w.sequence_preamble(True, [False, False, False, False])
        w.choice_index(0, 2)                        # nonDynamic5QI
        # NonDynamic5QIDescriptor ::= SEQUENCE { fiveQI, priorityLevelQos OPT,
        #   averagingWindow OPT, maximumDataBurstVolume OPT, iE-Ext OPT, ... }
        w.sequence_preamble(True, [False, False, False, False])
        w.constrained_int(9, 0, 255)                # 5QI = 9
        # AllocationAndRetentionPriority ::= SEQUENCE { priorityLevelARP,
        #   pre-emptionCapability, pre-emptionVulnerability, iE-Ext OPT, ... }
        w.sequence_preamble(True, [False])
        w.constrained_int(8, 1, 15)                 # priorityLevelARP
        w.enumerated(0, 2)                          # shall-not-trigger-pre-emption
        w.enumerated(0, 2)                          # not-pre-emptable
    qos_list = w.bytes()

    return build_ie_container([
        (IE_UL_NGU_UP_TNL_INFORMATION, CRIT_REJECT, tnl),
        (IE_PDU_SESSION_TYPE, CRIT_REJECT, pst),
        (IE_QOS_FLOW_SETUP_REQUEST_LIST, CRIT_REJECT, qos_list),
    ])


def build_ie_container(ies: List[Tuple[int, int, bytes]]) -> bytes:
    """SEQUENCE { protocolIEs ProtocolIE-Container, ... } 형태의 transfer 구조."""
    w = BitWriter()
    w.sequence_preamble(True, [])
    w.align()
    w.sequence_of_count(len(ies), 0, MAX_PROTOCOL_IES)
    for ie_id, crit, content in ies:
        _ie_field(w, ie_id, crit, content)
    return w.bytes()


def pdu_session_resource_setup_request(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                                       pdu_session_id: int, nas_pdu: Optional[bytes],
                                       transfer: bytes,
                                       sst: int = 1, sd: Optional[str] = None) -> bytes:
    """PDUSessionResourceSetupRequest (스텁 코어용)."""
    w = BitWriter()
    w.sequence_of_count(1, 1, MAX_PDU_SESSIONS)
    # PDUSessionResourceSetupItemSUReq ::= SEQUENCE {
    #   pDUSessionID, pDUSessionNAS-PDU OPTIONAL, s-NSSAI,
    #   pDUSessionResourceSetupRequestTransfer, iE-Extensions OPTIONAL, ... }
    w.sequence_preamble(True, [nas_pdu is not None, False])
    w.constrained_int(pdu_session_id, 0, 255)
    if nas_pdu is not None:
        w.octet_string(nas_pdu)
    _w_s_nssai(w, sst, sd)
    w.octet_string(transfer)
    su_req = w.bytes()

    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_REJECT, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_REJECT, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
        (IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ, CRIT_REJECT, su_req),
    ]
    return build_pdu(PDU_INITIATING, PROC_PDU_SESSION_RESOURCE_SETUP, CRIT_REJECT, ies)


def initial_context_setup_request(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                                  nas_pdu: Optional[bytes] = None,
                                  security_key: Optional[bytes] = None,
                                  plmn: bytes = b"\x54\xf0\x50",
                                  slices: Optional[List[Tuple[int, Optional[str]]]] = None,
                                  ue_ambr_dl: int = 1_000_000_000,
                                  ue_ambr_ul: int = 200_000_000) -> bytes:
    """InitialContextSetupRequest (스텁 코어용)."""
    slices = slices or [(1, None)]
    # UEAggregateMaximumBitRate ::= SEQUENCE { dl BitRate, ul BitRate, iE-Ext OPT, ... }
    # BitRate ::= INTEGER (0..4000000000000, ...)
    w = BitWriter()
    w.sequence_preamble(True, [False])
    for v in (ue_ambr_dl, ue_ambr_ul):
        w.bit(0)                                     # 확장 정수: 루트 범위 안
        w.constrained_int(v, 0, 4000000000000)
    ambr = w.bytes()

    # GUAMI
    w = BitWriter()
    w.sequence_preamble(True, [False])
    _w_plmn(w, plmn)
    w.bit_string(0x02, 8, 8, 8)
    w.bit_string(0x001, 10, 10, 10)
    w.bit_string(0x00, 6, 6, 6)
    guami = w.bytes()

    # AllowedNSSAI
    w = BitWriter()
    w.sequence_of_count(len(slices), 1, 8)
    for sst, sd in slices:
        w.sequence_preamble(True, [False])
        _w_s_nssai(w, sst, sd)
    allowed_nssai = w.bytes()

    # UESecurityCapabilities ::= SEQUENCE { nRencryption BIT STRING(16),
    #   nRintegrityProtection(16), eUTRAencryption(16), eUTRAintegrity(16), iE-Ext OPT, ...}
    w = BitWriter()
    w.sequence_preamble(True, [False])
    for _ in range(4):
        w.bit_string(0xE000, 16, 16, 16)             # 알고리즘 0/1/2 지원 표시
    ue_sec = w.bytes()

    ies = [
        (IE_AMF_UE_NGAP_ID, CRIT_REJECT, enc_amf_ue_ngap_id(amf_ue_ngap_id)),
        (IE_RAN_UE_NGAP_ID, CRIT_REJECT, enc_ran_ue_ngap_id(ran_ue_ngap_id)),
        (IE_UE_AGGREGATE_MAXIMUM_BIT_RATE, CRIT_REJECT, ambr),
        (IE_GUAMI, CRIT_REJECT, guami),
        (IE_ALLOWED_NSSAI, CRIT_REJECT, allowed_nssai),
        (IE_UE_SECURITY_CAPABILITIES, CRIT_REJECT, ue_sec),
        (IE_SECURITY_KEY, CRIT_REJECT,
         BitWriter().bit_string(int.from_bytes(security_key or bytes(32), "big"),
                                256, 256, 256).bytes()),
    ]
    if nas_pdu is not None:
        ies.append((IE_NAS_PDU, CRIT_IGNORE, enc_nas_pdu(nas_pdu)))
    return build_pdu(PDU_INITIATING, PROC_INITIAL_CONTEXT_SETUP, CRIT_REJECT, ies)


def ue_context_release_command(*, amf_ue_ngap_id: int, ran_ue_ngap_id: int,
                               cause: int = 0) -> bytes:
    ies = [
        (IE_UE_NGAP_IDS, CRIT_REJECT, enc_ue_ngap_id_pair(amf_ue_ngap_id, ran_ue_ngap_id)),
        (IE_CAUSE, CRIT_IGNORE, enc_cause_radio(cause)),
    ]
    return build_pdu(PDU_INITIATING, PROC_UE_CONTEXT_RELEASE, CRIT_REJECT, ies)


# ═════════════════════════════════════════════════════════════════════════════
# 상위 디코더 — 코어가 보낸 메시지에서 필요한 값을 뽑는다
# ═════════════════════════════════════════════════════════════════════════════
def extract_common(pdu: NgapPdu) -> Dict[str, Any]:
    """AMF/RAN UE NGAP ID 와 NAS-PDU 를 관용적으로 추출."""
    out: Dict[str, Any] = {}
    if IE_AMF_UE_NGAP_ID in pdu.ies:
        try:
            out["amf_ue_ngap_id"] = dec_amf_ue_ngap_id(pdu.ies[IE_AMF_UE_NGAP_ID])
        except AperError:
            pass
    if IE_RAN_UE_NGAP_ID in pdu.ies:
        try:
            out["ran_ue_ngap_id"] = dec_ran_ue_ngap_id(pdu.ies[IE_RAN_UE_NGAP_ID])
        except AperError:
            pass
    if IE_NAS_PDU in pdu.ies:
        try:
            out["nas_pdu"] = dec_nas_pdu(pdu.ies[IE_NAS_PDU])
        except AperError:
            pass
    return out


def find_gtp_tunnel(data: bytes) -> Optional[Dict[str, Any]]:
    """옥텟열에서 GTPTunnel 을 해석해 본다(구조 타당성 검사 포함)."""
    try:
        info = dec_gtp_tunnel(data)
    except (AperError, NgapError, ValueError):
        return None
    if info["addr_bits"] not in (32, 128):
        return None
    return info


def extract_pdu_session_setup_request(pdu: NgapPdu) -> List[Dict[str, Any]]:
    """PDUSessionResourceSetupRequest → [{pdu_session_id, nas_pdu, upf_addr, upf_teid, qfis}].

    설계 메모: transfer 안의 IE ID 는 릴리즈마다 추가/변동이 있어, ID 로 먼저 찾고
    실패하면 **모든 IE 를 GTPTunnel 로 해석 시도**하는 이중 전략을 쓴다. 이렇게 하면
    코어 구현체가 부가 IE 를 섞어 보내도 N3 종단 정보를 놓치지 않는다.
    """
    raw = pdu.ies.get(IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_REQ)
    if raw is None:
        raw = pdu.ies.get(IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_REQ)
    if raw is None:
        return []
    out: List[Dict[str, Any]] = []
    r = BitReader(raw)
    try:
        count = r.sequence_of_count(1, MAX_PDU_SESSIONS)
    except AperError:
        return []
    for _ in range(count):
        try:
            _ext, opts = r.sequence_preamble(True, 2)   # NAS-PDU?, iE-Extensions?
            psi = r.constrained_int(0, 255)
            nas = r.octet_string() if opts[0] else None
            # S-NSSAI
            _e2, sopts = r.sequence_preamble(True, 2)
            sst = r.octet_string(1, 1)[0]
            sd = r.octet_string(3, 3).hex() if sopts[0] else None
            transfer = r.octet_string()
        except AperError:
            break
        item: Dict[str, Any] = {"pdu_session_id": psi, "nas_pdu": nas,
                                "sst": sst, "sd": sd, "transfer": transfer}
        item.update(parse_setup_request_transfer(transfer))
        out.append(item)
    return out


def parse_setup_request_transfer(transfer: bytes) -> Dict[str, Any]:
    """PDUSessionResourceSetupRequestTransfer → UPF N3 종단 + QFI 목록."""
    out: Dict[str, Any] = {"upf_addr": None, "upf_teid": None, "qfis": []}
    try:
        ies = parse_ie_container(transfer)
    except AperError:
        return out

    by_id = {i: c for i, _crit, c in ies}
    # 1차: 규격 IE ID 로 조회
    tnl = by_id.get(IE_UL_NGU_UP_TNL_INFORMATION)
    info = find_gtp_tunnel(tnl) if tnl else None
    # 2차: ID 가 달라도 GTPTunnel 로 해석되는 IE 를 찾는다
    if info is None:
        for _id, content in by_id.items():
            info = find_gtp_tunnel(content)
            if info:
                break
    if info:
        out["upf_addr"] = info["addr"]
        out["upf_teid"] = info["teid"]

    qos = by_id.get(IE_QOS_FLOW_SETUP_REQUEST_LIST)
    if qos:
        out["qfis"] = _extract_qfis(qos)
    if not out["qfis"]:
        for _id, content in by_id.items():
            q = _extract_qfis(content)
            if q:
                out["qfis"] = q
                break
    return out


def _extract_qfis(data: bytes) -> List[int]:
    """QosFlowSetupRequestList 앞부분에서 QFI 만 최선노력으로 추출."""
    try:
        r = BitReader(data)
        n = r.sequence_of_count(1, MAX_QOS_FLOWS)
        if not (1 <= n <= MAX_QOS_FLOWS):
            return []
        r.sequence_preamble(True, 2)
        qfi = r.constrained_int(0, 63)
        return [qfi]
    except AperError:
        return []


def extract_ue_ngap_ids(pdu: NgapPdu) -> Dict[str, Any]:
    """UEContextReleaseCommand 의 UE-NGAP-IDs 파싱."""
    raw = pdu.ies.get(IE_UE_NGAP_IDS)
    if not raw:
        return extract_common(pdu)
    try:
        r = BitReader(raw)
        idx = r.choice_index(2)
        if idx == 0:
            r.sequence_preamble(True, 1)
            amf = r.constrained_int(0, 1099511627775)
            ran = r.constrained_int(0, 4294967295)
            return {"amf_ue_ngap_id": amf, "ran_ue_ngap_id": ran}
        return {"amf_ue_ngap_id": r.constrained_int(0, 1099511627775)}
    except AperError:
        return {}
