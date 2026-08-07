#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.nas.nas5gs — NAS 5GS (TS 24.501) 메시지 인코더/디코더.

NAS 는 ASN.1 이 아니라 **TLV 계열 바이트 포맷**이라 손수 구현이 현실적이다.
이 모듈은 단말 에뮬레이터가 실제로 주고받는 메시지만 정확히 다룬다:

  단말 → 네트워크                       네트워크 → 단말
  ─────────────────────────────         ────────────────────────────────
  Registration Request      0x41        Authentication Request     0x56
  Authentication Response   0x57        Security Mode Command      0x5D
  Authentication Failure    0x59        Registration Accept        0x42
  Security Mode Complete    0x5E        Registration Reject        0x44
  Registration Complete     0x43        DL NAS Transport           0x68
  UL NAS Transport          0x67        Identity Request           0x5B
  Deregistration Request    0x45        Configuration Update Cmd   0x54
  ─ 5GSM ────────────────────────       ─ 5GSM ─────────────────────────
  PDU Session Est. Request  0xC1        PDU Session Est. Accept    0xC2
                                        PDU Session Est. Reject    0xC3

IE 형식 규칙 (TS 24.007 §11.2.4)
================================
  Type 1 TV   : 1옥텟. 상위니블=IEI, 하위니블=값.   → 옥텟의 bit8 이 1
  Type 3 TV   : IEI(1) + 고정길이 값
  Type 4 TLV  : IEI(1) + 길이(1) + 값
  Type 6 TLV-E: IEI(1) + 길이(2) + 값
전체옥텟 IEI 는 0x00~0x7F 범위만 쓰이므로 `bit8` 로 Type1 과 구분할 수 있다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..util import bcd_decode_digits, bcd_encode_digits, imsi_split, plmn_decode, plmn_encode

# ═════════════════════════════════════════════════════════════════════════════
# 상수
# ═════════════════════════════════════════════════════════════════════════════
EPD_5GMM = 0x7E
EPD_5GSM = 0x2E

# 보안 헤더 타입 (TS 24.501 §9.3)
SHT_PLAIN = 0x00
SHT_INTEGRITY = 0x01
SHT_INTEGRITY_CIPHERED = 0x02
SHT_INTEGRITY_NEW_CTX = 0x03
SHT_INTEGRITY_CIPHERED_NEW_CTX = 0x04

# 5GMM 메시지 타입
MT_REGISTRATION_REQUEST = 0x41
MT_REGISTRATION_ACCEPT = 0x42
MT_REGISTRATION_COMPLETE = 0x43
MT_REGISTRATION_REJECT = 0x44
MT_DEREGISTRATION_REQUEST_UE = 0x45
MT_DEREGISTRATION_ACCEPT_UE = 0x46
MT_SERVICE_REQUEST = 0x4C
MT_SERVICE_REJECT = 0x4D
MT_SERVICE_ACCEPT = 0x4E
MT_CONFIGURATION_UPDATE_COMMAND = 0x54
MT_CONFIGURATION_UPDATE_COMPLETE = 0x55
MT_AUTHENTICATION_REQUEST = 0x56
MT_AUTHENTICATION_RESPONSE = 0x57
MT_AUTHENTICATION_REJECT = 0x58
MT_AUTHENTICATION_FAILURE = 0x59
MT_AUTHENTICATION_RESULT = 0x5A
MT_IDENTITY_REQUEST = 0x5B
MT_IDENTITY_RESPONSE = 0x5C
MT_SECURITY_MODE_COMMAND = 0x5D
MT_SECURITY_MODE_COMPLETE = 0x5E
MT_SECURITY_MODE_REJECT = 0x5F
MT_5GMM_STATUS = 0x64
MT_UL_NAS_TRANSPORT = 0x67
MT_DL_NAS_TRANSPORT = 0x68

# 5GSM 메시지 타입
MT_PDU_SESSION_EST_REQUEST = 0xC1
MT_PDU_SESSION_EST_ACCEPT = 0xC2
MT_PDU_SESSION_EST_REJECT = 0xC3
MT_PDU_SESSION_REL_REQUEST = 0xD1
MT_PDU_SESSION_REL_COMMAND = 0xD3

MSG_NAMES = {
    MT_REGISTRATION_REQUEST: "RegistrationRequest",
    MT_REGISTRATION_ACCEPT: "RegistrationAccept",
    MT_REGISTRATION_COMPLETE: "RegistrationComplete",
    MT_REGISTRATION_REJECT: "RegistrationReject",
    MT_DEREGISTRATION_REQUEST_UE: "DeregistrationRequest",
    MT_DEREGISTRATION_ACCEPT_UE: "DeregistrationAccept",
    MT_SERVICE_REQUEST: "ServiceRequest", MT_SERVICE_ACCEPT: "ServiceAccept",
    MT_SERVICE_REJECT: "ServiceReject",
    MT_CONFIGURATION_UPDATE_COMMAND: "ConfigurationUpdateCommand",
    MT_CONFIGURATION_UPDATE_COMPLETE: "ConfigurationUpdateComplete",
    MT_AUTHENTICATION_REQUEST: "AuthenticationRequest",
    MT_AUTHENTICATION_RESPONSE: "AuthenticationResponse",
    MT_AUTHENTICATION_REJECT: "AuthenticationReject",
    MT_AUTHENTICATION_FAILURE: "AuthenticationFailure",
    MT_AUTHENTICATION_RESULT: "AuthenticationResult",
    MT_IDENTITY_REQUEST: "IdentityRequest", MT_IDENTITY_RESPONSE: "IdentityResponse",
    MT_SECURITY_MODE_COMMAND: "SecurityModeCommand",
    MT_SECURITY_MODE_COMPLETE: "SecurityModeComplete",
    MT_SECURITY_MODE_REJECT: "SecurityModeReject",
    MT_5GMM_STATUS: "5GMMStatus",
    MT_UL_NAS_TRANSPORT: "ULNASTransport", MT_DL_NAS_TRANSPORT: "DLNASTransport",
    MT_PDU_SESSION_EST_REQUEST: "PDUSessionEstablishmentRequest",
    MT_PDU_SESSION_EST_ACCEPT: "PDUSessionEstablishmentAccept",
    MT_PDU_SESSION_EST_REJECT: "PDUSessionEstablishmentReject",
    MT_PDU_SESSION_REL_REQUEST: "PDUSessionReleaseRequest",
    MT_PDU_SESSION_REL_COMMAND: "PDUSessionReleaseCommand",
}

# 5GS 등록 유형
REG_TYPE_INITIAL = 0x01
REG_TYPE_MOBILITY_UPDATE = 0x02
REG_TYPE_PERIODIC_UPDATE = 0x03
REG_TYPE_EMERGENCY = 0x04

# 신원 유형 (TS 24.501 §9.11.3.4)
ID_TYPE_NONE = 0
ID_TYPE_SUCI = 1
ID_TYPE_5G_GUTI = 2
ID_TYPE_IMEI = 3
ID_TYPE_5G_S_TMSI = 4
ID_TYPE_IMEISV = 5

# PDU 세션 타입
PDU_TYPE_IPV4 = 1
PDU_TYPE_IPV6 = 2
PDU_TYPE_IPV4V6 = 3
PDU_TYPE_UNSTRUCTURED = 4
PDU_TYPE_ETHERNET = 5
_PDU_TYPE_BY_NAME = {"ipv4": PDU_TYPE_IPV4, "ipv6": PDU_TYPE_IPV6,
                     "ipv4v6": PDU_TYPE_IPV4V6, "unstructured": PDU_TYPE_UNSTRUCTURED,
                     "ethernet": PDU_TYPE_ETHERNET}

# 페이로드 컨테이너 타입
PAYLOAD_CONTAINER_N1_SM = 0x01

# 요청 유형 (UL NAS Transport)
REQUEST_TYPE_INITIAL = 0x01
REQUEST_TYPE_EXISTING = 0x02
REQUEST_TYPE_INITIAL_EMERGENCY = 0x03


class NasDecodeError(ValueError):
    """NAS 메시지 파싱 실패."""


# ═════════════════════════════════════════════════════════════════════════════
# IE 인코더
# ═════════════════════════════════════════════════════════════════════════════
def enc_suci_imsi(imsi: str, routing_indicator: str = "0",
                  protection_scheme: int = 0, hn_key_id: int = 0) -> bytes:
    """SUCI(SUPI 형식=IMSI) 값부. null 은닉(scheme 0)이면 MSIN 평문 BCD.

    TS 24.501 §9.11.3.4 Figure 9.11.3.4.3
        octet4  : bit8 spare | bit7-5 SUPI format(000=IMSI) | bit4 spare | bit3-1 type(001=SUCI)
        octet5-7: MCC/MNC
        octet8-9: Routing indicator (BCD 4자리, 미설정은 0xF 채움)
        octet10 : bit4-1 Protection scheme id
        octet11 : Home network public key identifier
        octet12+: Scheme output
    """
    mcc, mnc, msin = imsi_split(imsi)
    out = bytearray()
    out.append((0b000 << 4) | ID_TYPE_SUCI)          # SUPI format=IMSI, type=SUCI
    out += plmn_encode(mcc, mnc)
    ri = (routing_indicator or "0")[:4]
    out += bcd_encode_digits(ri.ljust(4, "￿").replace("￿", ""), fill=0xF) \
        .ljust(2, b"\xff")[:2]
    out.append(protection_scheme & 0x0F)
    out.append(hn_key_id & 0xFF)
    if protection_scheme == 0:
        out += bcd_encode_digits(msin)
    else:
        raise NotImplementedError(
            "SUCI 은닉(profile A/B)은 미구현 — security.suci_scheme=null 을 쓰거나 "
            "코어에서 null scheme 을 허용하십시오")
    return bytes(out)


def enc_5g_guti(mcc: str, mnc: str, amf_region: int, amf_set: int,
                amf_pointer: int, tmsi: int) -> bytes:
    """5G-GUTI 값부 (TS 24.501 §9.11.3.4)."""
    out = bytearray()
    out.append(0xF0 | ID_TYPE_5G_GUTI)               # 상위니블은 spare(모두 1)
    out += plmn_encode(mcc, mnc)
    out.append(amf_region & 0xFF)
    out += (((amf_set & 0x3FF) << 6) | (amf_pointer & 0x3F)).to_bytes(2, "big")
    out += (tmsi & 0xFFFFFFFF).to_bytes(4, "big")
    return bytes(out)


def enc_no_identity() -> bytes:
    return bytes([ID_TYPE_NONE])


def enc_ue_security_capability(enc_algs: List[int], int_algs: List[int],
                               eps_enc: Optional[List[int]] = None,
                               eps_int: Optional[List[int]] = None) -> bytes:
    """UE 보안능력 값부 (TS 24.501 §9.11.3.54).

    각 옥텟의 bit8 이 알고리즘 0, bit7 이 1, … 순서다.
    """
    def _bits(algs: List[int]) -> int:
        v = 0
        for a in algs:
            if 0 <= a <= 7:
                v |= 1 << (7 - a)
        return v
    out = bytearray([_bits(enc_algs), _bits(int_algs)])
    if eps_enc is not None or eps_int is not None:
        out.append(_bits(eps_enc or []))
        out.append(_bits(eps_int or []))
    return bytes(out)


def dec_ue_security_capability(data: bytes) -> Dict[str, List[int]]:
    def _algs(byte: int) -> List[int]:
        return [i for i in range(8) if byte & (1 << (7 - i))]
    res = {"enc": _algs(data[0]) if len(data) > 0 else [],
           "int": _algs(data[1]) if len(data) > 1 else []}
    if len(data) >= 4:
        res["eps_enc"] = _algs(data[2])
        res["eps_int"] = _algs(data[3])
    return res


def enc_s_nssai(sst: int, sd: Optional[str] = None) -> bytes:
    """S-NSSAI 값부: SST[, SD(3옥텟)]."""
    out = bytearray([sst & 0xFF])
    if sd not in (None, "", "null"):
        sd_b = bytes.fromhex(str(sd).zfill(6))
        if len(sd_b) != 3:
            raise ValueError(f"S-NSSAI SD 는 3바이트(6 hex)여야 함: {sd!r}")
        out += sd_b
    return bytes(out)


def dec_s_nssai(data: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"sst": data[0] if data else None, "sd": None}
    if len(data) >= 4:
        out["sd"] = data[1:4].hex()
    return out


def enc_nssai(slices: List[Tuple[int, Optional[str]]]) -> bytes:
    """(Requested/Allowed) NSSAI 값부: 각 S-NSSAI 를 [len][value] 로 나열."""
    out = bytearray()
    for sst, sd in slices:
        v = enc_s_nssai(sst, sd)
        out.append(len(v))
        out += v
    return bytes(out)


def dec_nssai(data: bytes) -> List[Dict[str, Any]]:
    out, i = [], 0
    while i < len(data):
        ln = data[i]; i += 1
        if i + ln > len(data):
            break
        out.append(dec_s_nssai(data[i:i + ln]))
        i += ln
    return out


def enc_dnn(dnn: str) -> bytes:
    """DNN 값부 — TS 23.003 라벨 인코딩(각 라벨 앞에 길이)."""
    out = bytearray()
    for label in str(dnn).split("."):
        b = label.encode("utf-8")
        if not b:
            continue
        out.append(len(b))
        out += b
    return bytes(out)


def dec_dnn(data: bytes) -> str:
    labels, i = [], 0
    while i < len(data):
        ln = data[i]; i += 1
        labels.append(data[i:i + ln].decode("utf-8", "replace"))
        i += ln
    return ".".join(labels)


def enc_5gmm_capability(s1_mode: bool = False, ho_attach: bool = True,
                        lpp: bool = False) -> bytes:
    v = (0x01 if s1_mode else 0) | (0x02 if ho_attach else 0) | (0x04 if lpp else 0)
    return bytes([v])


def enc_session_ambr(dl_bps: int, ul_bps: int) -> bytes:
    """Session-AMBR 값부(6옥텟): 각 방향 [단위(1)][값(2)].

    단위 코드(TS 24.501 §9.11.4.14): 1=1Kbps, 2=4Kbps, 3=16Kbps, 4=64Kbps,
    5=256Kbps, 6=1Mbps, 7=4Mbps, 8=16Mbps, 9=64Mbps, 10=256Mbps, 11=1Gbps …
    """
    def _pack(bps: int) -> bytes:
        units = [(1, 1_000), (2, 4_000), (3, 16_000), (4, 64_000), (5, 256_000),
                 (6, 1_000_000), (7, 4_000_000), (8, 16_000_000), (9, 64_000_000),
                 (10, 256_000_000), (11, 1_000_000_000), (12, 4_000_000_000)]
        for code, mult in units:
            val = max(1, round(bps / mult))
            if val <= 0xFFFF:
                return bytes([code]) + val.to_bytes(2, "big")
        return bytes([12]) + (0xFFFF).to_bytes(2, "big")
    return _pack(dl_bps) + _pack(ul_bps)


def dec_session_ambr(data: bytes) -> Dict[str, int]:
    mult = {1: 1_000, 2: 4_000, 3: 16_000, 4: 64_000, 5: 256_000, 6: 1_000_000,
            7: 4_000_000, 8: 16_000_000, 9: 64_000_000, 10: 256_000_000,
            11: 1_000_000_000, 12: 4_000_000_000}
    if len(data) < 6:
        return {}
    dl = int.from_bytes(data[1:3], "big") * mult.get(data[0], 1_000)
    ul = int.from_bytes(data[4:6], "big") * mult.get(data[3], 1_000)
    return {"dl_bps": dl, "ul_bps": ul}


# ═════════════════════════════════════════════════════════════════════════════
# 범용 IE 워커
# ═════════════════════════════════════════════════════════════════════════════
# 전체옥텟 IEI → 형식. ("TLV", None)=1바이트 길이, ("TLVE", None)=2바이트 길이,
# ("TV", n)=IEI 뒤 n바이트 고정.
_IEI_FORMAT_5GMM: Dict[int, Tuple[str, Optional[int]]] = {
    0x10: ("TLV", None),   # 5GMM capability
    0x11: ("TLV", None),   # Rejected NSSAI
    0x12: ("TV", 1),       # PDU session identity 2
    0x15: ("TLV", None),   # Allowed NSSAI
    0x16: ("TV", 3),       # T3502
    0x17: ("TLV", None),   # S1 UE network capability
    0x18: ("TLV", None),   # UE usage setting
    0x19: ("TLV", None),   # Replayed S1 UE security capability
    0x1A: ("TLV", None),   # Requested WUS assistance
    0x20: ("TLV", None),   # Authentication parameter AUTN
    0x21: ("TV", 16),      # Authentication parameter RAND
    0x22: ("TLV", None),   # S-NSSAI
    0x23: ("TLV", None),   # EAP message (일부 메시지)
    0x24: ("TLV", None),   # Additional information
    0x25: ("TLV", None),   # DNN / Allowed PDU session status
    0x26: ("TLV", None),   # PDU session reactivation result
    0x28: ("TLV", None),   # 5GSM capability
    0x2A: ("TLV", None),
    0x2B: ("TLV", None),   # UE status
    0x2C: ("TLV", None),
    0x2D: ("TLV", None),   # Authentication response parameter (RES*)
    0x2E: ("TLV", None),   # UE security capability
    0x2F: ("TLV", None),   # Requested NSSAI
    0x30: ("TLV", None),
    0x31: ("TLV", None),   # Configured NSSAI
    0x33: ("TLV", None),
    0x34: ("TLV", None),
    0x35: ("TLV", None),   # Requested mapped NSSAI
    0x36: ("TLV", None),   # Additional 5G security information
    0x37: ("TLV", None),
    0x38: ("TLV", None),   # ABBA
    0x39: ("TLV", None),
    0x3A: ("TLV", None),
    0x3B: ("TLV", None),
    0x40: ("TLV", None),   # Uplink data status
    0x41: ("TLV", None),
    0x42: ("TLV", None),
    0x43: ("TLV", None),
    0x44: ("TLV", None),
    0x47: ("TLV", None),
    0x48: ("TLV", None),
    0x4A: ("TLV", None),   # Equivalent PLMNs
    0x50: ("TLV", None),   # PDU session status
    0x51: ("TLV", None),   # Requested DRX parameters
    0x52: ("TV", 6),       # Last visited registered TAI
    0x53: ("TLV", None),   # 5GS update type
    0x54: ("TLV", None),   # TAI list
    0x55: ("TV", 2),
    0x56: ("TV", 1),       # RQ timer value / GPRS timer
    0x57: ("TV", 1),       # Selected EPS NAS security algorithms
    0x58: ("TLV", None),
    0x59: ("TV", 1),       # 5GSM cause / Old PDU session ID
    0x5A: ("TV", 1),
    0x5B: ("TLV", None),
    0x5C: ("TLV", None),
    0x5D: ("TV", 1),       # Non-3GPP de-registration timer
    0x5E: ("TV", 1),       # T3512
    0x5F: ("TV", 1),       # T3502 (일부)
    0x60: ("TLV", None),
    0x61: ("TLV", None),
    0x62: ("TLV", None),
    0x66: ("TLV", None),
    0x67: ("TLV", None),   # UE radio capability ID
    0x68: ("TLV", None),
    0x69: ("TLV", None),
    0x6A: ("TLV", None),   # T3324
    0x6B: ("TLV", None),
    0x6C: ("TLV", None),
    0x6D: ("TLV", None),
    0x6E: ("TLV", None),   # Requested extended DRX
    0x6F: ("TLV", None),
    0x70: ("TLVE", None),  # EPS NAS message container
    0x71: ("TLVE", None),  # NAS message container
    0x72: ("TLVE", None),
    0x73: ("TLVE", None),  # SOR transparent container
    0x74: ("TLVE", None),  # LADN indication
    0x75: ("TLVE", None),  # Mapped EPS bearer contexts
    0x76: ("TLVE", None),  # Operator-defined access category
    0x77: ("TLVE", None),  # 5G-GUTI / IMEISV / Additional GUTI
    0x78: ("TLVE", None),  # EAP message
    0x79: ("TLVE", None),  # Authorized QoS flow descriptions
    0x7A: ("TLVE", None),
    0x7B: ("TLVE", None),  # Payload container / Extended PCO
    0x7C: ("TLVE", None),
    0x7E: ("TLVE", None),
    0x7F: ("TLVE", None),
}

# 5GSM 전용 차이(같은 IEI 라도 형식이 다른 경우)
_IEI_FORMAT_5GSM: Dict[int, Tuple[str, Optional[int]]] = dict(_IEI_FORMAT_5GMM)
_IEI_FORMAT_5GSM.update({
    0x29: ("TLV", None),   # PDU address
    0x2A: ("TLV", None),
    0x56: ("TV", 1),       # RQ timer value
    0x59: ("TV", 1),       # 5GSM cause
    0x7B: ("TLVE", None),  # Extended protocol configuration options
})


@dataclass
class ParsedIEs:
    """옵션 IE 파싱 결과."""
    #: 전체옥텟 IEI → 값(bytes). 같은 IEI 가 반복되면 마지막 값.
    tlv: Dict[int, bytes] = field(default_factory=dict)
    #: Type1 TV: 상위니블 IEI → 하위니블 값
    tv1: Dict[int, int] = field(default_factory=dict)
    #: 파싱 중 만난 순서(진단용)
    order: List[str] = field(default_factory=list)

    def get(self, iei: int, default: Optional[bytes] = None) -> Optional[bytes]:
        return self.tlv.get(iei, default)

    def half(self, iei: int, default: Optional[int] = None) -> Optional[int]:
        return self.tv1.get(iei, default)


def parse_optional_ies(data: bytes, fmt: Optional[Dict[int, Tuple[str, Optional[int]]]] = None,
                       strict: bool = False) -> ParsedIEs:
    """옵션 IE 영역을 관용적으로 순회한다.

    알 수 없는 IEI 를 만나면(strict=False) TLV 로 가정하고 계속 진행한다.
    실코어의 부가 IE 때문에 파싱이 통째로 실패하지 않도록 하는 것이 목적이다.
    """
    fmt = fmt or _IEI_FORMAT_5GMM
    out = ParsedIEs()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b & 0x80:                                  # Type 1 TV (반옥텟)
            out.tv1[(b >> 4) & 0x0F] = b & 0x0F
            out.order.append(f"TV1:{(b >> 4) & 0x0F:X}")
            i += 1
            continue
        kind, fixed = fmt.get(b, ("TLV", None))
        if kind == "TV":
            ln = fixed or 0
            if i + 1 + ln > n:
                if strict:
                    raise NasDecodeError(f"IEI 0x{b:02X} TV 길이 초과")
                break
            out.tlv[b] = data[i + 1:i + 1 + ln]
            out.order.append(f"TV:{b:02X}")
            i += 1 + ln
        elif kind == "TLVE":
            if i + 3 > n:
                break
            ln = int.from_bytes(data[i + 1:i + 3], "big")
            if i + 3 + ln > n:
                if strict:
                    raise NasDecodeError(f"IEI 0x{b:02X} TLV-E 길이 초과")
                break
            out.tlv[b] = data[i + 3:i + 3 + ln]
            out.order.append(f"TLVE:{b:02X}")
            i += 3 + ln
        else:                                          # TLV
            if i + 2 > n:
                break
            ln = data[i + 1]
            if i + 2 + ln > n:
                if strict:
                    raise NasDecodeError(f"IEI 0x{b:02X} TLV 길이 초과")
                break
            out.tlv[b] = data[i + 2:i + 2 + ln]
            out.order.append(f"TLV:{b:02X}")
            i += 2 + ln
    return out


def _tlv(iei: int, value: bytes) -> bytes:
    return bytes([iei, len(value)]) + value


def _tlve(iei: int, value: bytes) -> bytes:
    return bytes([iei]) + len(value).to_bytes(2, "big") + value


def _tv1(iei: int, value: int) -> bytes:
    return bytes([((iei & 0x0F) << 4) | (value & 0x0F)])


# ═════════════════════════════════════════════════════════════════════════════
# 5GMM 메시지 — 인코더 (단말 → 네트워크)
# ═════════════════════════════════════════════════════════════════════════════
def _5gmm_header(msg_type: int) -> bytes:
    return bytes([EPD_5GMM, SHT_PLAIN, msg_type])


def encode_registration_request(
    *, mobile_identity: bytes, reg_type: int = REG_TYPE_INITIAL, ngksi: int = 7,
    follow_on: bool = True,
    enc_algs: Optional[List[int]] = None, int_algs: Optional[List[int]] = None,
    requested_nssai: Optional[List[Tuple[int, Optional[str]]]] = None,
    mm_capability: bool = True,
    nas_message_container: Optional[bytes] = None,
    ue_status: Optional[bytes] = None,
) -> bytes:
    """Registration Request (0x41)."""
    out = bytearray(_5gmm_header(MT_REGISTRATION_REQUEST))
    # 5GS registration type(bit1-3) + FOR(bit4) | ngKSI(bit5-8)
    out.append(((ngksi & 0x0F) << 4) | (reg_type & 0x07) | (0x08 if follow_on else 0x00))
    # 5GS mobile identity : LV-E (2바이트 길이)
    out += len(mobile_identity).to_bytes(2, "big") + mobile_identity
    if mm_capability:
        out += _tlv(0x10, enc_5gmm_capability())
    if enc_algs is not None and int_algs is not None:
        out += _tlv(0x2E, enc_ue_security_capability(enc_algs, int_algs))
    if requested_nssai:
        out += _tlv(0x2F, enc_nssai(requested_nssai))
    if ue_status is not None:
        out += _tlv(0x2B, ue_status)
    if nas_message_container is not None:
        out += _tlve(0x71, nas_message_container)
    return bytes(out)


def encode_authentication_response(res_star: bytes) -> bytes:
    """Authentication Response (0x57)."""
    return _5gmm_header(MT_AUTHENTICATION_RESPONSE) + _tlv(0x2D, res_star)


def encode_authentication_failure(cause: int = 0x15, auts: Optional[bytes] = None) -> bytes:
    """Authentication Failure (0x59). cause 0x15 = synch failure → AUTS 동봉."""
    out = bytearray(_5gmm_header(MT_AUTHENTICATION_FAILURE))
    out.append(cause & 0xFF)
    if auts is not None:
        out += _tlv(0x30, auts)
    return bytes(out)


def encode_security_mode_complete(imeisv: Optional[bytes] = None,
                                  nas_message_container: Optional[bytes] = None) -> bytes:
    """Security Mode Complete (0x5E)."""
    out = bytearray(_5gmm_header(MT_SECURITY_MODE_COMPLETE))
    if imeisv is not None:
        out += _tlve(0x77, imeisv)
    if nas_message_container is not None:
        out += _tlve(0x71, nas_message_container)
    return bytes(out)


def encode_registration_complete(sor_container: Optional[bytes] = None) -> bytes:
    out = bytearray(_5gmm_header(MT_REGISTRATION_COMPLETE))
    if sor_container is not None:
        out += _tlve(0x73, sor_container)
    return bytes(out)


def encode_identity_response(mobile_identity: bytes) -> bytes:
    """Identity Response (0x5C) — 신원은 LV-E."""
    return (_5gmm_header(MT_IDENTITY_RESPONSE)
            + len(mobile_identity).to_bytes(2, "big") + mobile_identity)


def encode_ul_nas_transport(
    *, payload: bytes, pdu_session_id: int,
    payload_container_type: int = PAYLOAD_CONTAINER_N1_SM,
    request_type: Optional[int] = REQUEST_TYPE_INITIAL,
    sst: Optional[int] = None, sd: Optional[str] = None,
    dnn: Optional[str] = None, old_pdu_session_id: Optional[int] = None,
) -> bytes:
    """UL NAS Transport (0x67) — 5GSM 메시지를 실어 보낸다."""
    out = bytearray(_5gmm_header(MT_UL_NAS_TRANSPORT))
    out.append(payload_container_type & 0x0F)            # 상위니블 spare
    out += len(payload).to_bytes(2, "big") + payload     # Payload container LV-E
    out += bytes([0x12, pdu_session_id & 0xFF])          # PDU session ID (TV)
    if old_pdu_session_id is not None:
        out += bytes([0x59, old_pdu_session_id & 0xFF])
    if request_type is not None:
        out += _tv1(0x8, request_type)
    if sst is not None:
        out += _tlv(0x22, enc_s_nssai(sst, sd))
    if dnn is not None:
        out += _tlv(0x25, enc_dnn(dnn))
    return bytes(out)


def encode_deregistration_request(*, ngksi: int, mobile_identity: bytes,
                                  switch_off: bool = True,
                                  access_type: int = 0x01) -> bytes:
    """Deregistration Request (UE originating, 0x45)."""
    out = bytearray(_5gmm_header(MT_DEREGISTRATION_REQUEST_UE))
    # bit1-2 access type, bit3 re-registration required, bit4 switch off, bit5-8 ngKSI
    v = (access_type & 0x03) | (0x08 if switch_off else 0x00) | ((ngksi & 0x0F) << 4)
    out.append(v)
    out += len(mobile_identity).to_bytes(2, "big") + mobile_identity
    return bytes(out)


# ═════════════════════════════════════════════════════════════════════════════
# 5GSM 메시지 — 인코더
# ═════════════════════════════════════════════════════════════════════════════
def encode_pdu_session_establishment_request(
    *, pdu_session_id: int, pti: int, pdu_session_type: str = "ipv4",
    ssc_mode: int = 1, max_dr_per_ue: int = 0xFF, max_dr_per_flow: int = 0xFF,
    always_on: bool = False, epco: Optional[bytes] = None,
) -> bytes:
    """PDU Session Establishment Request (0xC1).

    Integrity protection maximum data rate 는 필수 2옥텟(0xFF=full data rate).
    """
    out = bytearray([EPD_5GSM, pdu_session_id & 0xFF, pti & 0xFF,
                     MT_PDU_SESSION_EST_REQUEST])
    out.append(max_dr_per_ue & 0xFF)
    out.append(max_dr_per_flow & 0xFF)
    pst = _PDU_TYPE_BY_NAME.get(str(pdu_session_type).lower(), PDU_TYPE_IPV4)
    out += _tv1(0x9, pst)                                # PDU session type
    out += _tv1(0xA, ssc_mode)                           # SSC mode
    if always_on:
        out += _tv1(0xB, 0x01)
    if epco is not None:
        out += _tlve(0x7B, epco)
    return bytes(out)


def encode_pdu_session_release_request(*, pdu_session_id: int, pti: int,
                                       cause: int = 0x24) -> bytes:
    out = bytearray([EPD_5GSM, pdu_session_id & 0xFF, pti & 0xFF,
                     MT_PDU_SESSION_REL_REQUEST])
    out += bytes([0x59, cause & 0xFF])
    return bytes(out)


# ═════════════════════════════════════════════════════════════════════════════
# 디코더
# ═════════════════════════════════════════════════════════════════════════════
@dataclass
class NasMessage:
    """디코딩된 NAS 메시지."""
    epd: int
    security_header_type: int
    message_type: int
    name: str
    #: 메시지별 필수 필드
    fields: Dict[str, Any] = field(default_factory=dict)
    #: 옵션 IE
    ies: ParsedIEs = field(default_factory=ParsedIEs)
    #: 보안 헤더가 있었다면 그 정보
    mac: Optional[bytes] = None
    sequence_number: Optional[int] = None
    #: 원본(평문) 바이트
    raw: bytes = b""

    def __repr__(self) -> str:  # pragma: no cover - 진단용
        return f"<NAS {self.name} fields={self.fields} ies={sorted(self.ies.tlv)}>"


def is_security_protected(data: bytes) -> bool:
    return len(data) >= 2 and data[0] == EPD_5GMM and data[1] != SHT_PLAIN


def decode(data: bytes) -> NasMessage:
    """평문 NAS 메시지(5GMM 또는 5GSM)를 디코딩."""
    if len(data) < 3:
        raise NasDecodeError(f"NAS 메시지가 너무 짧음: {len(data)}바이트")
    epd = data[0]
    if epd == EPD_5GSM:
        return _decode_5gsm(data)
    if epd != EPD_5GMM:
        raise NasDecodeError(f"알 수 없는 EPD 0x{epd:02X}")
    sht = data[1] & 0x0F
    if sht != SHT_PLAIN:
        raise NasDecodeError("보안보호된 메시지는 decode_secured() 로 처리하십시오")
    return _decode_5gmm(data)


def _decode_5gmm(data: bytes) -> NasMessage:
    mt = data[2]
    msg = NasMessage(epd=data[0], security_header_type=data[1] & 0x0F, message_type=mt,
                     name=MSG_NAMES.get(mt, f"5GMM-0x{mt:02X}"), raw=data)
    body = data[3:]
    f = msg.fields

    if mt == MT_AUTHENTICATION_REQUEST:
        # ngKSI(1/2)+spare(1/2), ABBA(LV), 그다음 옵션(RAND/AUTN/EAP)
        if not body:
            raise NasDecodeError("AuthenticationRequest 본문 없음")
        f["ngksi"] = body[0] & 0x0F
        abba_len = body[1] if len(body) > 1 else 0
        f["abba"] = body[2:2 + abba_len]
        msg.ies = parse_optional_ies(body[2 + abba_len:])
        f["rand"] = msg.ies.get(0x21)
        f["autn"] = msg.ies.get(0x20)

    elif mt == MT_SECURITY_MODE_COMMAND:
        # 선택된 NAS 보안 알고리즘(1), ngKSI(1/2)+spare, 재생 UE 보안능력(LV)
        if len(body) < 3:
            raise NasDecodeError("SecurityModeCommand 본문 부족")
        f["enc_alg"] = (body[0] >> 4) & 0x0F
        f["int_alg"] = body[0] & 0x0F
        f["ngksi"] = body[1] & 0x0F
        cap_len = body[2]
        f["replayed_ue_sec_cap"] = body[3:3 + cap_len]
        f["replayed_caps"] = dec_ue_security_capability(f["replayed_ue_sec_cap"])
        msg.ies = parse_optional_ies(body[3 + cap_len:])
        f["imeisv_requested"] = msg.ies.half(0xE) is not None
        f["abba"] = msg.ies.get(0x38)

    elif mt == MT_REGISTRATION_ACCEPT:
        # 5GS registration result (LV)
        if not body:
            raise NasDecodeError("RegistrationAccept 본문 없음")
        rr_len = body[0]
        rr = body[1:1 + rr_len]
        f["registration_result"] = rr[0] & 0x07 if rr else None
        f["sms_allowed"] = bool(rr[0] & 0x08) if rr else False
        msg.ies = parse_optional_ies(body[1 + rr_len:])
        if 0x77 in msg.ies.tlv:
            f["guti"] = msg.ies.tlv[0x77]
            f["guti_parsed"] = _parse_mobile_identity(msg.ies.tlv[0x77])
        if 0x15 in msg.ies.tlv:
            f["allowed_nssai"] = dec_nssai(msg.ies.tlv[0x15])
        if 0x54 in msg.ies.tlv:
            f["tai_list"] = msg.ies.tlv[0x54]

    elif mt == MT_REGISTRATION_REJECT:
        f["cause"] = body[0] if body else None
        msg.ies = parse_optional_ies(body[1:])

    elif mt == MT_DL_NAS_TRANSPORT:
        # payload container type(1/2)+spare, payload container(LV-E)
        if len(body) < 3:
            raise NasDecodeError("DLNASTransport 본문 부족")
        f["payload_container_type"] = body[0] & 0x0F
        plen = int.from_bytes(body[1:3], "big")
        f["payload"] = body[3:3 + plen]
        msg.ies = parse_optional_ies(body[3 + plen:])
        if 0x12 in msg.ies.tlv:
            f["pdu_session_id"] = msg.ies.tlv[0x12][0] if msg.ies.tlv[0x12] else None

    elif mt == MT_IDENTITY_REQUEST:
        f["identity_type"] = body[0] & 0x07 if body else None

    elif mt == MT_AUTHENTICATION_REJECT:
        msg.ies = parse_optional_ies(body)

    elif mt == MT_SERVICE_ACCEPT:
        msg.ies = parse_optional_ies(body)

    elif mt == MT_CONFIGURATION_UPDATE_COMMAND:
        msg.ies = parse_optional_ies(body)

    elif mt == MT_5GMM_STATUS:
        f["cause"] = body[0] if body else None

    elif mt == MT_REGISTRATION_REQUEST:
        # 스텁 코어(네트워크 역할)에서 필요
        f["ngksi"] = (body[0] >> 4) & 0x0F
        f["registration_type"] = body[0] & 0x07
        f["follow_on"] = bool(body[0] & 0x08)
        mlen = int.from_bytes(body[1:3], "big")
        f["mobile_identity"] = body[3:3 + mlen]
        f["identity"] = _parse_mobile_identity(f["mobile_identity"])
        msg.ies = parse_optional_ies(body[3 + mlen:])
        if 0x2E in msg.ies.tlv:
            f["ue_security_capability"] = dec_ue_security_capability(msg.ies.tlv[0x2E])
        if 0x2F in msg.ies.tlv:
            f["requested_nssai"] = dec_nssai(msg.ies.tlv[0x2F])

    elif mt == MT_AUTHENTICATION_RESPONSE:
        msg.ies = parse_optional_ies(body)
        f["res_star"] = msg.ies.get(0x2D)

    elif mt == MT_SECURITY_MODE_COMPLETE:
        msg.ies = parse_optional_ies(body)
        f["nas_message_container"] = msg.ies.get(0x71)

    elif mt == MT_UL_NAS_TRANSPORT:
        f["payload_container_type"] = body[0] & 0x0F
        plen = int.from_bytes(body[1:3], "big")
        f["payload"] = body[3:3 + plen]
        msg.ies = parse_optional_ies(body[3 + plen:])
        if 0x12 in msg.ies.tlv and msg.ies.tlv[0x12]:
            f["pdu_session_id"] = msg.ies.tlv[0x12][0]
        f["request_type"] = msg.ies.half(0x8)
        if 0x22 in msg.ies.tlv:
            f["s_nssai"] = dec_s_nssai(msg.ies.tlv[0x22])
        if 0x25 in msg.ies.tlv:
            f["dnn"] = dec_dnn(msg.ies.tlv[0x25])

    elif mt in (MT_REGISTRATION_COMPLETE, MT_DEREGISTRATION_ACCEPT_UE,
                MT_SERVICE_REQUEST, MT_IDENTITY_RESPONSE):
        msg.ies = parse_optional_ies(body)

    else:
        msg.ies = parse_optional_ies(body)
    return msg


def _decode_5gsm(data: bytes) -> NasMessage:
    if len(data) < 4:
        raise NasDecodeError("5GSM 메시지가 너무 짧음")
    mt = data[3]
    msg = NasMessage(epd=data[0], security_header_type=0, message_type=mt,
                     name=MSG_NAMES.get(mt, f"5GSM-0x{mt:02X}"), raw=data)
    f = msg.fields
    f["pdu_session_id"] = data[1]
    f["pti"] = data[2]
    body = data[4:]

    if mt == MT_PDU_SESSION_EST_ACCEPT:
        # 선택된 PDU 세션 타입(1/2) + SSC 모드(1/2), QoS 규칙(LV-E), Session-AMBR(LV)
        if len(body) < 3:
            raise NasDecodeError("PDUSessionEstablishmentAccept 본문 부족")
        f["pdu_session_type"] = body[0] & 0x0F
        f["ssc_mode"] = (body[0] >> 4) & 0x0F
        qos_len = int.from_bytes(body[1:3], "big")
        f["qos_rules"] = body[3:3 + qos_len]
        i = 3 + qos_len
        ambr_len = body[i] if i < len(body) else 0
        f["session_ambr_raw"] = body[i + 1:i + 1 + ambr_len]
        f["session_ambr"] = dec_session_ambr(f["session_ambr_raw"])
        msg.ies = parse_optional_ies(body[i + 1 + ambr_len:], _IEI_FORMAT_5GSM)
        # PDU 주소(0x29) — 단말 IP. 시험검증의 핵심 값.
        addr = msg.ies.get(0x29)
        if addr:
            f.update(_parse_pdu_address(addr))
        if 0x22 in msg.ies.tlv:
            f["s_nssai"] = dec_s_nssai(msg.ies.tlv[0x22])
        if 0x25 in msg.ies.tlv:
            f["dnn"] = dec_dnn(msg.ies.tlv[0x25])

    elif mt in (MT_PDU_SESSION_EST_REJECT, MT_PDU_SESSION_REL_COMMAND):
        f["cause"] = body[0] if body else None
        msg.ies = parse_optional_ies(body[1:], _IEI_FORMAT_5GSM)

    elif mt == MT_PDU_SESSION_EST_REQUEST:
        f["max_dr_per_ue"] = body[0] if body else None
        f["max_dr_per_flow"] = body[1] if len(body) > 1 else None
        msg.ies = parse_optional_ies(body[2:], _IEI_FORMAT_5GSM)
        f["pdu_session_type"] = msg.ies.half(0x9)
        f["ssc_mode"] = msg.ies.half(0xA)

    else:
        msg.ies = parse_optional_ies(body, _IEI_FORMAT_5GSM)
    return msg


def _parse_pdu_address(data: bytes) -> Dict[str, Any]:
    """PDU address IE (TS 24.501 §9.11.4.10) → UE IP."""
    out: Dict[str, Any] = {}
    if not data:
        return out
    ptype = data[0] & 0x07
    out["pdu_address_type"] = ptype
    body = data[1:]
    if ptype == PDU_TYPE_IPV4 and len(body) >= 4:
        out["ue_ipv4"] = ".".join(str(b) for b in body[0:4])
    elif ptype == PDU_TYPE_IPV6 and len(body) >= 8:
        # IPv6 인터페이스 식별자(하위 64비트)만 전달된다
        out["ue_ipv6_ifid"] = body[0:8].hex()
    elif ptype == PDU_TYPE_IPV4V6 and len(body) >= 12:
        out["ue_ipv6_ifid"] = body[0:8].hex()
        out["ue_ipv4"] = ".".join(str(b) for b in body[8:12])
    return out


def _parse_mobile_identity(data: bytes) -> Dict[str, Any]:
    """5GS mobile identity 파싱(SUCI/5G-GUTI 지원)."""
    if not data:
        return {}
    idtype = data[0] & 0x07
    out: Dict[str, Any] = {"type": idtype}
    if idtype == ID_TYPE_SUCI and len(data) >= 11:
        supi_format = (data[0] >> 4) & 0x07
        out["supi_format"] = supi_format
        mcc, mnc = plmn_decode(data[1:4])
        out["mcc"], out["mnc"] = mcc, mnc
        out["routing_indicator"] = bcd_decode_digits(data[4:6])
        out["protection_scheme"] = data[6] & 0x0F
        out["hn_key_id"] = data[7]
        if out["protection_scheme"] == 0:
            msin = bcd_decode_digits(data[8:])
            out["msin"] = msin
            out["imsi"] = f"{mcc}{mnc}{msin}"
    elif idtype == ID_TYPE_5G_GUTI and len(data) >= 11:
        mcc, mnc = plmn_decode(data[1:4])
        out["mcc"], out["mnc"] = mcc, mnc
        out["amf_region"] = data[4]
        v = int.from_bytes(data[5:7], "big")
        out["amf_set"] = (v >> 6) & 0x3FF
        out["amf_pointer"] = v & 0x3F
        out["tmsi"] = int.from_bytes(data[7:11], "big")
    return out


# ═════════════════════════════════════════════════════════════════════════════
# 보안 래핑 / 해제
# ═════════════════════════════════════════════════════════════════════════════
def encode_secured(plain: bytes, *, security_header_type: int,
                   enc_alg: int, int_alg: int, k_nas_enc: bytes, k_nas_int: bytes,
                   count: int, direction: int, bearer: int = 1) -> bytes:
    """평문 NAS 메시지를 보안 헤더로 감싼다.

    구조: EPD(1) | SHT(1) | MAC(4) | SQN(1) | [암호화된 평문]
    MAC 은 [SQN | 평문] 구간에 대해 계산한다(TS 24.501 §9.3).
    """
    from ..crypto import nas_encrypt, nas_mac
    sqn = count & 0xFF
    ciphered = plain
    if security_header_type in (SHT_INTEGRITY_CIPHERED, SHT_INTEGRITY_CIPHERED_NEW_CTX):
        ciphered = nas_encrypt(enc_alg, k_nas_enc, count, direction, plain, bearer)
    payload = bytes([sqn]) + ciphered
    mac = nas_mac(int_alg, k_nas_int, count, direction, payload, bearer)
    return bytes([EPD_5GMM, security_header_type & 0x0F]) + mac + payload


def decode_secured(data: bytes, *, enc_alg: int, int_alg: int,
                   k_nas_enc: bytes, k_nas_int: bytes,
                   count: int, direction: int, bearer: int = 1,
                   verify_mac: bool = True) -> Tuple[NasMessage, Dict[str, Any]]:
    """보안 NAS 메시지를 검증·복호하고 내부 평문을 디코딩.

    반환: (NasMessage, {"mac_ok":bool, "sqn":int, "security_header_type":int})
    """
    from ..crypto import nas_decrypt, nas_mac
    if len(data) < 7:
        raise NasDecodeError(f"보안 NAS 메시지가 너무 짧음: {len(data)}")
    if data[0] != EPD_5GMM:
        raise NasDecodeError(f"EPD 가 5GMM 이 아님: 0x{data[0]:02X}")
    sht = data[1] & 0x0F
    mac = data[2:6]
    sqn = data[6]
    body = data[7:]

    # COUNT 의 하위 8비트는 전송된 SQN 이어야 한다(오버플로는 상위에서 관리)
    count = (count & 0xFFFFFF00) | sqn
    expected = nas_mac(int_alg, k_nas_int, count, direction, bytes([sqn]) + body, bearer)
    mac_ok = (expected == mac)
    if verify_mac and not mac_ok and sht != SHT_PLAIN:
        raise NasDecodeError(
            f"NAS MAC 불일치 (받은 {mac.hex()}, 계산 {expected.hex()}, COUNT={count})")

    plain = body
    if sht in (SHT_INTEGRITY_CIPHERED, SHT_INTEGRITY_CIPHERED_NEW_CTX):
        plain = nas_decrypt(enc_alg, k_nas_enc, count, direction, body, bearer)

    msg = decode(plain)
    msg.mac = mac
    msg.sequence_number = sqn
    msg.security_header_type = sht
    return msg, {"mac_ok": mac_ok, "sqn": sqn, "security_header_type": sht, "count": count}


# ═════════════════════════════════════════════════════════════════════════════
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    from ..crypto import DIRECTION_DL, DIRECTION_UL, NEA0, NEA2, NIA2
    ok = True

    # (1) SUCI 인코딩 → 파싱 왕복
    imsi = "450050000000001"
    suci = enc_suci_imsi(imsi)
    parsed = _parse_mobile_identity(suci)
    if parsed.get("imsi") != imsi:
        ok = False
        print(f"  [NAS] SUCI 왕복 실패: {parsed}")
    elif verbose:
        print(f"  [NAS] SUCI 왕복 OK (MCC={parsed['mcc']} MNC={parsed['mnc']} "
              f"MSIN={parsed['msin']})")
    if suci[0] & 0x07 != ID_TYPE_SUCI:
        ok = False
        print("  [NAS] SUCI 신원유형 필드 오류")

    # (2) 5G-GUTI 왕복
    guti = enc_5g_guti("450", "05", 0x02, 0x101, 0x3F, 0xDEADBEEF)
    g = _parse_mobile_identity(guti)
    if not (g["type"] == ID_TYPE_5G_GUTI and g["amf_region"] == 0x02
            and g["amf_set"] == 0x101 and g["amf_pointer"] == 0x3F
            and g["tmsi"] == 0xDEADBEEF and g["mcc"] == "450" and g["mnc"] == "05"):
        ok = False
        print(f"  [NAS] 5G-GUTI 왕복 실패: {g}")
    elif verbose:
        print("  [NAS] 5G-GUTI 왕복 OK")

    # (3) UE 보안능력 비트 배치 (bit8=alg0)
    cap = enc_ue_security_capability([0, 2], [0, 2])
    if cap[0] != 0b10100000 or cap[1] != 0b10100000:
        ok = False
        print(f"  [NAS] 보안능력 비트 배치 오류: {cap.hex()}")
    if dec_ue_security_capability(cap) != {"enc": [0, 2], "int": [0, 2]}:
        ok = False
        print("  [NAS] 보안능력 디코딩 실패")
    elif verbose:
        print("  [NAS] UE 보안능력 인코딩/디코딩 OK")

    # (4) Registration Request 인코딩 → 디코딩
    rr = encode_registration_request(
        mobile_identity=suci, enc_algs=[0, 2], int_algs=[0, 2],
        requested_nssai=[(1, None), (2, "000001")])
    m = decode(rr)
    if m.message_type != MT_REGISTRATION_REQUEST:
        ok = False
        print("  [NAS] RegistrationRequest 메시지타입 오류")
    if m.fields.get("identity", {}).get("imsi") != imsi:
        ok = False
        print(f"  [NAS] RegistrationRequest IMSI 복원 실패: {m.fields.get('identity')}")
    if m.fields.get("ue_security_capability") != {"enc": [0, 2], "int": [0, 2]}:
        ok = False
        print("  [NAS] RegistrationRequest 보안능력 복원 실패")
    nssai = m.fields.get("requested_nssai")
    if not (nssai and nssai[0]["sst"] == 1 and nssai[1]["sst"] == 2
            and nssai[1]["sd"] == "000001"):
        ok = False
        print(f"  [NAS] RegistrationRequest NSSAI 복원 실패: {nssai}")
    elif verbose:
        print("  [NAS] RegistrationRequest 인코딩→디코딩 OK")
    if m.fields.get("ngksi") != 7 or m.fields.get("registration_type") != REG_TYPE_INITIAL:
        ok = False
        print(f"  [NAS] 등록유형/ngKSI 복원 실패: {m.fields}")

    # (5) Authentication Request 디코딩 (네트워크가 만든 형태를 직접 조립)
    rand = bytes(range(16))
    autn = bytes(range(16, 32))
    ar = bytearray([EPD_5GMM, 0x00, MT_AUTHENTICATION_REQUEST, 0x01, 0x02, 0x00, 0x00])
    ar += bytes([0x21]) + rand                        # RAND: TV(16)
    ar += bytes([0x20, 0x10]) + autn                  # AUTN: TLV
    am = decode(bytes(ar))
    if am.fields.get("rand") != rand or am.fields.get("autn") != autn:
        ok = False
        print(f"  [NAS] AuthenticationRequest RAND/AUTN 추출 실패: {am.fields}")
    elif verbose:
        print("  [NAS] AuthenticationRequest RAND/AUTN 추출 OK")
    if am.fields.get("abba") != b"\x00\x00":
        ok = False
        print(f"  [NAS] ABBA 추출 실패: {am.fields.get('abba')}")

    # (6) Authentication Response 왕복
    res_star = bytes(range(16))
    aresp = decode(encode_authentication_response(res_star))
    if aresp.fields.get("res_star") != res_star:
        ok = False
        print("  [NAS] AuthenticationResponse RES* 왕복 실패")

    # (7) Security Mode Command 디코딩
    replayed = enc_ue_security_capability([0, 2], [0, 2])
    smc = bytearray([EPD_5GMM, 0x00, MT_SECURITY_MODE_COMMAND])
    smc.append((NEA2 << 4) | NIA2)
    smc.append(0x00)                                  # ngKSI = 0
    smc.append(len(replayed))
    smc += replayed
    smc += bytes([0xE1])                              # IMEISV 요청 (Type1 TV, IEI=E)
    sm = decode(bytes(smc))
    if not (sm.fields["enc_alg"] == NEA2 and sm.fields["int_alg"] == NIA2
            and sm.fields["replayed_caps"] == {"enc": [0, 2], "int": [0, 2]}
            and sm.fields["imeisv_requested"]):
        ok = False
        print(f"  [NAS] SecurityModeCommand 파싱 실패: {sm.fields}")
    elif verbose:
        print("  [NAS] SecurityModeCommand 파싱(알고리즘·재생능력·IMEISV) OK")

    # (8) PDU Session Establishment Request 왕복
    pser = encode_pdu_session_establishment_request(
        pdu_session_id=5, pti=1, pdu_session_type="ipv4v6", ssc_mode=1)
    pm = decode(pser)
    if not (pm.fields["pdu_session_id"] == 5 and pm.fields["pti"] == 1
            and pm.fields["pdu_session_type"] == PDU_TYPE_IPV4V6
            and pm.fields["ssc_mode"] == 1):
        ok = False
        print(f"  [NAS] PDUSessionEstablishmentRequest 왕복 실패: {pm.fields}")
    elif verbose:
        print("  [NAS] PDUSessionEstablishmentRequest 왕복 OK")

    # (9) UL NAS Transport 왕복 (5GSM 을 감싸서)
    ul = encode_ul_nas_transport(payload=pser, pdu_session_id=5, sst=1, sd="000001",
                                 dnn="internet")
    um = decode(ul)
    if um.fields.get("payload") != pser:
        ok = False
        print("  [NAS] ULNASTransport 페이로드 왕복 실패")
    if um.fields.get("dnn") != "internet":
        ok = False
        print(f"  [NAS] DNN 왕복 실패: {um.fields.get('dnn')}")
    if um.fields.get("s_nssai", {}).get("sd") != "000001":
        ok = False
        print(f"  [NAS] S-NSSAI 왕복 실패: {um.fields.get('s_nssai')}")
    if um.fields.get("request_type") != REQUEST_TYPE_INITIAL:
        ok = False
        print(f"  [NAS] request_type 왕복 실패: {um.fields.get('request_type')}")
    elif verbose:
        print("  [NAS] ULNASTransport(페이로드/DNN/S-NSSAI/요청유형) 왕복 OK")

    # (10) PDU Session Establishment Accept 조립 → UE IP 추출
    acc = bytearray([EPD_5GSM, 5, 0, MT_PDU_SESSION_EST_ACCEPT])
    acc.append((1 << 4) | PDU_TYPE_IPV4)              # SSC mode 1, IPv4
    qos = bytes([0x01, 0x20, 0x01, 0x00])             # 임의 QoS 규칙
    acc += len(qos).to_bytes(2, "big") + qos
    ambr = enc_session_ambr(100_000_000, 50_000_000)
    acc += bytes([len(ambr)]) + ambr
    acc += bytes([0x29, 0x05, PDU_TYPE_IPV4, 10, 45, 0, 7])   # PDU address
    acc += bytes([0x25, 0x09, 0x08]) + b"internet"
    ac = decode(bytes(acc))
    if ac.fields.get("ue_ipv4") != "10.45.0.7":
        ok = False
        print(f"  [NAS] PDU 주소(UE IP) 추출 실패: {ac.fields}")
    elif verbose:
        print(f"  [NAS] PDUSessionEstablishmentAccept → UE IP {ac.fields['ue_ipv4']}, "
              f"AMBR {ac.fields['session_ambr']} OK")
    if ac.fields.get("session_ambr", {}).get("dl_bps") != 100_000_000:
        ok = False
        print(f"  [NAS] Session-AMBR 왕복 실패: {ac.fields.get('session_ambr')}")
    if ac.fields.get("dnn") != "internet":
        ok = False
        print("  [NAS] Accept DNN 추출 실패")

    # (11) 보안 래핑 왕복 (암호화 + 무결성)
    kenc = bytes(range(16))
    kint = bytes(range(16, 32))
    inner = encode_registration_complete()
    wrapped = encode_secured(inner, security_header_type=SHT_INTEGRITY_CIPHERED,
                             enc_alg=NEA2, int_alg=NIA2, k_nas_enc=kenc, k_nas_int=kint,
                             count=3, direction=DIRECTION_UL)
    if not is_security_protected(wrapped):
        ok = False
        print("  [NAS] 보안헤더 감지 실패")
    back, info = decode_secured(wrapped, enc_alg=NEA2, int_alg=NIA2, k_nas_enc=kenc,
                                k_nas_int=kint, count=3, direction=DIRECTION_UL)
    if not (info["mac_ok"] and back.message_type == MT_REGISTRATION_COMPLETE
            and info["sqn"] == 3):
        ok = False
        print(f"  [NAS] 보안 래핑 왕복 실패: {info}")
    elif verbose:
        print("  [NAS] 보안 래핑(암호화+무결성) 왕복 OK")

    # (12) 변조 감지
    bad = bytearray(wrapped); bad[-1] ^= 0xFF
    try:
        decode_secured(bytes(bad), enc_alg=NEA2, int_alg=NIA2, k_nas_enc=kenc,
                       k_nas_int=kint, count=3, direction=DIRECTION_UL)
        ok = False
        print("  [NAS] 변조된 보안 메시지를 수락함")
    except NasDecodeError:
        if verbose:
            print("  [NAS] 변조 감지 OK")

    # (13) 무결성만 적용(암호화 없음)
    w2 = encode_secured(inner, security_header_type=SHT_INTEGRITY,
                        enc_alg=NEA0, int_alg=NIA2, k_nas_enc=b"", k_nas_int=kint,
                        count=1, direction=DIRECTION_DL)
    b2, i2 = decode_secured(w2, enc_alg=NEA0, int_alg=NIA2, k_nas_enc=b"",
                            k_nas_int=kint, count=1, direction=DIRECTION_DL)
    if not (i2["mac_ok"] and b2.message_type == MT_REGISTRATION_COMPLETE):
        ok = False
        print("  [NAS] 무결성 전용 래핑 왕복 실패")

    # (14) IE 워커: Type1 TV 와 전체옥텟 IEI 혼재
    mixed = bytes([0x81]) + bytes([0x25, 0x03, 0x02, ord("h"), ord("i")]) + bytes([0xA1])
    p = parse_optional_ies(mixed)
    if p.half(0x8) != 1 or p.half(0xA) != 1 or p.get(0x25) != bytes([0x02, ord("h"), ord("i")]):
        ok = False
        print(f"  [NAS] IE 워커 혼재 파싱 실패: {p}")
    elif verbose:
        print("  [NAS] IE 워커(Type1 TV + TLV 혼재) OK")

    # (15) 알 수 없는 IEI 를 만나도 나머지를 계속 파싱해야 함
    tolerant = bytes([0x3F, 0x02, 0xAA, 0xBB]) + bytes([0x25, 0x02, 0x01, ord("x")])
    p2 = parse_optional_ies(tolerant)
    if p2.get(0x25) != bytes([0x01, ord("x")]):
        ok = False
        print("  [NAS] 미지 IEI 이후 파싱 중단됨")
    elif verbose:
        print("  [NAS] 미지 IEI 관용 처리 OK")

    # (16) DNN 다중 라벨
    if dec_dnn(enc_dnn("web.apn.example")) != "web.apn.example":
        ok = False
        print("  [NAS] 다중 라벨 DNN 왕복 실패")

    # (17) Session-AMBR 단위 선택이 근사적으로 맞아야 함
    for bps in (1_000_000, 100_000_000, 1_000_000_000):
        got = dec_session_ambr(enc_session_ambr(bps, bps)).get("dl_bps", 0)
        if abs(got - bps) > bps * 0.02:
            ok = False
            print(f"  [NAS] Session-AMBR 왕복 오차 큼: {bps} → {got}")
    return ok


if __name__ == "__main__":
    print("NAS selftest:", "PASS" if selftest(verbose=True) else "FAIL")
