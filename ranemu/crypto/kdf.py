#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.crypto.kdf — 5G 키계층 유도 (3GPP TS 33.501 Annex A, TS 33.220 Annex B).

일반형(TS 33.220 B.2):
    derived = HMAC-SHA256( Key, S )
    S = FC || P0 || L0 || P1 || L1 || ...   (Ln 은 Pn 길이의 2바이트 빅엔디언)

5G 키계층:
    K(SIM) ──MILENAGE──► CK,IK
                          │  A.2 (FC=0x6A)
                          ▼
                       K_AUSF
                          │  A.6 (FC=0x6C)
                          ▼
                       K_SEAF
                          │  A.7 (FC=0x6D, P0=SUPI, P1=ABBA)
                          ▼
                       K_AMF ──┬── A.8 (FC=0x69) ──► K_NASenc / K_NASint
                               └── A.9 (FC=0x6E) ──► K_gNB ──► K_RRCenc/int, K_UPenc/int

RES* (A.4, FC=0x6B) 는 단말이 만들고, XRES* 는 네트워크가 같은 식으로 만든다(동일 함수).
"""
from __future__ import annotations

import hmac
from hashlib import sha256

# ── FC 상수 (TS 33.501 Annex A) ──────────────────────────────────────────────
FC_KAUSF = 0x6A          # A.2  CK||IK   → K_AUSF
FC_RES_STAR = 0x6B       # A.4  CK||IK   → RES*/XRES*
FC_KSEAF = 0x6C          # A.6  K_AUSF   → K_SEAF
FC_KAMF = 0x6D           # A.7  K_SEAF   → K_AMF
FC_ALG_KEY = 0x69        # A.8  K_AMF    → NAS 알고리즘 키
FC_KGNB = 0x6E           # A.9  K_AMF    → K_gNB
FC_NH = 0x6F             # A.10 수평/수직 키유도(NH)

# 알고리즘 타입 구분자 (TS 33.501 Table A.8-1)
ALG_TYPE_NAS_ENC = 0x01
ALG_TYPE_NAS_INT = 0x02
ALG_TYPE_RRC_ENC = 0x03
ALG_TYPE_RRC_INT = 0x04
ALG_TYPE_UP_ENC = 0x05
ALG_TYPE_UP_INT = 0x06

ACCESS_TYPE_3GPP = 0x01
ACCESS_TYPE_NON_3GPP = 0x02


def kdf(key: bytes, fc: int, *params: bytes) -> bytes:
    """TS 33.220 B.2.0 일반 KDF → 32바이트(256비트)."""
    s = bytearray([fc & 0xFF])
    for p in params:
        if isinstance(p, str):
            p = p.encode()
        if len(p) > 0xFFFF:
            raise ValueError("KDF 파라미터가 65535 바이트를 초과")
        s += p
        s += len(p).to_bytes(2, "big")
    return hmac.new(key, bytes(s), sha256).digest()


# ─────────────────────────────────────────────────────────────────────────────
# 5G-AKA 키 유도
# ─────────────────────────────────────────────────────────────────────────────
def k_ausf(ck: bytes, ik: bytes, snn: str, sqn_xor_ak: bytes) -> bytes:
    """A.2 — K_AUSF (32B). sqn_xor_ak 는 AUTN 의 앞 6바이트."""
    if len(sqn_xor_ak) != 6:
        raise ValueError("SQN XOR AK 는 6바이트")
    return kdf(ck + ik, FC_KAUSF, snn.encode(), sqn_xor_ak)


def k_seaf(kausf: bytes, snn: str) -> bytes:
    """A.6 — K_SEAF (32B)."""
    return kdf(kausf, FC_KSEAF, snn.encode())


def k_amf(kseaf: bytes, supi: str, abba: bytes = b"\x00\x00") -> bytes:
    """A.7 — K_AMF (32B). SUPI 는 IMSI 숫자문자열의 ASCII 바이트.

    주의: SUPI 는 'imsi-' 접두 없이 숫자만 쓴다(TS 33.501 A.7 각주).
    """
    supi_digits = "".join(ch for ch in str(supi) if ch.isdigit())
    return kdf(kseaf, FC_KAMF, supi_digits.encode("ascii"), abba)


def res_star(ck: bytes, ik: bytes, snn: str, rand: bytes, res: bytes) -> bytes:
    """A.4 — RES* (16B). 출력 256비트 중 하위 128비트."""
    return kdf(ck + ik, FC_RES_STAR, snn.encode(), rand, res)[16:]


#: 네트워크측 XRES* 는 동일 함수(입력이 XRES 일 뿐).
xres_star = res_star


def nas_keys(kamf: bytes, enc_alg: int, int_alg: int) -> tuple[bytes, bytes]:
    """A.8 — (K_NASenc, K_NASint), 각 16B. 출력 256비트 중 하위 128비트."""
    ke = kdf(kamf, FC_ALG_KEY, bytes([ALG_TYPE_NAS_ENC]), bytes([enc_alg & 0x0F]))[16:]
    ki = kdf(kamf, FC_ALG_KEY, bytes([ALG_TYPE_NAS_INT]), bytes([int_alg & 0x0F]))[16:]
    return ke, ki


def k_gnb(kamf: bytes, ul_nas_count: int, access_type: int = ACCESS_TYPE_3GPP) -> bytes:
    """A.9 — K_gNB (32B). ul_nas_count 는 32비트 빅엔디언."""
    return kdf(kamf, FC_KGNB,
               (ul_nas_count & 0xFFFFFFFF).to_bytes(4, "big"),
               bytes([access_type]))


def as_keys(kgnb: bytes, rrc_enc: int, rrc_int: int,
            up_enc: int, up_int: int) -> dict[str, bytes]:
    """A.8 — AS 계층 키(K_RRCenc/int, K_UPenc/int), 각 16B.

    RAN 에뮬레이터는 실제 무선 암호화를 하지 않지만(RF 구간 없음), 키 유도 경로를
    완전히 갖춰 두면 후속 확장(F1/E1, RRC 재현)에 그대로 쓸 수 있다.
    """
    def _k(t: int, a: int) -> bytes:
        return kdf(kgnb, FC_ALG_KEY, bytes([t]), bytes([a & 0x0F]))[16:]
    return {
        "k_rrc_enc": _k(ALG_TYPE_RRC_ENC, rrc_enc),
        "k_rrc_int": _k(ALG_TYPE_RRC_INT, rrc_int),
        "k_up_enc": _k(ALG_TYPE_UP_ENC, up_enc),
        "k_up_int": _k(ALG_TYPE_UP_INT, up_int),
    }


def selftest(verbose: bool = False) -> bool:
    """KDF 계층의 구조적 성질을 검증(결정성/길이/도메인 분리).

    참고: 5G KDF 는 공개 표준 테스트벡터가 희소하다. 여기서는
      (1) HMAC-SHA256 기반 KDF 의 알려진 값,
      (2) 길이·결정성·파라미터 민감도(도메인 분리)
    를 검증하고, 실제 상호운용은 스텁코어(양측 동일 구현) 및 실코어 연동으로 확인한다.
    """
    ok = True

    # (1) S 구성 규칙 검증: FC||P0||L0 형태를 직접 계산해 대조
    key = bytes(range(32))
    expect = hmac.new(key, bytes([0x6C]) + b"abc" + (3).to_bytes(2, "big"), sha256).digest()
    if kdf(key, 0x6C, b"abc") != expect:
        ok = False
        print("  [KDF] S 구성 규칙 불일치")
    elif verbose:
        print("  [KDF] S 구성(FC||P||L) OK")

    # (2) 길이
    ck = bytes(16); ik = bytes(16)
    snn = "5G:mnc001.mcc001.3gppnetwork.org"
    kausf = k_ausf(ck, ik, snn, bytes(6))
    kseaf = k_seaf(kausf, snn)
    kamf = k_amf(kseaf, "001010000000001")
    ke, ki = nas_keys(kamf, 2, 2)
    kg = k_gnb(kamf, 1)
    rs = res_star(ck, ik, snn, bytes(16), bytes(8))
    for name, val, n in (("K_AUSF", kausf, 32), ("K_SEAF", kseaf, 32), ("K_AMF", kamf, 32),
                         ("K_NASenc", ke, 16), ("K_NASint", ki, 16), ("K_gNB", kg, 32),
                         ("RES*", rs, 16)):
        if len(val) != n:
            ok = False
            print(f"  [KDF] {name} 길이 {len(val)} != {n}")
        elif verbose:
            print(f"  [KDF] {name} 길이 {n} OK")

    # (3) 도메인 분리: enc 키와 int 키는 달라야 하고, 알고리즘 ID 가 다르면 키도 달라야 함
    if ke == ki:
        ok = False
        print("  [KDF] NAS enc/int 키가 동일 — 도메인 분리 실패")
    if nas_keys(kamf, 1, 2)[0] == ke:
        ok = False
        print("  [KDF] 알고리즘 ID 변경이 키에 반영되지 않음")
    if k_gnb(kamf, 1) == k_gnb(kamf, 2):
        ok = False
        print("  [KDF] UL NAS COUNT 가 K_gNB 에 반영되지 않음")
    if k_amf(kseaf, "001010000000001") != k_amf(kseaf, "imsi-001010000000001"):
        ok = False
        print("  [KDF] SUPI 정규화(숫자만) 실패")

    # (4) 결정성
    if k_ausf(ck, ik, snn, bytes(6)) != kausf:
        ok = False
        print("  [KDF] 비결정적 출력")
    return ok


if __name__ == "__main__":
    print("KDF selftest:", "PASS" if selftest(verbose=True) else "FAIL")
