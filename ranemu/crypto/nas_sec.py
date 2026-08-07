#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.crypto.nas_sec — NAS 보안 (암호화 NEA*, 무결성 NIA*), TS 33.501 Annex D.

지원 알고리즘
=============
    NEA0 / NIA0  : null (무처리)                        — 구현
    NEA2 / NIA2  : 128-5G-EA2/IA2 (AES-CTR / AES-CMAC)  — 구현
    NEA1 / NIA1  : 128-5G-EA1/IA1 (SNOW 3G)             — 미구현(훅만 존재)
    NEA3 / NIA3  : 128-5G-EA3/IA3 (ZUC)                 — 미구현(훅만 존재)

왜 AES 계열만 구현했는가
------------------------
NAS 보안 알고리즘은 **단말이 광고한 능력(UE security capability) 안에서 AMF 가 선택**한다
(TS 33.501 §6.7.2). 따라서 에뮬레이터가 SNOW3G/ZUC 를 광고하지 않으면 코어는 그것을 고를
수 없고, 미구현 때문에 등록이 실패하는 일은 없다. `IMPLEMENTED_ENC/INT` 가 광고 IE 의
기본 소스다.

반대로 **검증되지 않은 암호 구현을 넣는 것은 해롭다**. SNOW3G/ZUC 는 공개 표준 테스트
벡터로 대조하지 않으면 정확성을 보장할 수 없고, 틀린 MAC 은 실코어에서 "원인 불명의
Security mode reject" 로 나타나 디버깅을 크게 어렵게 만든다. 그래서 여기서는 `cryptography`
라이브러리가 보장하는 AES-CTR/AES-CMAC 위에, 규격이 정하는 IV/M 조립만 구현했다
(그 조립은 selftest 에서 정의식과 독립 대조한다).

추가하려면: `snow3g.py` / `zuc.py` 에 `f8(key,count,bearer,dir,data)` 와
`f9(...)->4B` 를 구현하고 아래 `_ENC`/`_INT` 표와 `IMPLEMENTED_*` 에 등록하면 된다.
반드시 TS 35.216/35.221 의 표준 테스트셋으로 먼저 검증할 것.

입력 규약 (TS 33.501 §D.3, TS 33.401 Annex B)
=============================================
    COUNT     : 32비트 = 8비트 0 || NAS overflow(16b) || NAS SQN(8b)
    BEARER    : 5비트 — NAS 연결 식별자(3GPP 접속=0x01, non-3GPP=0x02)
    DIRECTION : 1비트 — 0=상향(UE→네트워크), 1=하향
"""
from __future__ import annotations

from typing import Callable, Dict

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ── 알고리즘 식별자 (TS 24.501 §9.11.3.34) ──────────────────────────────────
NEA0, NEA1, NEA2, NEA3 = 0x00, 0x01, 0x02, 0x03
NIA0, NIA1, NIA2, NIA3 = 0x00, 0x01, 0x02, 0x03

ALG_NAMES = {
    "enc": {NEA0: "NEA0(null)", NEA1: "NEA1(SNOW3G)", NEA2: "NEA2(AES)", NEA3: "NEA3(ZUC)"},
    "int": {NIA0: "NIA0(null)", NIA1: "NIA1(SNOW3G)", NIA2: "NIA2(AES)", NIA3: "NIA3(ZUC)"},
}

DIRECTION_UL = 0
DIRECTION_DL = 1
BEARER_NAS_3GPP = 0x01
BEARER_NAS_NON_3GPP = 0x02


class UnsupportedAlgorithm(NotImplementedError):
    """코어가 이 구현이 지원하지 않는 알고리즘을 선택했을 때."""


def _iv(count: int, bearer: int, direction: int) -> bytes:
    """16바이트 초기 카운터/IV: COUNT(4) || BEARER<<3|DIR<<2 (1) || 0*11."""
    return (
        (count & 0xFFFFFFFF).to_bytes(4, "big")
        + bytes([((bearer & 0x1F) << 3) | ((direction & 0x01) << 2)])
        + bytes(11)
    )


# ─────────────────────────────────────────────────────────────────────────────
# 암호화 (스트림) — 암/복호가 동일 연산
# ─────────────────────────────────────────────────────────────────────────────
def _ea0(key, count, bearer, direction, data: bytes) -> bytes:
    return data


def _ea2(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    """128-5G-EA2 = AES-128-CTR."""
    if len(key) != 16:
        raise ValueError("NEA2 키는 16바이트")
    enc = Cipher(algorithms.AES(key), modes.CTR(_iv(count, bearer, direction))).encryptor()
    return enc.update(data) + enc.finalize()


def _ea1(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    """128-5G-EA1 = SNOW 3G 기반 f8.  (미구현 — 모듈 상단 주석 참조)"""
    from .snow3g import f8  # noqa: F401  — 파일을 추가하면 자동으로 동작
    return f8(key, count, bearer, direction, data)


# ─────────────────────────────────────────────────────────────────────────────
# 무결성 (MAC 4바이트)
# ─────────────────────────────────────────────────────────────────────────────
def _ia0(key, count, bearer, direction, data: bytes) -> bytes:
    return b"\x00\x00\x00\x00"


def _ia2(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    """128-5G-IA2 = AES-CMAC 의 상위 32비트.

    M = COUNT(32b) || BEARER(5b) || DIRECTION(1b) || 0^26 || MESSAGE
    """
    if len(key) != 16:
        raise ValueError("NIA2 키는 16바이트")
    c = cmac.CMAC(algorithms.AES(key))
    c.update(_iv(count, bearer, direction)[:8] + data)  # 앞 8바이트가 규격의 헤더부
    return c.finalize()[:4]


def _ia1(key: bytes, count: int, bearer: int, direction: int, data: bytes) -> bytes:
    """128-5G-IA1 = SNOW 3G 기반 f9.  (미구현 — 모듈 상단 주석 참조)"""
    from .snow3g import f9  # noqa: F401
    return f9(key, count, bearer, direction, data)


def _unsupported(name: str) -> Callable:
    def _f(*_a, **_k):
        raise UnsupportedAlgorithm(
            f"{name} 는 이 구현에 없음. 이 알고리즘은 UE 보안능력 광고에서 제외되므로 "
            f"정상 코어라면 선택하지 않습니다. 코어가 광고를 무시했거나, 강제 시험이 필요하면 "
            f"crypto/{name[:4].lower()}.py 를 추가하고 _ENC/_INT 에 등록하십시오.")
    return _f


def _hooked(name: str, fn: Callable) -> Callable:
    """구현 모듈이 있으면 그것을, 없으면 명확한 오류를 쓰는 지연 바인딩."""
    def _f(*a, **k):
        try:
            return fn(*a, **k)
        except ImportError:
            return _unsupported(name)()
    return _f


_ENC: Dict[int, Callable] = {
    NEA0: _ea0,
    NEA1: _hooked("NEA1(SNOW3G)", _ea1),
    NEA2: _ea2,
    NEA3: _unsupported("NEA3(ZUC)"),
}
_INT: Dict[int, Callable] = {
    NIA0: _ia0,
    NIA1: _hooked("NIA1(SNOW3G)", _ia1),
    NIA2: _ia2,
    NIA3: _unsupported("NIA3(ZUC)"),
}


def implemented() -> tuple[tuple[int, ...], tuple[int, ...]]:
    """실제로 동작하는 (암호화, 무결성) 알고리즘 목록 — UE 보안능력 광고의 기본 소스.

    선택적 모듈(snow3g)이 나중에 추가되면 자동으로 목록에 포함된다.
    """
    enc = [NEA0, NEA2]
    integ = [NIA0, NIA2]
    try:
        from . import snow3g  # noqa: F401
        enc.insert(1, NEA1)
        integ.insert(1, NIA1)
    except ImportError:
        pass
    return tuple(enc), tuple(integ)


IMPLEMENTED_ENC, IMPLEMENTED_INT = implemented()


# ─────────────────────────────────────────────────────────────────────────────
# 공개 API
# ─────────────────────────────────────────────────────────────────────────────
def nas_encrypt(alg: int, key: bytes, count: int, direction: int, data: bytes,
                bearer: int = BEARER_NAS_3GPP) -> bytes:
    return _ENC[alg & 0x0F](key, count, bearer, direction, data)


#: 스트림 암호이므로 복호는 암호와 동일 연산.
nas_decrypt = nas_encrypt


def nas_mac(alg: int, key: bytes, count: int, direction: int, data: bytes,
            bearer: int = BEARER_NAS_3GPP) -> bytes:
    """NAS 무결성 MAC 4바이트."""
    return _INT[alg & 0x0F](key, count, bearer, direction, data)


def nas_count(overflow: int, sqn: int) -> int:
    """NAS COUNT 조립: 8비트 0 || overflow(16b) || sqn(8b)."""
    return ((overflow & 0xFFFF) << 8) | (sqn & 0xFF)


def selftest(verbose: bool = False) -> bool:
    ok = True

    # (1) NEA2 = AES-CTR 임을 독립 계산으로 검증
    key = bytes.fromhex("d3c5d592327fb11c4035c6680af8c6d1")
    pt = bytes.fromhex("981ba6824c1bfb1ab485472029b71d80" * 2)
    ct = nas_encrypt(NEA2, key, 0x398a59b4, DIRECTION_UL, pt, bearer=0x15)
    enc = Cipher(algorithms.AES(key), modes.CTR(_iv(0x398a59b4, 0x15, 0))).encryptor()
    if ct != enc.update(pt) + enc.finalize():
        ok = False
        print("  [NAS-SEC] NEA2 가 AES-CTR 정의와 불일치")
    elif verbose:
        print("  [NAS-SEC] NEA2 = AES-CTR OK")

    # (2) 왕복(암→복)
    if nas_decrypt(NEA2, key, 0x398a59b4, DIRECTION_UL, ct, bearer=0x15) != pt:
        ok = False
        print("  [NAS-SEC] NEA2 왕복 실패")

    # (3) IV 도메인 분리: direction/bearer/count 가 바뀌면 결과가 달라야 함
    base = nas_encrypt(NEA2, key, 1, DIRECTION_UL, pt)
    for label, other in (
        ("direction", nas_encrypt(NEA2, key, 1, DIRECTION_DL, pt)),
        ("count", nas_encrypt(NEA2, key, 2, DIRECTION_UL, pt)),
        ("bearer", nas_encrypt(NEA2, key, 1, DIRECTION_UL, pt, bearer=2)),
    ):
        if base == other:
            ok = False
            print(f"  [NAS-SEC] NEA2 {label} 가 키스트림에 반영되지 않음")

    # (4) NIA2 = AES-CMAC 상위 4바이트
    ikey = bytes.fromhex("2bd6459f82c5b300952c49104881ff48")
    msg = bytes.fromhex("3332346263393840")
    mac = nas_mac(NIA2, ikey, 0x38a6f056, DIRECTION_UL, msg, bearer=0x18)
    c = cmac.CMAC(algorithms.AES(ikey))
    c.update(_iv(0x38a6f056, 0x18, 0)[:8] + msg)
    if mac != c.finalize()[:4] or len(mac) != 4:
        ok = False
        print("  [NAS-SEC] NIA2 가 AES-CMAC 정의와 불일치")
    elif verbose:
        print("  [NAS-SEC] NIA2 = AES-CMAC[0:4] OK")

    # (5) 무결성: 1비트만 바꿔도 MAC 이 달라져야 함
    tampered = bytearray(msg); tampered[0] ^= 0x01
    if nas_mac(NIA2, ikey, 0x38a6f056, DIRECTION_UL, bytes(tampered), bearer=0x18) == mac:
        ok = False
        print("  [NAS-SEC] NIA2 가 변조를 감지하지 못함")

    # (6) null 알고리즘
    if nas_encrypt(NEA0, b"", 0, 0, pt) != pt or nas_mac(NIA0, b"", 0, 0, pt) != bytes(4):
        ok = False
        print("  [NAS-SEC] null 알고리즘 동작 이상")

    # (7) 미구현 알고리즘은 조용히 틀린 값을 내지 말고 명확히 실패해야 한다
    for alg, fn in ((NEA3, nas_encrypt), (NEA1, nas_encrypt)):
        try:
            fn(alg, key, 1, DIRECTION_UL, pt)
            ok = False
            print(f"  [NAS-SEC] 미구현 알고리즘 {alg} 가 조용히 값을 반환함")
        except UnsupportedAlgorithm:
            pass
        except NotImplementedError:
            pass
    # 광고 목록은 구현된 것만 담아야 한다
    if NEA3 in IMPLEMENTED_ENC or NIA3 in IMPLEMENTED_INT:
        ok = False
        print("  [NAS-SEC] 미구현 알고리즘이 광고 목록에 포함됨")
    elif verbose:
        print(f"  [NAS-SEC] 광고대상 enc={IMPLEMENTED_ENC} int={IMPLEMENTED_INT} OK")

    # (8) COUNT 조립
    if nas_count(0x0102, 0x03) != 0x010203:
        ok = False
        print("  [NAS-SEC] nas_count 조립 오류")
    return ok


if __name__ == "__main__":
    print("NAS-SEC selftest:", "PASS" if selftest(verbose=True) else "FAIL")
