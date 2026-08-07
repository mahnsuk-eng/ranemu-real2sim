"""ranemu.crypto — 5G-AKA 인증(MILENAGE), 키유도(TS 33.501), NAS 보안 알고리즘.

주의: 하위 모듈 이름(`kdf`)과 함수 이름이 겹치지 않도록, 일반 KDF 함수는
`ranemu.crypto.kdf.kdf` 로만 접근한다(패키지 레벨에서 재수출하지 않음).
"""
from . import kdf as kdf_mod          # noqa: F401  (모듈 접근 보장)
from . import milenage as milenage_mod  # noqa: F401
from . import nas_sec as nas_sec_mod    # noqa: F401

from .milenage import Milenage, derive_opc, AkaVector
from .kdf import k_ausf, k_seaf, k_amf, nas_keys, k_gnb, as_keys, res_star, xres_star
from .nas_sec import (
    nas_encrypt, nas_decrypt, nas_mac, nas_count, UnsupportedAlgorithm,
    NEA0, NEA1, NEA2, NEA3, NIA0, NIA1, NIA2, NIA3,
    ALG_NAMES, DIRECTION_UL, DIRECTION_DL, BEARER_NAS_3GPP,
    IMPLEMENTED_ENC, IMPLEMENTED_INT,
)

__all__ = [
    "Milenage", "derive_opc", "AkaVector",
    "k_ausf", "k_seaf", "k_amf", "nas_keys", "k_gnb", "as_keys", "res_star", "xres_star",
    "nas_encrypt", "nas_decrypt", "nas_mac", "nas_count", "UnsupportedAlgorithm",
    "NEA0", "NEA1", "NEA2", "NEA3", "NIA0", "NIA1", "NIA2", "NIA3",
    "ALG_NAMES", "DIRECTION_UL", "DIRECTION_DL", "BEARER_NAS_3GPP",
    "IMPLEMENTED_ENC", "IMPLEMENTED_INT",
]


def selftest(verbose: bool = False) -> bool:
    """crypto 계층 전체 자체검증."""
    results = [
        ("MILENAGE", milenage_mod.selftest(verbose)),
        ("KDF", kdf_mod.selftest(verbose)),
        ("NAS-SEC", nas_sec_mod.selftest(verbose)),
    ]
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  crypto/{name}")
    return all(ok for _, ok in results)
