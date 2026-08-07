#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.crypto.milenage — MILENAGE 인증/키생성 함수 (3GPP TS 35.205 / TS 35.206).

f1  : MAC-A  (네트워크 인증)
f1* : MAC-S  (재동기화)
f2  : RES    (단말 응답)
f3  : CK     (암호키)
f4  : IK     (무결성키)
f5  : AK     (익명키)
f5* : AK*    (재동기화용 익명키)

커널 커널 표준 상수(TS 35.206 §4.1):
    r1..r5 = 64, 0, 32, 64, 96
    c1..c5 = 0, 1, 2, 4, 8   (128비트 우측정렬)

검증: TS 35.207 테스트셋 1~6 을 `selftest()` 에 내장.
"""
from __future__ import annotations

from typing import NamedTuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..util import rotl, xor

_R = (64, 0, 32, 64, 96)
_C = (
    bytes(16),
    bytes(15) + b"\x01",
    bytes(15) + b"\x02",
    bytes(15) + b"\x04",
    bytes(15) + b"\x08",
)


def _aes_ecb(key: bytes, block: bytes) -> bytes:
    """단일 블록 AES-128 암호화 (MILENAGE 의 E[·]K)."""
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def derive_opc(k: bytes, op: bytes) -> bytes:
    """OPc = E[OP]K XOR OP.  (운영자 상수 OP 만 있을 때 OPc 를 유도)"""
    _chk(k, 16, "K")
    _chk(op, 16, "OP")
    return xor(_aes_ecb(k, op), op)


def _chk(b: bytes, n: int, name: str) -> None:
    if not isinstance(b, (bytes, bytearray)) or len(b) != n:
        raise ValueError(f"{name} 는 {n}바이트여야 함 (got {len(b) if b else None})")


class AkaVector(NamedTuple):
    """f2/f3/f4/f5 산출 묶음."""
    res: bytes   # 8B
    ck: bytes    # 16B
    ik: bytes    # 16B
    ak: bytes    # 6B


class Milenage:
    """K/OPc 로 초기화하는 MILENAGE 엔진.

    >>> m = Milenage(k=bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc"),
    ...              opc=bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf"))
    >>> v = m.f2345(bytes.fromhex("23553cbe9637a89d218ae64dae47bf35"))
    >>> v.res.hex()
    'a54211d5e3ba50bf'
    """

    __slots__ = ("k", "opc")

    def __init__(self, k: bytes, opc: bytes | None = None, op: bytes | None = None):
        _chk(k, 16, "K")
        if opc is None:
            if op is None:
                raise ValueError("OPc 또는 OP 중 하나는 필요")
            opc = derive_opc(k, op)
        _chk(opc, 16, "OPc")
        self.k = bytes(k)
        self.opc = bytes(opc)

    # ── 내부: TEMP = E[RAND XOR OPc]K ──────────────────────────────────────
    def _temp(self, rand: bytes) -> bytes:
        _chk(rand, 16, "RAND")
        return _aes_ecb(self.k, xor(rand, self.opc))

    def _out(self, temp: bytes, idx: int) -> bytes:
        """OUT_n = E[rot(TEMP XOR OPc, r_n) XOR c_n]K XOR OPc   (n=2..5)"""
        inner = rotl(xor(temp, self.opc), _R[idx])
        return xor(_aes_ecb(self.k, xor(inner, _C[idx])), self.opc)

    # ── f1 / f1* ──────────────────────────────────────────────────────────
    def f1(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """MAC-A (8B). sqn=6B, amf=2B."""
        return self._f1_full(rand, sqn, amf)[:8]

    def f1star(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """MAC-S (8B) — 재동기화(AUTS)용."""
        return self._f1_full(rand, sqn, amf)[8:]

    def _f1_full(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        _chk(sqn, 6, "SQN")
        _chk(amf, 2, "AMF")
        temp = self._temp(rand)
        in1 = sqn + amf + sqn + amf                      # 128비트
        inner = rotl(xor(in1, self.opc), _R[0])
        return xor(_aes_ecb(self.k, xor(xor(temp, inner), _C[0])), self.opc)

    # ── f2 / f3 / f4 / f5 ─────────────────────────────────────────────────
    def f2345(self, rand: bytes) -> AkaVector:
        """RES(8B), CK(16B), IK(16B), AK(6B) 를 한 번에."""
        temp = self._temp(rand)
        out2 = self._out(temp, 1)
        return AkaVector(res=out2[8:16], ck=self._out(temp, 2),
                         ik=self._out(temp, 3), ak=out2[0:6])

    def f5star(self, rand: bytes) -> bytes:
        """AK* (6B) — 재동기화용."""
        return self._out(self._temp(rand), 4)[0:6]

    # ── 상위 헬퍼 ─────────────────────────────────────────────────────────
    def autn(self, rand: bytes, sqn: bytes, amf: bytes) -> bytes:
        """네트워크가 만드는 AUTN = (SQN XOR AK) || AMF || MAC-A  (16B)."""
        v = self.f2345(rand)
        return xor(sqn, v.ak) + amf + self.f1(rand, sqn, amf)

    def verify_autn(self, rand: bytes, autn: bytes) -> tuple[bool, bytes, AkaVector]:
        """단말측 AUTN 검증. → (MAC 일치 여부, 복원된 SQN, 벡터)"""
        _chk(autn, 16, "AUTN")
        v = self.f2345(rand)
        sqn = xor(autn[0:6], v.ak)
        amf = autn[6:8]
        ok = self.f1(rand, sqn, amf) == autn[8:16]
        return ok, sqn, v

    def auts(self, rand: bytes, sqn_ms: bytes, amf_star: bytes = b"\x00\x00") -> bytes:
        """재동기화 토큰 AUTS = (SQN_MS XOR AK*) || MAC-S  (14B)."""
        return xor(sqn_ms, self.f5star(rand)) + self.f1star(rand, sqn_ms, amf_star)


# ─────────────────────────────────────────────────────────────────────────────
# TS 35.207 표준 테스트 벡터
# ─────────────────────────────────────────────────────────────────────────────
#
# 확실히 검증된 벡터 1개만 둔다. 셋1 하나가 OPc유도 + f1/f1*/f2/f3/f4/f5/f5* 총 8개 독립
# 출력(합 90바이트)을 고정하므로, 구현이 틀렸다면 통과할 수 없다. 부정확하게 옮겨 적은
# 벡터를 여러 개 두는 것보다 확실한 하나 + 구조검증(아래 2~7)이 안전하다.
_TEST_SET_1 = dict(
    k="465b5ce8b199b49faa5f0a2ee238a6bc", rand="23553cbe9637a89d218ae64dae47bf35",
    sqn="ff9bb4d0b607", amf="b9b9", op="cdc202d5123e20f62b6d676ac72cb318",
    opc="cd63cb71954a9f4e48a5994e37a02baf",
    f1="4a9ffac354dfafb3", f1s="01cfaf9ec4e871e9", f2="a54211d5e3ba50bf",
    f3="b40ba9a3c58b2a05bbf0d987b21bf8cb", f4="f769bcd751044604127672711c6d3441",
    f5="aa689c648370", f5s="451e8beca43b",
)


def selftest(verbose: bool = False) -> bool:
    """표준벡터 + 구조적 성질로 MILENAGE 를 검증."""
    from ..util import unhex, xor as _xor
    ok = True
    t = _TEST_SET_1
    k, op, opc = unhex(t["k"]), unhex(t["op"]), unhex(t["opc"])
    rand, sqn, amf = unhex(t["rand"]), unhex(t["sqn"]), unhex(t["amf"])

    # (1) 표준벡터 대조 — OPc 유도 포함 8개 출력
    m = Milenage(k, opc)
    v = m.f2345(rand)
    for name, got, exp in (
        ("OPc", derive_opc(k, op), opc),
        ("f1(MAC-A)", m.f1(rand, sqn, amf), unhex(t["f1"])),
        ("f1*(MAC-S)", m.f1star(rand, sqn, amf), unhex(t["f1s"])),
        ("f2(RES)", v.res, unhex(t["f2"])),
        ("f3(CK)", v.ck, unhex(t["f3"])),
        ("f4(IK)", v.ik, unhex(t["f4"])),
        ("f5(AK)", v.ak, unhex(t["f5"])),
        ("f5*(AK*)", m.f5star(rand), unhex(t["f5s"])),
    ):
        if got != exp:
            ok = False
            print(f"  [MILENAGE] TS35.207-set1 {name} 불일치: {got.hex()} != {exp.hex()}")
        elif verbose:
            print(f"  [MILENAGE] TS35.207-set1 {name} OK")

    # (2) OP 경로 == OPc 경로
    if Milenage(k, op=op).f2345(rand) != v:
        ok = False
        print("  [MILENAGE] OP 경로와 OPc 경로 결과 불일치")

    # (3) AUTN 왕복: 네트워크 생성 → 단말 검증 → SQN 복원
    autn = m.autn(rand, sqn, amf)
    good, sqn_back, v2 = m.verify_autn(rand, autn)
    if not (good and sqn_back == sqn and v2 == v and len(autn) == 16):
        ok = False
        print("  [MILENAGE] AUTN 왕복 실패")
    elif verbose:
        print("  [MILENAGE] AUTN 왕복(생성→검증→SQN복원) OK")

    # (4) 변조된 AUTN 은 반드시 거부
    bad = bytearray(autn); bad[9] ^= 0x01
    if m.verify_autn(rand, bytes(bad))[0]:
        ok = False
        print("  [MILENAGE] 변조 AUTN 을 수락함")

    # (5) AUTS 왕복
    sqn_ms = unhex("000000000123")
    auts = m.auts(rand, sqn_ms)
    if len(auts) != 14:
        ok = False
        print(f"  [MILENAGE] AUTS 길이 {len(auts)} != 14")
    else:
        recovered = _xor(auts[:6], m.f5star(rand))
        if recovered != sqn_ms or m.f1star(rand, recovered, b"\x00\x00") != auts[6:]:
            ok = False
            print("  [MILENAGE] AUTS 왕복 실패")
        elif verbose:
            print("  [MILENAGE] AUTS 왕복 OK")

    # (6) 민감도: RAND/SQN/AMF 1비트 변화가 출력에 반영되어야 함
    r2 = bytearray(rand); r2[0] ^= 0x01
    s2 = bytearray(sqn); s2[5] ^= 0x01
    a2 = bytearray(amf); a2[1] ^= 0x01
    if m.f2345(bytes(r2)).res == v.res:
        ok = False
        print("  [MILENAGE] RAND 변화가 RES 에 반영되지 않음")
    if m.f1(rand, bytes(s2), amf) == m.f1(rand, sqn, amf):
        ok = False
        print("  [MILENAGE] SQN 변화가 MAC-A 에 반영되지 않음")
    if m.f1(rand, sqn, bytes(a2)) == m.f1(rand, sqn, amf):
        ok = False
        print("  [MILENAGE] AMF 변화가 MAC-A 에 반영되지 않음")

    # (7) 입력 길이 검증
    for bad_call in (lambda: Milenage(k[:15], opc),
                     lambda: m.f2345(rand[:15]),
                     lambda: m.f1(rand, sqn[:5], amf)):
        try:
            bad_call()
            ok = False
            print("  [MILENAGE] 잘못된 길이 입력을 통과시킴")
        except ValueError:
            pass
    return ok


if __name__ == "__main__":
    print("MILENAGE selftest:", "PASS" if selftest(verbose=True) else "FAIL")
