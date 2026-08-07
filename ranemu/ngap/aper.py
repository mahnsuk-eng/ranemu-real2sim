#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.ngap.aper — NGAP 용 ASN.1 ALIGNED PER (X.691) 프리미티브.

범용 ASN.1 컴파일러를 쓰지 않는 이유
====================================
NGAP 전체 스펙을 처리하는 범용 APER 코덱은 크고, 이 프로젝트는 그중 10여 개 메시지만
쓴다. 대신 **X.691 규칙 자체**를 정확히 구현하고(아래), 메시지 구조는 messages.py 에서
명시적으로 조립한다. 결과 바이트는 tshark 의 NGAP 디섹터로 독립 검증한다.

구현한 X.691 규칙
=================
  §11.5  제약 정수(constrained whole number)
           range = 1        → 0비트
           range ≤ 255      → 최소비트 비트필드(정렬 안 함)
           range = 256      → 1옥텟(정렬)
           257 ≤ range ≤ 64K→ 2옥텟(정렬)
           range > 64K      → 최소옥텟수 + 길이지시자
  §11.9  길이지시자(비제약): <128 → 1옥텟, <16K → 2옥텟(상위비트 10), 그 이상 → 단편화
  §13    CHOICE: 확장비트 + 인덱스(제약 정수)
  §18    SEQUENCE: 확장비트 + OPTIONAL/DEFAULT 존재비트 프리앰블
  §19    SEQUENCE OF: 크기제약을 제약 정수로 인코딩한 개수
  §15    BIT STRING: 크기제약 → 길이 + (ub>16비트면 옥텟정렬) 내용
  §16/17 OCTET STRING: 고정크기 ≤2옥텟은 정렬 안 함, 그 외 정렬
  §10.9  Open type: 길이지시자 + 옥텟정렬 내용
"""
from __future__ import annotations

from typing import List, Optional, Tuple


class AperError(ValueError):
    """APER 인코딩/디코딩 오류."""


def _bits_needed(range_size: int) -> int:
    """range_size 개의 값을 표현하는 최소 비트 수."""
    if range_size <= 1:
        return 0
    return (range_size - 1).bit_length()


# ═════════════════════════════════════════════════════════════════════════════
# 비트 기록기
# ═════════════════════════════════════════════════════════════════════════════
class BitWriter:
    """MSB-우선 비트 스트림 기록기."""

    __slots__ = ("_bits",)

    def __init__(self) -> None:
        self._bits: List[int] = []

    # ── 저수준 ────────────────────────────────────────────────────────────
    def bit(self, value: int) -> "BitWriter":
        self._bits.append(1 if value else 0)
        return self

    def bits(self, value: int, count: int) -> "BitWriter":
        if count < 0:
            raise AperError(f"음수 비트수: {count}")
        if count and value >= (1 << count):
            raise AperError(f"값 {value} 이 {count}비트를 초과")
        for i in range(count - 1, -1, -1):
            self._bits.append((value >> i) & 1)
        return self

    def align(self) -> "BitWriter":
        while len(self._bits) % 8:
            self._bits.append(0)
        return self

    def octets(self, data: bytes) -> "BitWriter":
        """옥텟 정렬 후 바이트열 기록."""
        self.align()
        for b in data:
            self.bits(b, 8)
        return self

    @property
    def bit_length(self) -> int:
        return len(self._bits)

    def bytes(self) -> bytes:
        self.align()
        out = bytearray()
        for i in range(0, len(self._bits), 8):
            v = 0
            for b in self._bits[i:i + 8]:
                v = (v << 1) | b
            out.append(v)
        return bytes(out)

    # ── X.691 규칙 ────────────────────────────────────────────────────────
    def constrained_int(self, value: int, lo: int, hi: int) -> "BitWriter":
        """§11.5 제약 정수."""
        if not (lo <= value <= hi):
            raise AperError(f"제약 정수 범위 밖: {value} ∉ [{lo},{hi}]")
        rng = hi - lo + 1
        v = value - lo
        if rng == 1:
            return self
        if rng <= 255:
            return self.bits(v, _bits_needed(rng))
        if rng == 256:
            self.align()
            return self.bits(v, 8)
        if rng <= 65536:
            self.align()
            return self.bits(v, 16)
        # range > 64K: 값을 담을 최소 옥텟수를 길이로 먼저 보낸다
        nbytes = max(1, (v.bit_length() + 7) // 8)
        self.constrained_int(nbytes - 1, 0, ((rng - 1).bit_length() + 7) // 8 - 1)
        self.align()
        return self.bits(v, nbytes * 8)

    def length_det(self, n: int) -> "BitWriter":
        """§11.9 비제약 길이지시자."""
        self.align()
        if n < 128:
            return self.bits(n, 8)
        if n < 16384:
            return self.bits(0x8000 | n, 16)
        raise AperError(f"16K 이상 길이는 단편화 필요(미지원): {n}")

    def open_type(self, data: bytes) -> "BitWriter":
        """§10.9 open type: 길이 + 옥텟정렬 내용. 빈 내용은 1옥텟으로 채운다."""
        if not data:
            data = b"\x00"
        self.length_det(len(data))
        return self.octets(data)

    def octet_string(self, data: bytes, lo: Optional[int] = None,
                     hi: Optional[int] = None) -> "BitWriter":
        """§16/17 OCTET STRING."""
        n = len(data)
        if lo is not None and hi is not None and lo == hi:
            if n != lo:
                raise AperError(f"고정 OCTET STRING 길이 불일치: {n} != {lo}")
            if n <= 2:                      # ≤16비트는 정렬하지 않고 그대로
                for b in data:
                    self.bits(b, 8)
                return self
            return self.octets(data)
        if lo is not None and hi is not None:
            self.constrained_int(n, lo, hi)
        else:
            self.length_det(n)
        return self.octets(data)

    def bit_string(self, value: int, nbits: int,
                   lo: Optional[int] = None, hi: Optional[int] = None,
                   extensible: bool = False) -> "BitWriter":
        """§15 BIT STRING. value 는 MSB 우선 정수, nbits 는 유효 비트수."""
        if extensible:
            self.bit(0)                      # 확장 루트 안
        if lo is not None and hi is not None:
            if lo != hi:
                self.constrained_int(nbits, lo, hi)
            elif nbits != lo:
                raise AperError(f"고정 BIT STRING 길이 불일치: {nbits} != {lo}")
            ub = hi
        else:
            self.length_det(nbits)
            ub = nbits
        if ub > 16:
            self.align()
        return self.bits(value, nbits)

    def choice_index(self, index: int, n_alternatives: int,
                     extensible: bool = True) -> "BitWriter":
        """§13 CHOICE 인덱스."""
        if extensible:
            self.bit(0)
        return self.constrained_int(index, 0, n_alternatives - 1)

    def enumerated(self, index: int, n_values: int,
                   extensible: bool = False) -> "BitWriter":
        """§14 ENUMERATED."""
        if extensible:
            self.bit(0)
        return self.constrained_int(index, 0, n_values - 1)

    def sequence_preamble(self, extensible: bool, optionals: List[bool]) -> "BitWriter":
        """§18 SEQUENCE 프리앰블: 확장비트 + OPTIONAL 존재비트."""
        if extensible:
            self.bit(0)
        for present in optionals:
            self.bit(1 if present else 0)
        return self

    def sequence_of_count(self, n: int, lo: int, hi: int) -> "BitWriter":
        """§19 SEQUENCE OF 개수."""
        return self.constrained_int(n, lo, hi)

    def printable_string(self, text: str, lo: int, hi: int,
                         extensible: bool = True) -> "BitWriter":
        """§30 PrintableString (정렬 PER: 문자당 8비트, ub*8>16 이면 옥텟정렬)."""
        data = text.encode("ascii", "replace")[:hi]
        if len(data) < lo:
            data = data.ljust(lo, b" ")
        if extensible:
            self.bit(0)
        self.constrained_int(len(data), lo, hi)
        if hi * 8 > 16:
            self.align()
        for b in data:
            self.bits(b, 8)
        return self


# ═════════════════════════════════════════════════════════════════════════════
# 비트 판독기
# ═════════════════════════════════════════════════════════════════════════════
class BitReader:
    """MSB-우선 비트 스트림 판독기."""

    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = bytes(data)
        self._pos = 0                      # 비트 단위 위치

    @property
    def pos(self) -> int:
        return self._pos

    @property
    def remaining_bits(self) -> int:
        return len(self._data) * 8 - self._pos

    def bit(self) -> int:
        if self._pos >= len(self._data) * 8:
            raise AperError("비트 스트림 끝을 넘어 읽음")
        byte = self._data[self._pos // 8]
        b = (byte >> (7 - (self._pos % 8))) & 1
        self._pos += 1
        return b

    def bits(self, count: int) -> int:
        v = 0
        for _ in range(count):
            v = (v << 1) | self.bit()
        return v

    def align(self) -> None:
        while self._pos % 8:
            self._pos += 1

    def octets(self, n: int) -> bytes:
        self.align()
        start = self._pos // 8
        if start + n > len(self._data):
            raise AperError(f"옥텟 {n}개를 읽을 수 없음(남은 {len(self._data) - start})")
        self._pos += n * 8
        return self._data[start:start + n]

    # ── X.691 규칙 ────────────────────────────────────────────────────────
    def constrained_int(self, lo: int, hi: int) -> int:
        rng = hi - lo + 1
        if rng == 1:
            return lo
        if rng <= 255:
            return lo + self.bits(_bits_needed(rng))
        if rng == 256:
            self.align()
            return lo + self.bits(8)
        if rng <= 65536:
            self.align()
            return lo + self.bits(16)
        nbytes_bits = ((rng - 1).bit_length() + 7) // 8
        nbytes = self.constrained_int(0, nbytes_bits - 1) + 1
        self.align()
        return lo + self.bits(nbytes * 8)

    def length_det(self) -> int:
        self.align()
        first = self.bits(8)
        if first < 128:
            return first
        if first < 192:
            return ((first & 0x3F) << 8) | self.bits(8)
        raise AperError(f"단편화 길이(0x{first:02X})는 미지원")

    def open_type(self) -> bytes:
        n = self.length_det()
        return self.octets(n)

    def octet_string(self, lo: Optional[int] = None, hi: Optional[int] = None) -> bytes:
        if lo is not None and hi is not None and lo == hi:
            if lo <= 2:
                return bytes(self.bits(8) for _ in range(lo))
            return self.octets(lo)
        n = self.constrained_int(lo, hi) if (lo is not None and hi is not None) \
            else self.length_det()
        return self.octets(n)

    def bit_string(self, lo: Optional[int] = None, hi: Optional[int] = None,
                   extensible: bool = False) -> Tuple[int, int]:
        """→ (값, 비트수)"""
        if extensible and self.bit():
            raise AperError("BIT STRING 확장값은 미지원")
        if lo is not None and hi is not None:
            nbits = lo if lo == hi else self.constrained_int(lo, hi)
            ub = hi
        else:
            nbits = self.length_det()
            ub = nbits
        if ub > 16:
            self.align()
        return self.bits(nbits), nbits

    def choice_index(self, n_alternatives: int, extensible: bool = True) -> int:
        if extensible and self.bit():
            raise AperError("CHOICE 확장 대안은 미지원")
        return self.constrained_int(0, n_alternatives - 1)

    def enumerated(self, n_values: int, extensible: bool = False) -> int:
        if extensible and self.bit():
            raise AperError("ENUMERATED 확장값은 미지원")
        return self.constrained_int(0, n_values - 1)

    def sequence_preamble(self, extensible: bool, n_optionals: int) -> Tuple[bool, List[bool]]:
        ext = bool(self.bit()) if extensible else False
        return ext, [bool(self.bit()) for _ in range(n_optionals)]

    def sequence_of_count(self, lo: int, hi: int) -> int:
        return self.constrained_int(lo, hi)

    def printable_string(self, lo: int, hi: int, extensible: bool = True) -> str:
        if extensible and self.bit():
            raise AperError("PrintableString 확장은 미지원")
        n = self.constrained_int(lo, hi)
        if hi * 8 > 16:
            self.align()
        return bytes(self.bits(8) for _ in range(n)).decode("ascii", "replace")


# ═════════════════════════════════════════════════════════════════════════════
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    ok = True

    # (1) 제약 정수: 각 구간별 인코딩 크기 규칙
    cases = [
        # (값, lo, hi, 기대 비트길이)
        (0, 0, 0, 0),          # range 1 → 0비트
        (5, 0, 7, 3),          # range 8 → 3비트
        (200, 0, 254, 8),      # range 255 → 8비트(정렬 안 함)
        (200, 0, 255, 8),      # range 256 → 1옥텟(정렬)
        (1000, 0, 65535, 16),  # range 64K → 2옥텟(정렬)
    ]
    for val, lo, hi, exp_bits in cases:
        w = BitWriter().constrained_int(val, lo, hi)
        if w.bit_length != exp_bits:
            ok = False
            print(f"  [APER] 제약정수({val},{lo},{hi}) 비트수 {w.bit_length} != {exp_bits}")
        r = BitReader(w.bytes())
        if r.constrained_int(lo, hi) != val:
            ok = False
            print(f"  [APER] 제약정수 왕복 실패: {val} [{lo},{hi}]")
    if verbose and ok:
        print("  [APER] 제약정수 5개 구간 규칙 + 왕복 OK")

    # (2) 정렬 동작: range=256 은 옥텟 경계에서 시작해야 함
    w = BitWriter().bit(1).constrained_int(3, 0, 255)
    if w.bit_length != 16:
        ok = False
        print(f"  [APER] range=256 정렬 실패: {w.bit_length} 비트")
    elif verbose:
        print("  [APER] range=256 옥텟정렬 OK")

    # (3) 길이지시자
    for n in (0, 1, 127, 128, 300, 16383):
        w = BitWriter().length_det(n)
        if BitReader(w.bytes()).length_det() != n:
            ok = False
            print(f"  [APER] 길이지시자 왕복 실패: {n}")
    if len(BitWriter().length_det(127).bytes()) != 1:
        ok = False
        print("  [APER] 길이 127 이 1옥텟이 아님")
    if len(BitWriter().length_det(128).bytes()) != 2:
        ok = False
        print("  [APER] 길이 128 이 2옥텟이 아님")
    if verbose:
        print("  [APER] 길이지시자(1/2옥텟 경계) OK")

    # (4) open type 왕복
    payload = bytes(range(50))
    w = BitWriter().open_type(payload)
    if BitReader(w.bytes()).open_type() != payload:
        ok = False
        print("  [APER] open type 왕복 실패")

    # (5) OCTET STRING: 고정 3옥텟(PLMN)은 정렬됨
    plmn = bytes([0x54, 0xF0, 0x50])
    w = BitWriter().bit(1).octet_string(plmn, 3, 3)
    if w.bit_length != 8 + 24:
        ok = False
        print(f"  [APER] 고정 OCTET STRING 정렬 실패: {w.bit_length}")
    r = BitReader(w.bytes()); r.bit()
    if r.octet_string(3, 3) != plmn:
        ok = False
        print("  [APER] 고정 OCTET STRING 왕복 실패")
    elif verbose:
        print("  [APER] OCTET STRING(고정 3옥텟, 정렬) OK")

    # (6) 2옥텟 이하 고정 OCTET STRING 은 정렬하지 않음
    w = BitWriter().bit(1).octet_string(b"\xAB\xCD", 2, 2)
    if w.bit_length != 17:
        ok = False
        print(f"  [APER] 2옥텟 OCTET STRING 이 정렬됨: {w.bit_length}")

    # (7) BIT STRING SIZE(22..32) — gNB-ID
    for nbits in (22, 24, 32):
        val = (1 << (nbits - 1)) | 0x15
        w = BitWriter().bit_string(val, nbits, 22, 32)
        r = BitReader(w.bytes())
        got, gn = r.bit_string(22, 32)
        if (got, gn) != (val, nbits):
            ok = False
            print(f"  [APER] BIT STRING({nbits}) 왕복 실패: {got:x}/{gn}")
    if verbose:
        print("  [APER] BIT STRING SIZE(22..32) 왕복 OK")

    # (8) CHOICE / ENUMERATED
    w = BitWriter().choice_index(1, 3)
    r = BitReader(w.bytes())
    if r.choice_index(3) != 1:
        ok = False
        print("  [APER] CHOICE 인덱스 왕복 실패")
    w = BitWriter().enumerated(2, 3)
    if BitReader(w.bytes()).enumerated(3) != 2:
        ok = False
        print("  [APER] ENUMERATED 왕복 실패")

    # (9) SEQUENCE 프리앰블
    w = BitWriter().sequence_preamble(True, [True, False, True])
    r = BitReader(w.bytes())
    ext, opts = r.sequence_preamble(True, 3)
    if ext or opts != [True, False, True]:
        ok = False
        print(f"  [APER] SEQUENCE 프리앰블 왕복 실패: {ext},{opts}")
    elif verbose:
        print("  [APER] SEQUENCE 프리앰블 OK")

    # (10) SEQUENCE OF 개수: maxnoofTACs=256 → 1옥텟, maxnoofSliceItems=1024 → 2옥텟
    if BitWriter().sequence_of_count(1, 1, 256).bit_length != 8:
        ok = False
        print("  [APER] SIZE(1..256) 개수가 1옥텟이 아님")
    if BitWriter().sequence_of_count(1, 1, 1024).bit_length != 16:
        ok = False
        print("  [APER] SIZE(1..1024) 개수가 2옥텟이 아님")
    if BitWriter().sequence_of_count(3, 1, 12).bit_length != 4:
        ok = False
        print("  [APER] SIZE(1..12) 개수가 4비트가 아님")
    elif verbose:
        print("  [APER] SEQUENCE OF 개수 규칙(4비트/1옥텟/2옥텟) OK")

    # (11) PrintableString 왕복
    w = BitWriter().printable_string("ranemu-gnb-1", 1, 150)
    if BitReader(w.bytes()).printable_string(1, 150) != "ranemu-gnb-1":
        ok = False
        print("  [APER] PrintableString 왕복 실패")
    elif verbose:
        print("  [APER] PrintableString 왕복 OK")

    # (12) 범위초과는 예외
    try:
        BitWriter().constrained_int(300, 0, 255)
        ok = False
        print("  [APER] 범위 초과를 검출하지 못함")
    except AperError:
        pass

    # (13) 비트 스트림 끝 초과 읽기는 예외
    try:
        BitReader(b"\x00").bits(16)
        ok = False
        print("  [APER] 스트림 끝 초과 읽기를 검출하지 못함")
    except AperError:
        pass
    return ok


if __name__ == "__main__":
    print("APER selftest:", "PASS" if selftest(verbose=True) else "FAIL")
