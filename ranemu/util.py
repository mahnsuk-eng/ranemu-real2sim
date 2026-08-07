#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ranemu.util — 공통 유틸(로깅, 비트/바이트 조작, BCD, 시간)."""
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Iterable, List

# ─────────────────────────────────────────────────────────────────────────────
# 로깅
# ─────────────────────────────────────────────────────────────────────────────
_LEVEL = os.environ.get("RANEMU_LOG", "INFO").upper()


def get_logger(name: str) -> logging.Logger:
    lg = logging.getLogger(name)
    if not lg.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname).1s [%(name)s] %(message)s", "%H:%M:%S"))
        lg.addHandler(h)
        lg.setLevel(getattr(logging, _LEVEL, logging.INFO))
        lg.propagate = False
    return lg


log = get_logger("ranemu")


# ─────────────────────────────────────────────────────────────────────────────
# 바이트/비트
# ─────────────────────────────────────────────────────────────────────────────
def xor(a: bytes, b: bytes) -> bytes:
    """길이가 같은 두 바이트열의 XOR."""
    if len(a) != len(b):
        raise ValueError(f"xor 길이 불일치: {len(a)} vs {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))


def rotl(data: bytes, bits: int) -> bytes:
    """바이트열 전체를 왼쪽으로 `bits` 비트 회전(MILENAGE rot)."""
    n = len(data) * 8
    bits %= n
    if bits == 0:
        return bytes(data)
    v = int.from_bytes(data, "big")
    v = ((v << bits) | (v >> (n - bits))) & ((1 << n) - 1)
    return v.to_bytes(len(data), "big")


def hexs(data: bytes | None, sep: str = "") -> str:
    return "" if data is None else data.hex(sep) if sep else data.hex()


def unhex(s: str) -> bytes:
    """'0x' 접두/공백/콜론을 허용하는 관용적 hex 파서."""
    s = (s or "").strip().replace(" ", "").replace(":", "").replace("-", "")
    if s.lower().startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        raise ValueError(f"홀수 길이 hex: {s!r}")
    return bytes.fromhex(s)


def hexdump(data: bytes, width: int = 16, prefix: str = "  ") -> str:
    out: List[str] = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3 - 1)
        txt = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{prefix}{off:04x}  {hexpart}  |{txt}|")
    return "\n".join(out)


# ─────────────────────────────────────────────────────────────────────────────
# BCD / PLMN (TS 24.008 §10.5.1.13, TS 38.413)
# ─────────────────────────────────────────────────────────────────────────────
def bcd_encode_digits(digits: str, fill: int = 0xF) -> bytes:
    """숫자 문자열 → swapped-nibble BCD. 홀수 길이는 상위 니블을 `fill` 로 채운다."""
    out = bytearray()
    for i in range(0, len(digits), 2):
        lo = int(digits[i])
        hi = int(digits[i + 1]) if i + 1 < len(digits) else fill
        out.append((hi << 4) | lo)
    return bytes(out)


def bcd_decode_digits(data: bytes, fill: int = 0xF) -> str:
    out = []
    for b in data:
        lo, hi = b & 0x0F, (b >> 4) & 0x0F
        if lo != fill:
            out.append(str(lo))
        if hi != fill:
            out.append(str(hi))
    return "".join(out)


def plmn_encode(mcc: str, mnc: str) -> bytes:
    """MCC/MNC → 3바이트 PLMN identity.

    바이트 배치(TS 24.501 §9.11.3.5 / TS 38.413 PLMNIdentity):
        b0 = MCC2|MCC1, b1 = MNC3|MCC3, b2 = MNC2|MNC1
    2자리 MNC 는 MNC3 자리에 0xF.
    """
    mcc = str(mcc).zfill(3)
    mnc = str(mnc)
    if len(mnc) not in (2, 3):
        raise ValueError(f"MNC 자릿수 이상: {mnc!r}")
    m3 = int(mnc[2]) if len(mnc) == 3 else 0xF
    return bytes([
        (int(mcc[1]) << 4) | int(mcc[0]),
        (m3 << 4) | int(mcc[2]),
        (int(mnc[1]) << 4) | int(mnc[0]),
    ])


def plmn_decode(data: bytes) -> tuple[str, str]:
    b0, b1, b2 = data[0], data[1], data[2]
    mcc = f"{b0 & 0x0F}{(b0 >> 4) & 0x0F}{b1 & 0x0F}"
    m3 = (b1 >> 4) & 0x0F
    mnc = f"{b2 & 0x0F}{(b2 >> 4) & 0x0F}" + ("" if m3 == 0xF else str(m3))
    return mcc, mnc


def serving_network_name(mcc: str, mnc: str) -> str:
    """TS 24.501 §5.4.1.3.2 SNN — 5G-AKA KDF 의 P0."""
    return f"5G:mnc{str(mnc).zfill(3)}.mcc{str(mcc).zfill(3)}.3gppnetwork.org"


def imsi_split(imsi: str) -> tuple[str, str, str]:
    """IMSI → (MCC, MNC, MSIN). MNC 길이는 MCC 로 판별(한국 450=2자리)."""
    imsi = "".join(ch for ch in str(imsi) if ch.isdigit())
    mcc = imsi[:3]
    # 3자리 MNC 를 쓰는 대표 MCC (북미/일부). 그 외는 2자리.
    mnc_len = 3 if mcc in {"310", "311", "312", "313", "316", "302", "334", "732"} else 2
    return mcc, imsi[3:3 + mnc_len], imsi[3 + mnc_len:]


# ─────────────────────────────────────────────────────────────────────────────
# 시간
# ─────────────────────────────────────────────────────────────────────────────
def now() -> float:
    return time.time()


def mono() -> float:
    return time.monotonic()


def human_bps(bps: float) -> str:
    for unit, div in (("Gbps", 1e9), ("Mbps", 1e6), ("kbps", 1e3)):
        if abs(bps) >= div:
            return f"{bps / div:.2f} {unit}"
    return f"{bps:.0f} bps"


def chunked(data: bytes, size: int) -> Iterable[bytes]:
    for i in range(0, len(data), size):
        yield data[i:i + size]
