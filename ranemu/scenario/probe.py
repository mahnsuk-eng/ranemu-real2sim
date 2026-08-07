#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.probe — (호환 shim) stamp.py 로 통합됨.

이 파일에 있던 20 B 시제품 스탬프는 설계 §3.6 의 48 B STAMP 포맷(`stamp.py`)으로
대체되었다. **트리에는 스탬프 포맷이 하나만 존재해야** 두 포맷이 섞여 디코딩되는
사고를 원천 차단할 수 있으므로, 여기서는 어떤 포맷도 정의하지 않고 재수출만 한다.

EVIDENCE.md §3 의 실측치(증분 3.8 µs vs 전체 38.8 µs, 10.3배)는 20 B 판 기준이다.
48 B 판의 동일 검증(바이트 동일성 + 속도 비교)은 `stamp.selftest` 가 다시 수행한다
(48 B 는 재합산 워드가 10→24개라 이득이 10.3배에서 ~7배로 줄지만 여전히 증분이 빠르다).
"""
from __future__ import annotations

from .stamp import (  # noqa: F401 — 하위 호환 재수출
    MAGIC, STAMP_LEN, MIN_PAYLOAD, Stamp,
    pack_stamp, unpack_stamp, decode_from_inner_ip, fill_t2t3, stamp_packet,
    FlowLedger, BurstLedger, LogHistogram,
    selftest as _stamp_selftest,
)


def selftest(verbose: bool = False) -> bool:
    """20 B 판의 자체시험은 48 B 판(stamp.py)으로 위임된다."""
    return _stamp_selftest(verbose)


if __name__ == "__main__":
    print("PROBE(→STAMP shim) selftest:",
          "PASS" if selftest(verbose=True) else "FAIL")
