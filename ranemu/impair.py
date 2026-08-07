#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.impair — 코어측 캡처 경로의 손상(impairment) 모델.

목적
====
수동 측정 프로브가 보고하는 값은 **캡처 경로를 통과한 뒤의 스트림**에서 계산된다.
그 경로는 무손실이 아니다. 이 테스트베드에서 실제로 관측된 네 가지 손상이 있다:

  1. **미러 포화 tail-drop** — 1 GbE SPAN 이 ~950 Mb/s 에서 포화해 피크 구간 패킷을 버린다.
  2. **타임스탬프 합침(coalescing)** — GRO/IRQ 배칭으로 여러 패킷이 같은 시각을 갖는다.
     짧은 창(≤10 ms)의 순간속도가 부풀려진다.
  3. **다중 탭 중복** — N3/N6 두 탭이 같은 바이트를 두 번 보여 준다.
  4. **snaplen 절단** — 헤더만 남고 페이로드가 잘린다.

이 모듈은 각 손상을 **파라미터로 주입**한다. 손상량을 우리가 정하므로 정답을 알고,
프로브의 보고값이 정답에서 얼마나 벗어나는지 통제된 실험으로 잴 수 있다.
이것이 실 코어 없이도 측정 시스템의 오차 특성을 얻는 방법이다.
"""
from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .pcapio import PcapReader, PcapWriter
from .util import get_logger

log = get_logger("ranemu.impair")


# ─────────────────────────────────────────────────────────────────────────────
class MirrorSaturation:
    """유한 용량 미러 링크의 tail-drop 모델.

    용량 `capacity_bps` 로 배출되는 버퍼에 패킷을 넣되, 버퍼가 넘치면 버린다.
    균등 무작위 손실과 달리 **피크 구간에 손실이 집중**되므로 실제 SPAN 포화의
    거동(평균은 멀쩡한데 버스트만 잘림)을 재현한다.
    """

    __slots__ = ("capacity_bps", "buffer_bytes", "_queue", "_last")

    def __init__(self, capacity_mbps: float, buffer_kb: float = 256.0):
        self.capacity_bps = max(1.0, capacity_mbps * 1e6)
        self.buffer_bytes = max(1500.0, buffer_kb * 1000.0)
        self._queue = 0.0
        self._last: Optional[float] = None

    def accept(self, ts: float, wire_len: int) -> bool:
        if self._last is None:
            self._last = ts
        drained = max(0.0, (ts - self._last)) * self.capacity_bps / 8.0
        self._queue = max(0.0, self._queue - drained)
        self._last = ts
        if self._queue + wire_len > self.buffer_bytes:
            return False
        self._queue += wire_len
        return True


class TimestampCoalescer:
    """GRO/IRQ 배칭에 의한 타임스탬프 합침.

    연속한 k개 패킷이 배치의 **마지막 패킷 시각**을 공유한다. 커널이 인터럽트
    한 번에 여러 패킷을 올릴 때 나타나는 현상이다.
    """

    __slots__ = ("mean_batch", "_rng")

    def __init__(self, mean_batch: float, rng: Optional[random.Random] = None):
        self.mean_batch = max(1.0, float(mean_batch))
        self._rng = rng or random.Random(0)

    def apply(self, records: List[Tuple[float, bytes, int]]
              ) -> List[Tuple[float, bytes, int]]:
        if self.mean_batch <= 1.0:
            return records
        out: List[Tuple[float, bytes, int]] = []
        i = 0
        n = len(records)
        while i < n:
            k = max(1, int(round(self._rng.expovariate(1.0 / self.mean_batch))))
            batch = records[i:i + k]
            if not batch:
                break
            ts = batch[-1][0]                      # 배치 마지막 시각으로 통일
            out.extend((ts, d, o) for _t, d, o in batch)
            i += len(batch)
        return out


@dataclass
class ImpairmentConfig:
    """캡처 손상 파라미터. 모두 끄면 무손상(정답) 패스스루."""
    #: 균등 무작위 손실률 (0~1). 통제된 스윕용.
    loss_rate: float = 0.0
    #: 미러 링크 용량(Mb/s). None 이면 포화 없음. 실측 근거: 1 GbE SPAN ≈ 950 Mb/s
    capacity_mbps: Optional[float] = None
    buffer_kb: float = 256.0
    #: 타임스탬프 합침 평균 배치 크기 (1.0 = 없음)
    coalesce_batch: float = 1.0
    #: 다중 탭 중복 비율 (0~1)
    duplicate_rate: float = 0.0
    #: 캡처 snaplen (0 = 절단 없음)
    snaplen: int = 0
    seed: int = 42

    def is_identity(self) -> bool:
        return (self.loss_rate <= 0 and self.capacity_mbps is None
                and self.coalesce_batch <= 1.0 and self.duplicate_rate <= 0
                and self.snaplen <= 0)


@dataclass
class ImpairmentStats:
    packets_in: int = 0
    packets_out: int = 0
    dropped_random: int = 0
    dropped_saturation: int = 0
    duplicated: int = 0
    truncated: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    coalesced_packets: int = 0

    @property
    def loss_rate_actual(self) -> float:
        return ((self.dropped_random + self.dropped_saturation) / self.packets_in
                if self.packets_in else 0.0)

    @property
    def coalescing_ratio(self) -> float:
        """이전 패킷과 같은 시각을 갖는 패킷의 비율(프로브가 관측 가능한 신호)."""
        return self.coalesced_packets / self.packets_out if self.packets_out else 0.0

    def as_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        d["loss_rate_actual"] = round(self.loss_rate_actual, 6)
        d["coalescing_ratio"] = round(self.coalescing_ratio, 4)
        return d


def apply_to_pcap(src_path: str, dst_path: str, cfg: ImpairmentConfig
                  ) -> ImpairmentStats:
    """정답 pcap 에 손상을 주입해 '프로브가 실제로 보게 될' pcap 을 만든다."""
    rng = random.Random(cfg.seed)
    sat = MirrorSaturation(cfg.capacity_mbps, cfg.buffer_kb) if cfg.capacity_mbps else None
    st = ImpairmentStats()

    kept: List[Tuple[float, bytes, int]] = []
    reader = PcapReader(src_path)
    linktype = reader.linktype
    try:
        for ts, data, orig in reader:
            st.packets_in += 1
            st.bytes_in += orig
            # 1) 균등 무작위 손실
            if cfg.loss_rate > 0 and rng.random() < cfg.loss_rate:
                st.dropped_random += 1
                continue
            # 2) 미러 포화 tail-drop (와이어 길이 기준 + 프리앰블/IFG 20B)
            if sat is not None and not sat.accept(ts, orig + 20):
                st.dropped_saturation += 1
                continue
            # 3) 다중 탭 중복
            copies = 1
            if cfg.duplicate_rate > 0 and rng.random() < cfg.duplicate_rate:
                copies = 2
                st.duplicated += 1
            # 4) snaplen 절단
            out = data
            if cfg.snaplen and len(data) > cfg.snaplen:
                out = data[:cfg.snaplen]
                st.truncated += 1
            for _ in range(copies):
                kept.append((ts, out, orig))
    finally:
        reader.close()

    # 5) 타임스탬프 합침
    if cfg.coalesce_batch > 1.0:
        kept = TimestampCoalescer(cfg.coalesce_batch, rng).apply(kept)

    prev_ts = None
    with PcapWriter(dst_path, linktype=linktype,
                    snaplen=cfg.snaplen or 262144) as w:
        for ts, data, orig in kept:
            if prev_ts is not None and ts == prev_ts:
                st.coalesced_packets += 1
            prev_ts = ts
            w.write(ts, data, orig_len=orig)
            st.packets_out += 1
            st.bytes_out += len(data)
    log.info("손상 주입: %d→%d 패킷 (손실 %.2f%%, 중복 %d, 절단 %d, 합침비 %.1f%%)",
             st.packets_in, st.packets_out, st.loss_rate_actual * 100,
             st.duplicated, st.truncated, st.coalescing_ratio * 100)
    return st


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    import os
    import tempfile
    from .pcapio import GtpuFramer
    from .transport.gtpu import build_ipv4_udp, encode, MSG_GPDU

    ok = True
    with tempfile.TemporaryDirectory(prefix="ranemu-imp-") as td:
        # 기준 pcap: 10 ms 간격 2000패킷 (1400B inner) = 약 1.12 Gb/s 순간율
        src = os.path.join(td, "truth.pcap")
        fr = GtpuFramer("10.1.16.52", "10.1.16.60")
        inner = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434, bytes(1372))
        n = 2000
        gap = 1e-4                                  # 10 kpps → 약 112 Mb/s
        with PcapWriter(src) as w:
            for i in range(n):
                w.write(1700000000.0 + i * gap, fr.frame(encode(MSG_GPDU, 1, inner, qfi=1)))

        # (1) 무손상은 그대로 통과해야 한다
        dst = os.path.join(td, "id.pcap")
        st = apply_to_pcap(src, dst, ImpairmentConfig())
        if st.packets_out != n or st.dropped_random or st.dropped_saturation:
            ok = False
            print(f"  [IMPAIR] 무손상 패스스루 실패: {st.as_dict()}")
        elif verbose:
            print(f"  [IMPAIR] 무손상 패스스루 {st.packets_out}/{n} OK")

        # (2) 균등 손실률이 설정값에 근접해야 한다
        for target in (0.05, 0.20, 0.50):
            d = os.path.join(td, f"l{target}.pcap")
            st = apply_to_pcap(src, d, ImpairmentConfig(loss_rate=target, seed=7))
            actual = st.loss_rate_actual
            if abs(actual - target) > 0.03:
                ok = False
                print(f"  [IMPAIR] 손실률 목표 {target} → 실제 {actual:.3f}")
        if verbose and ok:
            print("  [IMPAIR] 균등 손실률 5/20/50% 재현 OK")

        # (3) 포화 모델: 용량을 낮추면 손실이 늘고, 충분히 높으면 손실이 없어야 한다
        d_hi = os.path.join(td, "sat_hi.pcap")
        st_hi = apply_to_pcap(src, d_hi, ImpairmentConfig(capacity_mbps=1000.0))
        d_lo = os.path.join(td, "sat_lo.pcap")
        st_lo = apply_to_pcap(src, d_lo, ImpairmentConfig(capacity_mbps=50.0))
        if st_hi.dropped_saturation != 0:
            ok = False
            print(f"  [IMPAIR] 여유 용량에서 손실 발생: {st_hi.dropped_saturation}")
        if st_lo.dropped_saturation <= 0:
            ok = False
            print("  [IMPAIR] 용량 부족인데 손실 없음")
        elif verbose:
            print(f"  [IMPAIR] 포화 tail-drop: 1000Mb/s→0, 50Mb/s→"
                  f"{st_lo.loss_rate_actual*100:.1f}% 손실 OK")
        # 포화 손실은 용량이 낮을수록 단조 증가해야 한다
        prev = -1.0
        for cap in (200.0, 100.0, 50.0, 25.0):
            s = apply_to_pcap(src, os.path.join(td, f"s{cap}.pcap"),
                              ImpairmentConfig(capacity_mbps=cap))
            if s.loss_rate_actual < prev - 1e-9:
                ok = False
                print(f"  [IMPAIR] 포화 손실 단조성 위반 @{cap}Mb/s")
            prev = s.loss_rate_actual

        # (4) 타임스탬프 합침: 합침비가 올라가야 한다
        d = os.path.join(td, "co.pcap")
        st_c = apply_to_pcap(src, d, ImpairmentConfig(coalesce_batch=4.0, seed=3))
        if st_c.coalescing_ratio < 0.3:
            ok = False
            print(f"  [IMPAIR] 합침비가 낮음: {st_c.coalescing_ratio:.3f}")
        elif verbose:
            print(f"  [IMPAIR] 타임스탬프 합침(평균배치 4) → 합침비 "
                  f"{st_c.coalescing_ratio*100:.0f}% OK")
        # 합침은 패킷을 잃거나 만들지 않는다
        if st_c.packets_out != n:
            ok = False
            print(f"  [IMPAIR] 합침이 패킷 수를 바꿈: {st_c.packets_out} != {n}")

        # (5) 중복
        d = os.path.join(td, "dup.pcap")
        st_d = apply_to_pcap(src, d, ImpairmentConfig(duplicate_rate=0.3, seed=5))
        ratio = st_d.packets_out / n
        if not (1.25 <= ratio <= 1.35):
            ok = False
            print(f"  [IMPAIR] 중복 비율 이상: {ratio:.3f}")
        elif verbose:
            print(f"  [IMPAIR] 다중탭 중복 30% → 패킷 {ratio:.2f}배 OK")

        # (6) snaplen 절단: incl_len 이 줄고 orig_len 은 보존
        d = os.path.join(td, "snap.pcap")
        st_s = apply_to_pcap(src, d, ImpairmentConfig(snaplen=128))
        first = next(iter(PcapReader(d)))
        if len(first[1]) != 128 or first[2] <= 128:
            ok = False
            print(f"  [IMPAIR] 절단 실패: incl={len(first[1])} orig={first[2]}")
        elif verbose:
            print(f"  [IMPAIR] snaplen 128 절단(원본길이 {first[2]} 보존) OK")

        # (7) 결정성: 같은 시드는 같은 결과
        a = apply_to_pcap(src, os.path.join(td, "r1.pcap"),
                          ImpairmentConfig(loss_rate=0.1, seed=99))
        b = apply_to_pcap(src, os.path.join(td, "r2.pcap"),
                          ImpairmentConfig(loss_rate=0.1, seed=99))
        if a.packets_out != b.packets_out:
            ok = False
            print("  [IMPAIR] 같은 시드에서 결과가 다름(비결정적)")
        elif verbose:
            print("  [IMPAIR] 시드 결정성 OK")
    return ok


if __name__ == "__main__":
    print("IMPAIR selftest:", "PASS" if selftest(verbose=True) else "FAIL")
