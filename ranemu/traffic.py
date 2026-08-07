#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.traffic — 단말이 만들 트래픽 패턴 생성기.

feature 가 결정한 TrafficHints(패턴/주기/크기/버스트)를 실제 **전송 이벤트 시각**으로
바꾼다. 생성기는 시각만 알려주고, 실제 송신 여부는 shaper 가 결정한다.

패턴
====
    fullbuffer : 링크가 허용하는 만큼 계속 보낸다(스루풋 상한 측정용)
    periodic   : 고정 주기(URLLC 제어루프, 측위 보고)
    burst      : 프레임 주기마다 N개 패킷 몰아서(XR/비디오)
    poisson    : 지수분포 도착간격(웹/일반 데이터)
    sporadic   : 아주 드물게 한 개(mMTC, 앰비언트 IoT)
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class TrafficEvent:
    """한 번의 송신 기회."""
    time: float
    size: int
    #: 같은 시각에 묶여 나가는 버스트 내 순번
    burst_index: int = 0
    kind: str = "data"


class TrafficGenerator:
    """단말 하나의 상향 트래픽 스케줄러.

    `next_events(now)` 를 반복 호출하면 그 시점까지 보내야 할 이벤트를 돌려준다.
    """

    def __init__(self, pattern: str = "fullbuffer", *, packet_size: int = 1400,
                 rate_mbps: float = 10.0, period_ms: Optional[float] = None,
                 burst_packets: int = 1, active_ratio: float = 1.0,
                 rng: Optional[random.Random] = None, start: float = 0.0):
        self.pattern = pattern
        self.packet_size = max(1, int(packet_size))
        self.rate_mbps = max(0.0, float(rate_mbps))
        self.period_ms = period_ms
        self.burst_packets = max(1, int(burst_packets))
        self.active_ratio = max(0.0, min(1.0, float(active_ratio)))
        self.rng = rng or random.Random(0)
        self._next = start
        self._seq = 0
        self.generated = 0
        self.generated_bytes = 0

        # fullbuffer/poisson 은 목표 속도에서 평균 간격을 유도
        pps = (self.rate_mbps * 1e6) / (self.packet_size * 8) if self.packet_size else 0.0
        self._mean_gap = (1.0 / pps) if pps > 0 else float("inf")

    # ── 다음 이벤트 시각 ──────────────────────────────────────────────────
    def _advance(self) -> float:
        if self.pattern == "periodic":
            gap = (self.period_ms or 1000.0) / 1000.0
        elif self.pattern == "burst":
            gap = (self.period_ms or 16.67) / 1000.0
        elif self.pattern == "poisson":
            gap = self.rng.expovariate(1.0 / self._mean_gap) if self._mean_gap < math.inf \
                else float("inf")
        elif self.pattern == "sporadic":
            base = (self.period_ms or 60000.0) / 1000.0
            # 산발성: 주기 주변에서 크게 흔들린다
            gap = base * self.rng.uniform(0.5, 1.5)
        else:                                    # fullbuffer
            gap = self._mean_gap
        if not math.isfinite(gap):
            gap = 1.0
        return self._next + max(gap, 1e-9)

    def next_events(self, now: float, max_events: int = 256) -> List[TrafficEvent]:
        """now 시점까지 발생했어야 할 송신 이벤트 목록."""
        out: List[TrafficEvent] = []
        while self._next <= now and len(out) < max_events:
            n = self.burst_packets if self.pattern == "burst" else 1
            # active_ratio 가 1 미만이면 이번 기회를 확률적으로 건너뛴다
            if self.active_ratio >= 1.0 or self.rng.random() < self.active_ratio:
                for i in range(n):
                    out.append(TrafficEvent(time=self._next, size=self.packet_size,
                                            burst_index=i))
                    self.generated += 1
                    self.generated_bytes += self.packet_size
            self._next = self._advance()
        return out

    def next_time(self) -> float:
        return self._next

    def set_active_ratio(self, ratio: float) -> None:
        """활성 비율을 바꾼다 — phase 전환에서 부하를 올리고 내리는 손잡이."""
        self.active_ratio = max(0.0, min(1.0, float(ratio)))

    def set_rate(self, rate_mbps: float) -> None:
        """링크 상황이 바뀌면 목표 속도를 갱신(fullbuffer/poisson 에 반영)."""
        self.rate_mbps = max(0.0, float(rate_mbps))
        pps = (self.rate_mbps * 1e6) / (self.packet_size * 8) if self.packet_size else 0.0
        self._mean_gap = (1.0 / pps) if pps > 0 else float("inf")

    def stats(self) -> Dict[str, Any]:
        return {"pattern": self.pattern, "generated": self.generated,
                "generated_bytes": self.generated_bytes,
                "packet_size": self.packet_size, "rate_mbps": self.rate_mbps}


def from_hints(hints: Any, *, default_rate_mbps: float, default_size: int,
               rng: Optional[random.Random] = None,
               start: float = 0.0) -> TrafficGenerator:
    """features.TrafficHints → TrafficGenerator."""
    size = getattr(hints, "packet_size", None) or default_size
    rate = getattr(hints, "offered_ul_mbps", None)
    if rate is None:
        rate = default_rate_mbps
    return TrafficGenerator(
        pattern=getattr(hints, "pattern", "fullbuffer") or "fullbuffer",
        packet_size=size, rate_mbps=rate,
        period_ms=getattr(hints, "period_ms", None),
        burst_packets=getattr(hints, "burst_packets", 1) or 1,
        active_ratio=getattr(hints, "active_ratio", 1.0),
        rng=rng, start=start)


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    ok = True

    # (1) fullbuffer 가 목표 속도에 맞는 패킷수를 만드는가
    g = TrafficGenerator("fullbuffer", packet_size=1400, rate_mbps=10.0,
                         rng=random.Random(1))
    n = len(g.next_events(1.0, max_events=100000))
    mbps = n * 1400 * 8 / 1e6
    if not (9.0 <= mbps <= 11.0):
        ok = False
        print(f"  [TRAFFIC] fullbuffer 10Mbps → {mbps:.2f} Mbps")
    elif verbose:
        print(f"  [TRAFFIC] fullbuffer 10Mbps → 1초 {n}패킷 = {mbps:.2f} Mbps OK")

    # (2) periodic 주기 정확도 (1ms)
    g = TrafficGenerator("periodic", packet_size=256, period_ms=1.0, rng=random.Random(2))
    ev = g.next_events(0.1, max_events=100000)
    if not (95 <= len(ev) <= 105):
        ok = False
        print(f"  [TRAFFIC] periodic 1ms → 100ms 동안 {len(ev)}개")
    elif verbose:
        print(f"  [TRAFFIC] periodic 1ms → 100ms 동안 {len(ev)}개 OK")
    gaps = [ev[i + 1].time - ev[i].time for i in range(min(10, len(ev) - 1))]
    if gaps and max(abs(gp - 0.001) for gp in gaps) > 1e-9:
        ok = False
        print(f"  [TRAFFIC] periodic 간격 오차: {gaps[:3]}")

    # (3) burst: 프레임당 N개가 같은 시각에
    g = TrafficGenerator("burst", packet_size=1400, period_ms=1000 / 60,
                         burst_packets=40, rng=random.Random(3))
    ev = g.next_events(1.0, max_events=100000)
    frames = len({round(e.time, 6) for e in ev})
    if not (55 <= frames <= 62):
        ok = False
        print(f"  [TRAFFIC] burst 60fps → 프레임 {frames}개")
    if ev and len(ev) != frames * 40:
        ok = False
        print(f"  [TRAFFIC] burst 패킷수 {len(ev)} != {frames}*40")
    elif verbose:
        print(f"  [TRAFFIC] burst 60fps × 40패킷 → {frames}프레임 {len(ev)}패킷 OK")

    # (4) sporadic: 아주 드물게
    g = TrafficGenerator("sporadic", packet_size=100, period_ms=60000,
                         active_ratio=1.0, rng=random.Random(4))
    ev = g.next_events(300.0, max_events=100000)
    if not (2 <= len(ev) <= 12):
        ok = False
        print(f"  [TRAFFIC] sporadic 60초주기 → 300초에 {len(ev)}개")
    elif verbose:
        print(f"  [TRAFFIC] sporadic 60초주기 → 300초에 {len(ev)}개 OK")

    # (5) poisson 평균 속도
    g = TrafficGenerator("poisson", packet_size=1000, rate_mbps=8.0, rng=random.Random(5))
    ev = g.next_events(10.0, max_events=1000000)
    mbps = len(ev) * 1000 * 8 / 1e6 / 10.0
    if not (6.5 <= mbps <= 9.5):
        ok = False
        print(f"  [TRAFFIC] poisson 8Mbps → 실측 {mbps:.2f} Mbps")
    elif verbose:
        print(f"  [TRAFFIC] poisson 8Mbps → 실측 {mbps:.2f} Mbps OK")

    # (6) active_ratio 가 실제로 줄이는가
    g_full = TrafficGenerator("periodic", period_ms=10, active_ratio=1.0,
                              rng=random.Random(6))
    g_low = TrafficGenerator("periodic", period_ms=10, active_ratio=0.1,
                             rng=random.Random(6))
    a = len(g_full.next_events(10.0, max_events=100000))
    b = len(g_low.next_events(10.0, max_events=100000))
    if not (b < a * 0.3):
        ok = False
        print(f"  [TRAFFIC] active_ratio 0.1 이 반영되지 않음: {a} vs {b}")
    elif verbose:
        print(f"  [TRAFFIC] active_ratio 1.0→{a}개, 0.1→{b}개 OK")

    # (7) 시간이 전진하지 않으면 이벤트도 없어야(무한루프 방지)
    g = TrafficGenerator("fullbuffer", rate_mbps=100.0, rng=random.Random(7))
    g.next_events(0.001)
    before = g.generated
    g.next_events(0.001)
    if g.generated != before:
        ok = False
        print("  [TRAFFIC] 같은 시각 재호출이 이벤트를 중복 생성")

    # (8) max_events 상한이 지켜지는가
    g = TrafficGenerator("fullbuffer", rate_mbps=1000.0, packet_size=100,
                         rng=random.Random(8))
    if len(g.next_events(10.0, max_events=50)) != 50:
        ok = False
        print("  [TRAFFIC] max_events 상한 미준수")

    # (9) rate 0 이면 사실상 생성 없음
    g = TrafficGenerator("fullbuffer", rate_mbps=0.0, rng=random.Random(9))
    if len(g.next_events(1.0)) > 2:
        ok = False
        print("  [TRAFFIC] rate=0 인데 대량 생성")

    # (10) features.TrafficHints 연동
    from .features import build_profile
    xr = build_profile(["xr"], params={"xr": {"fps": 90}})
    gen = from_hints(xr["traffic"], default_rate_mbps=10.0, default_size=1400,
                     rng=random.Random(10))
    if gen.pattern != "burst" or abs((gen.period_ms or 0) - 1000 / 90) > 0.01:
        ok = False
        print(f"  [TRAFFIC] XR hints 연동 실패: {gen.pattern}/{gen.period_ms}")
    elif verbose:
        print(f"  [TRAFFIC] XR hints → burst {gen.period_ms:.2f}ms "
              f"{gen.burst_packets}패킷 OK")

    mm = build_profile(["mmtc"])
    gen2 = from_hints(mm["traffic"], default_rate_mbps=10.0, default_size=1400,
                      rng=random.Random(11))
    if gen2.pattern != "sporadic" or gen2.packet_size != 100:
        ok = False
        print(f"  [TRAFFIC] mMTC hints 연동 실패: {gen2.pattern}/{gen2.packet_size}")
    elif verbose:
        print(f"  [TRAFFIC] mMTC hints → sporadic {gen2.packet_size}B OK")
    return ok


if __name__ == "__main__":
    print("TRAFFIC selftest:", "PASS" if selftest(verbose=True) else "FAIL")
