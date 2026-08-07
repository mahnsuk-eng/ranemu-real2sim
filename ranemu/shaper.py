#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.shaper — 무선 링크 특성을 실제 패킷 전송에 반영하는 계층.

radio.py 가 산출한 LinkBudget(속도/지연/지터/손실)을 여기서 **실제 송신 시각과
패킷 폐기**로 바꾼다. 그 결과 코어 미러에 잡히는 GTP-U 트래픽이 해당 feature 의
물리적 성질을 그대로 갖게 된다.

    LinkBudget(dl 34Mbps, owd 240ms, jitter 2.4ms, loss 1e-3)
        │
        ├─ TokenBucket   → 34Mbps 를 넘지 않게 송신 시각 결정
        ├─ DelayLine     → 240ms 뒤에야 도착하도록 보류
        ├─ LossModel     → 1e-3 확률로 폐기
        └─ Interrupter   → NTN LEO 셀전환/LTM 핸드오버 구간에는 전송 중단
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


#: 토큰 비교 허용오차(비트). 부동소수점 반올림으로 `next_time` 이 돌려준 시각에
#: 토큰이 극미하게 모자라 `allow` 가 실패하면, 시간이 전진하지 않아 송신 루프가
#: 무한정 회전한다(실측으로 확인된 결함). 1e-6 비트는 물리적으로 무의미한 양이다.
_TOKEN_EPS = 1e-6


class TokenBucket:
    """평균 rate(bps) 를 지키되 burst 만큼의 순간 초과를 허용."""

    __slots__ = ("rate_bps", "burst_bits", "_tokens", "_last")

    def __init__(self, rate_bps: float, burst_seconds: float = 0.05,
                 now: float = 0.0):
        self.rate_bps = max(float(rate_bps), 0.0)
        self.burst_bits = max(self.rate_bps * burst_seconds, 12_000.0)  # 최소 1.5KB
        self._tokens = self.burst_bits
        self._last = now

    def _refill(self, now: float) -> None:
        if now > self._last:
            self._tokens = min(self.burst_bits,
                               self._tokens + (now - self._last) * self.rate_bps)
            self._last = now

    def allow(self, size_bytes: int, now: float) -> bool:
        """지금 이 크기를 보낼 수 있으면 True(토큰 차감)."""
        if self.rate_bps <= 0:
            return False
        self._refill(now)
        need = size_bytes * 8
        if self._tokens + _TOKEN_EPS >= need:
            self._tokens = max(0.0, self._tokens - need)
            return True
        return False

    def next_time(self, size_bytes: int, now: float) -> float:
        """이 크기를 보낼 수 있게 되는 가장 이른 시각.

        반환 시각에는 `allow()` 가 반드시 성공하도록 미세 여유를 더한다.
        """
        if self.rate_bps <= 0:
            return float("inf")
        self._refill(now)
        need = size_bytes * 8
        if self._tokens + _TOKEN_EPS >= need:
            return now
        deficit = need - self._tokens
        return now + deficit / self.rate_bps + _TOKEN_EPS / self.rate_bps

    def set_rate(self, rate_bps: float) -> None:
        self.rate_bps = max(float(rate_bps), 0.0)
        self.burst_bits = max(self.rate_bps * 0.05, 12_000.0)


class DelayLine:
    """전파+스케줄링 지연과 지터를 재현하는 보류 큐(시각 오름차순)."""

    __slots__ = ("base_ms", "jitter_ms", "_queue", "_rng", "_seq")

    def __init__(self, base_ms: float, jitter_ms: float = 0.0,
                 rng: Optional[random.Random] = None):
        self.base_ms = float(base_ms)
        self.jitter_ms = float(jitter_ms)
        self._queue: List[Tuple[float, int, Any]] = []
        self._rng = rng or random.Random(0)
        self._seq = 0

    def push(self, item: Any, now: float) -> float:
        """항목을 넣고 도착 예정 시각을 반환."""
        jitter = self._rng.uniform(-self.jitter_ms, self.jitter_ms) if self.jitter_ms else 0.0
        due = now + max(0.0, (self.base_ms + jitter) / 1000.0)
        self._seq += 1
        # 삽입 정렬(항목 수가 적어 충분히 빠름)
        entry = (due, self._seq, item)
        lo, hi = 0, len(self._queue)
        while lo < hi:
            mid = (lo + hi) // 2
            if self._queue[mid][0] <= due:
                lo = mid + 1
            else:
                hi = mid
        self._queue.insert(lo, entry)
        return due

    def pop_ready(self, now: float) -> List[Any]:
        """도착 시각이 지난 항목들을 꺼낸다."""
        out: List[Any] = []
        while self._queue and self._queue[0][0] <= now:
            out.append(self._queue.pop(0)[2])
        return out

    def next_due(self) -> Optional[float]:
        return self._queue[0][0] if self._queue else None

    def __len__(self) -> int:
        return len(self._queue)


class LossModel:
    """무작위 손실 + 선택적 버스트 손실(Gilbert-Elliott 단순형)."""

    __slots__ = ("rate", "_rng", "burst_len", "_in_burst")

    def __init__(self, rate: float, rng: Optional[random.Random] = None,
                 burst_len: int = 1):
        self.rate = max(0.0, min(1.0, float(rate)))
        self._rng = rng or random.Random(0)
        self.burst_len = max(1, int(burst_len))
        self._in_burst = 0

    def drop(self) -> bool:
        if self.rate <= 0:
            return False
        if self._in_burst > 0:
            self._in_burst -= 1
            return True
        if self._rng.random() < self.rate:
            self._in_burst = self.burst_len - 1
            return True
        return False


class Interrupter:
    """주기적 단절(핸드오버/셀전환/DTX)을 재현한다.

    NTN LEO 는 위성 이동으로 수십 초마다, LTM 은 설정 주기마다 짧게 끊긴다.
    NES 는 셀 DTX 로 반복적으로 꺼진다.
    """

    __slots__ = ("period_s", "duration_s", "enabled", "_offset")

    def __init__(self, period_s: Optional[float], duration_ms: float,
                 offset_s: float = 0.0):
        self.period_s = float(period_s) if period_s else None
        self.duration_s = max(0.0, float(duration_ms) / 1000.0)
        self.enabled = bool(self.period_s and self.duration_s > 0)
        self._offset = offset_s

    def blocked(self, t: float) -> bool:
        if not self.enabled or not self.period_s:
            return False
        phase = (t + self._offset) % self.period_s
        return phase < self.duration_s

    def next_change(self, t: float) -> Optional[float]:
        if not self.enabled or not self.period_s:
            return None
        phase = (t + self._offset) % self.period_s
        return t + (self.duration_s - phase if phase < self.duration_s
                    else self.period_s - phase)


@dataclass
class ShaperStats:
    sent_packets: int = 0
    sent_bytes: int = 0
    dropped_loss: int = 0
    dropped_interrupt: int = 0
    delayed_packets: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {"sent_packets": self.sent_packets, "sent_bytes": self.sent_bytes,
                "dropped_loss": self.dropped_loss,
                "dropped_interrupt": self.dropped_interrupt,
                "delayed_packets": self.delayed_packets}


class LinkShaper:
    """한 단말의 한 방향(UL 또는 DL) 링크를 대표하는 쉐이퍼."""

    def __init__(self, rate_mbps: float, owd_ms: float, jitter_ms: float,
                 loss_rate: float, *, rng: Optional[random.Random] = None,
                 interrupt_period_s: Optional[float] = None,
                 interrupt_ms: float = 0.0, burst_seconds: float = 0.05,
                 now: float = 0.0):
        self.rng = rng or random.Random(0)
        self.bucket = TokenBucket(rate_mbps * 1e6, burst_seconds, now=now)
        self.delay = DelayLine(owd_ms, jitter_ms, rng=self.rng)
        self.loss = LossModel(loss_rate, rng=self.rng)
        self.interrupter = Interrupter(interrupt_period_s, interrupt_ms,
                                       offset_s=self.rng.uniform(0, 1))
        self.stats = ShaperStats()

    @property
    def rate_mbps(self) -> float:
        return self.bucket.rate_bps / 1e6

    def retune(self, *, rate_mbps: Optional[float] = None,
               owd_ms: Optional[float] = None, jitter_ms: Optional[float] = None,
               loss_rate: Optional[float] = None,
               interrupt_period_s: Optional[float] = None,
               interrupt_ms: Optional[float] = None) -> None:
        """운영 중 링크 조건을 바꾼다 — 시나리오의 phase 전환용.

        왜 필요한가: 서비스 시나리오는 "부하를 올린다", "무선을 열화시킨다",
        "이동성 중단을 넣는다" 같은 **시간에 따라 변하는 조건** 을 표현해야 한다.
        쉐이퍼를 새로 만들면 토큰버킷 잔량과 지연선 안의 패킷이 사라져 전환 순간에
        인위적인 불연속이 생기므로, 상태를 보존한 채 파라미터만 갈아끼운다.

        `None` 인 항목은 손대지 않는다.
        """
        if rate_mbps is not None:
            self.bucket.set_rate(max(0.0, float(rate_mbps)) * 1e6)
        if owd_ms is not None:
            self.delay.base_ms = max(0.0, float(owd_ms))
        if jitter_ms is not None:
            self.delay.jitter_ms = max(0.0, float(jitter_ms))
        if loss_rate is not None:
            self.loss.rate = max(0.0, min(1.0, float(loss_rate)))
        if interrupt_period_s is not None or interrupt_ms is not None:
            # 중단기는 주기/지속을 함께 봐야 의미가 있으므로 한쪽만 와도 재구성한다.
            p = (interrupt_period_s if interrupt_period_s is not None
                 else self.interrupter.period_s)
            d = (interrupt_ms if interrupt_ms is not None
                 else self.interrupter.duration_s * 1000.0)
            self.interrupter = Interrupter(p, d, offset_s=self.rng.uniform(0, 1))

    def try_send(self, size_bytes: int, now: float) -> Tuple[bool, str]:
        """지금 이 패킷을 링크에 태울 수 있는가?

        → (가능여부, 사유). 사유: ok | rate | interrupt | loss
        """
        if self.interrupter.blocked(now):
            self.stats.dropped_interrupt += 1
            return False, "interrupt"
        if not self.bucket.allow(size_bytes, now):
            return False, "rate"
        if self.loss.drop():
            self.stats.dropped_loss += 1
            return False, "loss"
        self.stats.sent_packets += 1
        self.stats.sent_bytes += size_bytes
        return True, "ok"

    def next_send_time(self, size_bytes: int, now: float) -> float:
        t = self.bucket.next_time(size_bytes, now)
        if self.interrupter.blocked(t):
            nxt = self.interrupter.next_change(t)
            if nxt is not None:
                t = max(t, nxt)
        return t

    def deliver_later(self, item: Any, now: float) -> float:
        """지연선에 넣어 나중에 도착시킨다(하향 경로 재현)."""
        self.stats.delayed_packets += 1
        return self.delay.push(item, now)

    def ready(self, now: float) -> List[Any]:
        return self.delay.pop_ready(now)


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    ok = True

    # (1) 토큰버킷이 평균 속도를 지키는가 (10 Mbps, 1500B 패킷)
    tb = TokenBucket(10e6, burst_seconds=0.01, now=0.0)
    t, sent = 0.0, 0
    for _ in range(2000):
        t = tb.next_time(1500, t)
        if tb.allow(1500, t):
            sent += 1
    measured = sent * 1500 * 8 / t if t > 0 else 0
    if not (9.0e6 <= measured <= 11.0e6):
        ok = False
        print(f"  [SHAPER] 토큰버킷 실측 {measured/1e6:.2f} Mbps ∉ [9,11]")
    elif verbose:
        print(f"  [SHAPER] 토큰버킷 10Mbps → 실측 {measured/1e6:.2f} Mbps OK")

    # (2) 속도가 0 이면 아무것도 못 보냄
    if TokenBucket(0).allow(100, 0.0):
        ok = False
        print("  [SHAPER] rate=0 인데 전송 허용")

    # (3) 지연선: base 240ms 는 그 전에 나오면 안 됨
    dl = DelayLine(240.0, 0.0, rng=random.Random(1))
    dl.push("pkt", 0.0)
    if dl.pop_ready(0.2):
        ok = False
        print("  [SHAPER] 지연선이 너무 일찍 방출")
    got = dl.pop_ready(0.241)
    if got != ["pkt"]:
        ok = False
        print(f"  [SHAPER] 지연선 방출 실패: {got}")
    elif verbose:
        print("  [SHAPER] 지연선 240ms OK")

    # (4) 지연선 순서 보존(지터 0)
    dl2 = DelayLine(10.0, 0.0, rng=random.Random(2))
    for i in range(5):
        dl2.push(i, i * 0.001)
    out = dl2.pop_ready(1.0)
    if out != [0, 1, 2, 3, 4]:
        ok = False
        print(f"  [SHAPER] 지연선 순서 어긋남: {out}")

    # (5) 지터가 범위 안인가
    dl3 = DelayLine(100.0, 10.0, rng=random.Random(3))
    dues = [dl3.push(i, 0.0) - 0.0 for i in range(200)]
    if not all(0.089 <= d <= 0.111 for d in dues):
        ok = False
        print(f"  [SHAPER] 지터 범위 이탈: {min(dues):.4f}~{max(dues):.4f}")
    elif verbose:
        print(f"  [SHAPER] 지터 ±10ms 범위 {min(dues)*1000:.1f}~{max(dues)*1000:.1f}ms OK")

    # (6) 손실률
    lm = LossModel(0.1, rng=random.Random(4))
    drops = sum(1 for _ in range(20000) if lm.drop())
    if not (0.08 <= drops / 20000 <= 0.12):
        ok = False
        print(f"  [SHAPER] 손실률 실측 {drops/20000:.3f} ∉ [0.08,0.12]")
    elif verbose:
        print(f"  [SHAPER] 손실률 10% → 실측 {drops/20000*100:.1f}% OK")
    if LossModel(0.0).drop():
        ok = False
        print("  [SHAPER] 손실률 0 인데 폐기")

    # (7) 단절: 주기 10s, 지속 50ms
    it = Interrupter(10.0, 50.0, offset_s=0.0)
    if not it.blocked(0.01) or it.blocked(0.5):
        ok = False
        print("  [SHAPER] 단절 구간 판정 오류")
    if not it.blocked(10.02) or it.blocked(5.0):
        ok = False
        print("  [SHAPER] 단절 주기성 오류")
    elif verbose:
        print("  [SHAPER] 주기적 단절(10s마다 50ms) OK")
    if Interrupter(None, 0).blocked(1.0):
        ok = False
        print("  [SHAPER] 비활성 단절기가 차단함")

    # (7b) next_time 이 돌려준 시각에는 allow 가 반드시 성공해야 한다
    #      (부동소수점 경계에서 실패하면 송신 루프가 전진하지 못한다)
    tb2 = TokenBucket(34e6, burst_seconds=0.05, now=0.0)
    t2 = 0.0
    for _ in range(5000):
        t2 = tb2.next_time(1400, t2)
        if not tb2.allow(1400, t2):
            ok = False
            print("  [SHAPER] next_time 시각에 allow 실패 — 무한루프 위험")
            break
    else:
        if verbose:
            print("  [SHAPER] next_time→allow 전진성 5000회 OK")

    # (8) LinkShaper 통합: RedCap 급 34Mbps 에서 실제 달성률
    sh = LinkShaper(34.0, owd_ms=1.0, jitter_ms=0.1, loss_rate=0.0,
                    rng=random.Random(5))
    t, n, guard = 0.0, 0, 0
    while t < 1.0:
        guard += 1
        if guard > 200000:
            ok = False
            print("  [SHAPER] LinkShaper 루프가 전진하지 않음")
            break
        t = sh.next_send_time(1400, t)
        if t >= 1.0:
            break
        good, _why = sh.try_send(1400, t)
        if good:
            n += 1
    mbps = n * 1400 * 8 / 1e6
    if not (30.0 <= mbps <= 38.0):
        ok = False
        print(f"  [SHAPER] LinkShaper 34Mbps → 실측 {mbps:.1f} Mbps")
    elif verbose:
        print(f"  [SHAPER] LinkShaper 34Mbps → 1초간 {n}패킷 = {mbps:.1f} Mbps OK")

    # (9) 단절 중에는 사유가 interrupt 여야 함
    sh2 = LinkShaper(100.0, 1.0, 0.0, 0.0, rng=random.Random(6),
                     interrupt_period_s=1.0, interrupt_ms=1000.0)
    sh2.interrupter._offset = 0.0
    good, why = sh2.try_send(100, 0.1)
    if good or why != "interrupt":
        ok = False
        print(f"  [SHAPER] 단절 중 전송 허용됨: {good},{why}")
    elif verbose:
        print("  [SHAPER] 단절 중 전송 차단 OK")

    # (10) 통계 집계
    if sh.stats.sent_packets != n:
        ok = False
        print("  [SHAPER] 통계 카운터 불일치")
    return ok


if __name__ == "__main__":
    print("SHAPER selftest:", "PASS" if selftest(verbose=True) else "FAIL")
