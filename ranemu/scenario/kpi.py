#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.kpi — 3GPP-정합 KPI 추정기 (설계 §4).

무엇이 '3GPP-정합' 인가
=======================
- **Reliability = Pr[delivered ∧ delay ≤ PDB]** (TS 22.261 §3.1). raw loss 가 아니다 —
  늦게 온 패킷은 도착했어도 실패다. 추정은 Clopper–Pearson 정확 구간으로 게이팅한다:
  관측 성공률이 아니라 **하한이 목표를 넘어야** PASS 다.
- **지연 quantile** 은 순서통계량 기반 무분포 CI. 분포 가정이 없으므로 코어의 지연
  분포가 어떤 모양이든 유효하다. 표본 게이트 n·(1−p) ≥ 10 미달이면 추정 자체를
  거부한다(INCONCLUSIVE) — p99 를 표본 500개로 말하는 일을 구조적으로 막는다.
- **Survival/availability (TS 22.104)** 는 falsify 전용이다: 짧은 런으로 고가용성을
  '입증' 할 수 없으므로 위반의 통계적 입증(FAIL)만 낸다.
- **planner**: 실행 **전에** 필요 표본을 계산해 "이 런에서는 이 target 이
  INCONCLUSIVE 로 예정되어 있다" 를 미리 경고한다 — honest by construction.

독립성 경고(정직한 한계): CP 구간은 i.i.d. 베르누이 가정이다. 버스트 상관 실패에서
CI 는 낙관적일 수 있다. 대응으로 run-length 통계를 verdict 에 병기하고(stamp.py),
버스트성 자체는 survival KPI 가 직접 포착한다. 상관 구조에 대한 유효 표본수 보정은
하지 않는다 — 판정 의미는 "i.i.d. 가정 하의 보증" 으로 한정 진술한다.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .stats import (beta_ppf, binom_cdf, clopper_pearson_lower,
                    clopper_pearson_upper, newcombe_diff_ci, percentile,
                    required_samples)
from .stamp import LogHistogram

#: quantile 표본 게이트: 꼬리쪽 기대 표본 n·(1−p) 의 최소값 (§4.1)
QUANTILE_TAIL_MIN = 10


# ─────────────────────────────────────────────────────────────────────────────
# §4.1 지연 quantile — 순서통계량 rank CI
# ─────────────────────────────────────────────────────────────────────────────
def quantile_ranks(n: int, p: float, conf: float = 0.95) -> Tuple[int, int]:
    """분위 p 의 무분포 CI 랭크 (1-기반, 하한/상한 각각 단측 수준 conf).

    상한 랭크 r_u = min{r : BinomCDF(r−1; n, p) ≥ conf} — P[Q_p ≤ d_(r_u)] ≥ conf.
    하한 랭크 r_l = max{r : BinomCDF(r−1; n, p) ≤ 1−conf} — P[d_(r_l) ≤ Q_p] ≥ conf.
    CDF 가 r 에 단조증가이므로 이분탐색. 범위를 벗어나면 [1, n] 으로 클램프하되,
    클램프된 상한은 보증 수준이 conf 에 못 미칠 수 있다 — 호출측 게이트가 걸러낸다.
    """
    if n <= 0:
        return 1, 1
    # r_u: 최소 r with cdf(r-1) >= conf
    lo, hi = 1, n
    while lo < hi:
        mid = (lo + hi) // 2
        if binom_cdf(mid - 1, n, p) >= conf:
            hi = mid
        else:
            lo = mid + 1
    r_u = lo if binom_cdf(lo - 1, n, p) >= conf else n
    # r_l: 최대 r with cdf(r-1) <= 1-conf
    lo, hi = 1, n
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if binom_cdf(mid - 1, n, p) <= 1.0 - conf:
            lo = mid
        else:
            hi = mid - 1
    r_l = lo if binom_cdf(lo - 1, n, p) <= 1.0 - conf else 1
    return r_l, r_u


@dataclass
class QuantileEstimate:
    """지연 분위수 점추정 + 무분포 CI. 판정은 verdict.decide_quantile 이 한다."""
    n: int
    p: float
    confidence: float
    point: float
    lo: float                 # d_(r_l) — FAIL 게이트용
    hi: float                 # d_(r_u) — PASS 게이트용
    gate_ok: bool             # n·(1−p) ≥ QUANTILE_TAIL_MIN
    source: str = "samples"   # "samples" | "histogram"

    @property
    def n_required(self) -> int:
        """게이트를 넘기 위한 최소 표본."""
        return math.ceil(QUANTILE_TAIL_MIN / (1.0 - self.p))

    @classmethod
    def from_samples(cls, vals: Sequence[float], p: float,
                     conf: float = 0.95) -> "QuantileEstimate":
        v = sorted(vals)
        n = len(v)
        if n == 0:
            return cls(0, p, conf, float("nan"), float("nan"), float("nan"), False)
        r_l, r_u = quantile_ranks(n, p, conf)
        point = percentile(v, p)
        return cls(n, p, conf, point, v[r_l - 1], v[r_u - 1],
                   n * (1.0 - p) >= QUANTILE_TAIL_MIN, "samples")

    @classmethod
    def from_histogram(cls, hist: LogHistogram, p: float,
                       conf: float = 0.95) -> "QuantileEstimate":
        """히스토그램 경로 — bin 상단값이므로 point/hi 는 보수적(≥ 참값).

        lo(FAIL 게이트)까지 상단값을 쓰면 FAIL 방향으로 ~2.3% 과잉엄격해질 수
        있으나, 분해능이 판정 여유보다 훨씬 작고 방향이 안전측(FAIL 을 내려면
        더 확실해야 함... 이 아니라 조금 쉬워짐)이라 정직하게 source 로 표기하고
        분해능 한계를 verdict reason 에 남기는 쪽을 택한다.
        """
        n = hist.count
        if n == 0:
            return cls(0, p, conf, float("nan"), float("nan"), float("nan"),
                       False, "histogram")
        r_l, r_u = quantile_ranks(n, p, conf)
        return cls(n, p, conf, hist.quantile(p), hist.value_at_rank(r_l),
                   hist.value_at_rank(r_u),
                   n * (1.0 - p) >= QUANTILE_TAIL_MIN, "histogram")


# ─────────────────────────────────────────────────────────────────────────────
# §4.2 Reliability — Clopper–Pearson 게이트
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ReliabilityEstimate:
    """R = k/n 과 정확 단측 상·하한. n 은 검열 규칙(§3.7) 통과 후의 분모다."""
    n: int
    k: int
    confidence: float = 0.95

    @property
    def estimate(self) -> float:
        return self.k / self.n if self.n else 0.0

    @property
    def lo(self) -> float:
        return clopper_pearson_lower(self.k, self.n, self.confidence)

    @property
    def hi(self) -> float:
        return clopper_pearson_upper(self.k, self.n, self.confidence)

    def required_failure_free(self, target: float) -> int:
        return required_samples(target, self.confidence)


# ─────────────────────────────────────────────────────────────────────────────
# §4.3 Survival time / availability 스캔
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class SurvivalReport:
    """cyclic 흐름의 down 구간 스캔 결과.

    down 진입: 마지막 성공 이후 경과 > survival time. up 복귀: 다음 성공 즉시.
    availability 는 짧은 런으로 입증 불가하므로 이 보고서는 FAIL(위반 입증)의
    근거로만 쓰인다(§4.3 판정 비대칭).
    """
    events: List[Tuple[float, float]]     # (down 시작 ms, 지속 ms)
    downtime_ms: float
    t_obs_ms: float
    n_cycles: int
    n_down_cycles: int

    @property
    def availability(self) -> float:
        return 1.0 - self.downtime_ms / self.t_obs_ms if self.t_obs_ms > 0 else 0.0

    def unavailability_lower(self, conf: float = 0.95) -> float:
        """down-cycle 비율의 단측 하한 (CP). FAIL 게이트: 하한 > 1−A_target.

        i.i.d. 가정의 한계는 §4.2 와 동일하게 적용된다 — down 은 정의상
        버스트이므로 이 하한은 참고용 보수 게이트이지 정밀 추정이 아니다.
        """
        if self.n_cycles <= 0 or self.n_down_cycles <= 0:
            return 0.0
        if self.n_down_cycles >= self.n_cycles:
            return (1.0 - conf) ** (1.0 / self.n_cycles)
        return beta_ppf(1.0 - conf, self.n_down_cycles,
                        self.n_cycles - self.n_down_cycles + 1)


def survival_scan(cycles: Sequence[Tuple[float, bool]],
                  survival_time_ms: float) -> SurvivalReport:
    """(시각 ms, 성공여부) cycle 열에서 down 구간을 스캔한다.

    시작 상태는 up 으로 본다(첫 성공 전 실패 연속은 t0 를 anchor 로 계상) —
    시험 시작 전 이력을 모르므로 down 을 소급 발명하지 않는 보수적 선택이다.
    """
    if not cycles:
        return SurvivalReport([], 0.0, 0.0, 0, 0)
    cy = sorted(cycles)
    t0, t_end = cy[0][0], cy[-1][0]
    events: List[Tuple[float, float]] = []
    last_success: Optional[float] = None
    in_down = False
    down_start = 0.0
    for t, okc in cy:
        anchor = last_success if last_success is not None else t0
        if okc:
            if in_down:
                events.append((down_start, t - down_start))
                in_down = False
            last_success = t
        else:
            if not in_down and t - anchor > survival_time_ms:
                in_down = True
                down_start = anchor + survival_time_ms
    if in_down:
        events.append((down_start, t_end - down_start))
    downtime = sum(d for _, d in events)
    n_down = sum(1 for t, _ok in cy
                 if any(s <= t <= s + d for s, d in events))
    return SurvivalReport(events, downtime, t_end - t0, len(cy), n_down)


def cycles_from_failures(failure_send_ns: Sequence[int], first_ns: int,
                         last_ns: int, ti_ms: float) -> List[Tuple[float, bool]]:
    """원장의 실패 송신시각 목록 + 관측 구간에서 cycle 열을 복원한다.

    원장은 메모리 상수를 위해 실패만 목록으로 남긴다(무실패 = 메모리 0) —
    주기 TI 를 알면 성공 cycle 은 재구성 가능하다.
    """
    n = max(1, int(round((last_ns - first_ns) / (ti_ms * 1e6))) + 1)
    fails = {int(round((f - first_ns) / (ti_ms * 1e6))) for f in failure_send_ns}
    return [(i * ti_ms, i not in fails) for i in range(n)]


# ─────────────────────────────────────────────────────────────────────────────
# §4.4 PDV / §4.5 throughput
# ─────────────────────────────────────────────────────────────────────────────
def pdv_series(delays_ms: Sequence[float]) -> List[float]:
    """RFC 5481 PDV: d_i − min(d). target 은 quantile 술어를 재사용한다.

    RFC 3550 평활 jitter 는 report 참고치 전용 — 3GPP 에 jitter 의 규범 정의가
    없으므로 판정에는 쓰지 않는다(§4.4).
    """
    if not delays_ms:
        return []
    m = min(delays_ms)
    return [d - m for d in delays_ms]


def rfc3550_jitter(delays_ms: Sequence[float]) -> float:
    """RFC 3550 §6.4.1 평활 interarrival jitter — report 병기용."""
    j = 0.0
    for a, b in zip(delays_ms, delays_ms[1:]):
        j += (abs(b - a) - j) / 16.0
    return j


def goodput_mbps(nbytes: int, active_s: float) -> float:
    """평가창 내 회신확인(T2)/수신(DL) 바이트 기준 goodput."""
    return nbytes * 8.0 / 1e6 / active_s if active_s > 0 else 0.0


def sustained_mbps(bins_mbps: Sequence[float]) -> float:
    """1 s bin 시계열의 p05 — 순간 피크가 아닌 지속 성능. NES/DTX blackout 이
    정직하게 반영된다(§4.5). 관례상 p05 는 **아래쪽** 표본을 취해야 보수적이다."""
    v = sorted(bins_mbps)
    if not v:
        return float("nan")
    # stats.percentile 과 같은 ceil 관례 — 5% blackout 이 정확히 5% 여도 blackout
    # bin 이 잡히는(작은 쪽) 방향이라 지속 성능 주장에 보수적이다.
    return percentile(v, 0.05)


# ─────────────────────────────────────────────────────────────────────────────
# Delta (§6.3)
# ─────────────────────────────────────────────────────────────────────────────
def delta_ratio_ci(k1: int, n1: int, k0: int, n0: int,
                   conf: float = 0.95) -> Tuple[float, float, float]:
    """비율 delta Δ = p(phase) − p(ref) 의 (점추정, lo, hi) — Newcombe."""
    d = (k1 / n1 if n1 else 0.0) - (k0 / n0 if n0 else 0.0)
    lo, hi = newcombe_diff_ci(k1, n1, k0, n0, conf)
    return d, lo, hi


def delta_quantile_ci(q1: QuantileEstimate, q0: QuantileEstimate,
                      mode: str = "abs") -> Tuple[float, float, float]:
    """quantile delta 의 보수적 CI — 양쪽 rank-CI 의 합집합(§6.3).

    abs: Δ = Q1 − Q0, CI = [lo1−hi0, hi1−lo0]
    rel: Δ = Q1/Q0 − 1, CI = [lo1/hi0−1, hi1/lo0−1]
    두 CI 를 독립처럼 합성하므로 실제보다 넓다 — INCONCLUSIVE 쪽으로 기우는
    안전한 방향이다.
    """
    if mode == "rel":
        d = q1.point / q0.point - 1.0 if q0.point else float("nan")
        return d, q1.lo / q0.hi - 1.0, q1.hi / q0.lo - 1.0
    return q1.point - q0.point, q1.lo - q0.hi, q1.hi - q0.lo


# ─────────────────────────────────────────────────────────────────────────────
# Planner — 실행 전 필요표본/예상판정 (§4.2)
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PlanEntry:
    target_name: str
    kind: str
    n_expected: int
    n_required: int
    feasible: bool
    note: str = ""


def plan_target(target, n_expected: int) -> PlanEntry:
    """target 하나의 예상 표본 대비 판별 가능성.

    ratio: 무실패 가정 최소표본 ln(1/α)/(1−R_t). 예: 99.999%@95% → 299,572.
    1 ms 주기 흐름 하나는 6 s 에 ~5,950 표본 — 99.95% 까지만 확인 가능하므로
    URLLC 5-nines 는 흐름당 ~300 s 가 필요하다. 이것을 **실행 전에** 말해 주는
    것이 planner 의 존재 이유다.
    """
    if target.kind == "ratio":
        need = required_samples(target.value, target.confidence)
        okf = n_expected >= need
        note = "" if okf else (f"무실패여도 n={n_expected:,} 로는 목표 "
                               f"{target.value:.6g} 입증 불가 — 예상 INCONCLUSIVE"
                               f" (n≥{need:,} 필요)")
        return PlanEntry(target.name, target.kind, n_expected, need, okf, note)
    if target.kind == "quantile":
        p = target.quantile or 0.99
        need = math.ceil(QUANTILE_TAIL_MIN / (1.0 - p))
        okf = n_expected >= need
        note = "" if okf else (f"p{p:g} 표본 게이트 미달 — 예상 INCONCLUSIVE")
        return PlanEntry(target.name, target.kind, n_expected, need, okf, note)
    if target.kind == "availability":
        # PASS 자체가 금지된 falsify 전용 KPI — 항상 '입증 불가' 로 예고한다.
        return PlanEntry(target.name, target.kind, n_expected, 0, False,
                         "availability 는 falsify 전용 — PASS 없음, "
                         "위반 미관측 시 INCONCLUSIVE 예정")
    return PlanEntry(target.name, target.kind, n_expected, 0, True, "")


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    from math import comb
    from .model import KpiTarget

    ok = True

    # 1) CP 경계 수치검증: 무실패 n=299,572 에서 하한이 0.99999 에 '겨우' 도달,
    #    299,571 은 미달 (EVIDENCE §4 의 표와 일치해야 한다)
    r_pass = ReliabilityEstimate(n=299572, k=299572)
    r_fail = ReliabilityEstimate(n=299571, k=299571)
    if not (r_pass.lo >= 0.99999 and r_fail.lo < 0.99999):
        ok = False
        print(f"  [KP] CP 경계 오류: n=299572→{r_pass.lo:.9f}, "
              f"n=299571→{r_fail.lo:.9f}")
    elif verbose:
        print(f"  [KP] CP 경계: 무실패 299,572→하한 {r_pass.lo:.9f} (≥0.99999), "
              f"299,571→{r_fail.lo:.9f} (<) OK")
    if ReliabilityEstimate(n=10000, k=10000).lo >= 0.99999:
        ok = False
        print("  [KP] 10⁴ 표본으로 5-nines 하한 도달 — 구조적 금지 위반")

    # 2) rank CI: betainc 경로를 직접 이항합산과 대조 (n=1000, p=0.99)
    n, p, conf = 1000, 0.99, 0.95
    r_l, r_u = quantile_ranks(n, p, conf)

    def cdf_direct(k: int) -> float:
        return sum(comb(n, i) * (p ** i) * ((1 - p) ** (n - i))
                   for i in range(k + 1))
    # 정의 재검: r_u 최소성 / r_l 최대성
    if not (cdf_direct(r_u - 1) >= conf and cdf_direct(r_u - 2) < conf):
        ok = False
        print(f"  [KP] r_u={r_u} 최소성 위반")
    if not (cdf_direct(r_l - 1) <= 1 - conf and cdf_direct(r_l) > 1 - conf):
        ok = False
        print(f"  [KP] r_l={r_l} 최대성 위반")
    elif verbose:
        print(f"  [KP] rank CI (n=1000,p=0.99): r_l={r_l}, r_u={r_u} — "
              f"직접 이항합산과 일치 OK")

    # 3) 알려진 분위수: 0.1..100.0 균일 표본의 p99 — 점추정과 CI 포함 관계
    vals = [i / 10.0 for i in range(1, 1001)]           # d_(r) = r/10
    qe = QuantileEstimate.from_samples(vals, 0.99, 0.95)
    if qe.point != 99.0 or qe.lo != r_l / 10.0 or qe.hi != r_u / 10.0:
        ok = False
        print(f"  [KP] 분위수/CI 값 오류: {qe}")
    if not (qe.lo <= qe.point <= qe.hi and qe.gate_ok):
        ok = False
        print(f"  [KP] CI 순서/게이트 오류: {qe}")

    # 4) 히스토그램 경로: 보수성(상단값) — 표본 경로 대비 크거나 같고 2.4% 이내
    h = LogHistogram()
    for v in vals:
        h.add(v)
    qh = QuantileEstimate.from_histogram(h, 0.99, 0.95)
    if not (qe.point <= qh.point <= qe.point * 1.024
            and qe.hi <= qh.hi <= qe.hi * 1.024):
        ok = False
        print(f"  [KP] 히스토그램 보수성 위반: {qh.point} vs {qe.point}")
    elif verbose:
        print(f"  [KP] 히스토그램 분위수 보수성 (+{(qh.point/qe.point-1)*100:.2f}%) OK")

    # 5) 표본 게이트: p99.9 는 n=1000 으로 부족해야 한다 (n·(1−p)=1 < 10)
    qg = QuantileEstimate.from_samples(vals, 0.999, 0.95)
    if qg.gate_ok or qg.n_required != 10000:
        ok = False
        print(f"  [KP] 표본 게이트 오류: gate={qg.gate_ok} req={qg.n_required}")

    # 6) survival 스캔 — 손으로 만든 손실 패턴: TI 2 ms, ST 2 ms,
    #    t=10,12,14 실패(3연속), 마지막 성공 t=8 → down 은 8+ST=10 에 시작,
    #    t=16 성공으로 종료 → 사건 1건, downtime 6 ms
    cycles = [(2.0 * i, i not in (5, 6, 7)) for i in range(11)]
    rep = survival_scan(cycles, survival_time_ms=2.0)
    if rep.events != [(10.0, 6.0)] or rep.downtime_ms != 6.0:
        ok = False
        print(f"  [KP] survival 스캔 오류: {rep.events}, {rep.downtime_ms}")
    elif verbose:
        print(f"  [KP] survival: down@10ms 6ms 지속, A={rep.availability:.4f} OK")
    # 단일 실패(연속 아님)는 ST=2, TI=2 에서 down 이 아니어야 한다 (경과=2, >2 아님)
    rep2 = survival_scan([(2.0 * i, i != 5) for i in range(11)], 2.0)
    if rep2.events:
        ok = False
        print(f"  [KP] 단일실패가 down 으로 오판: {rep2.events}")
    # 전실패: t0 anchor, down 은 t0+ST 부터 끝까지
    rep3 = survival_scan([(2.0 * i, False) for i in range(11)], 2.0)
    if not (len(rep3.events) == 1 and rep3.events[0] == (2.0, 18.0)):
        ok = False
        print(f"  [KP] 전실패 down 구간 오류: {rep3.events}")
    # down-cycle 하한: 사건 0 이면 0 (FAIL 근거 없음)
    if rep2.unavailability_lower() != 0.0:
        ok = False
        print("  [KP] 사건 0 인데 불가용 하한이 0 이 아님")
    if not (0.0 < rep.unavailability_lower() < rep.n_down_cycles / rep.n_cycles):
        ok = False
        print(f"  [KP] 불가용 하한 이상: {rep.unavailability_lower()}")

    # 7) 원장 실패목록 → cycle 복원
    cy = cycles_from_failures([int(10e6), int(12e6), int(14e6)], 0, int(20e6), 2.0)
    if survival_scan(cy, 2.0).events != [(10.0, 6.0)]:
        ok = False
        print("  [KP] cycles_from_failures 복원 오류")

    # 8) PDV: [5,6,7,10] → [0,1,2,5]; RFC3550 은 참고치(비판정)
    if pdv_series([5.0, 6.0, 7.0, 10.0]) != [0.0, 1.0, 2.0, 5.0]:
        ok = False
        print("  [KP] PDV 오류")
    if not (0.0 < rfc3550_jitter([1.0, 2.0, 1.0, 2.0]) < 1.0):
        ok = False
        print("  [KP] RFC3550 jitter 범위 이상")

    # 9) throughput: goodput 산술 + sustained 는 p05 의 아래쪽 표본
    if abs(goodput_mbps(12_500_000, 10.0) - 10.0) > 1e-9:
        ok = False
        print("  [KP] goodput 산술 오류")
    bins = [30.0] * 95 + [3.0] * 5                     # 5% blackout
    s = sustained_mbps(bins)
    if s != 3.0:                                        # 피크가 아닌 지속 성능
        ok = False
        print(f"  [KP] sustained p05 오류: {s}")

    # 10) delta: 동일 신뢰도 → CI 가 0 포함, 열화 0.01 → 검출
    d, lo, hi = delta_ratio_ci(9990, 10000, 9990, 10000)
    if not (lo < 0.0 < hi and abs(d) < 1e-12):
        ok = False
        print(f"  [KP] 동일비율 delta 오류: {d} [{lo},{hi}]")
    d2, lo2, hi2 = delta_ratio_ci(9890, 10000, 9990, 10000)
    if not (hi2 < 0.0 and d2 < -0.009):
        ok = False
        print(f"  [KP] 열화 delta 미검출: {d2} [{lo2},{hi2}]")
    # quantile delta (rel): 20% 증가 사례
    q0 = QuantileEstimate.from_samples(vals, 0.99, 0.95)
    q1 = QuantileEstimate.from_samples([v * 1.2 for v in vals], 0.99, 0.95)
    dr, dlo, dhi = delta_quantile_ci(q1, q0, "rel")
    if not (abs(dr - 0.2) < 1e-9 and dlo <= 0.2 <= dhi):
        ok = False
        print(f"  [KP] quantile delta(rel) 오류: {dr} [{dlo},{dhi}]")

    # 11) planner: 1 ms 주기 1흐름 × 6 s ≈ 5,950 표본 → 5-nines 예상 INCONCLUSIVE,
    #     10 UE × 2 ms × 60 s = 300,000 → 판별 가능
    t = KpiTarget(name="rel", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99999, pdb_ms=1.0)
    pe = plan_target(t, 5950)
    if pe.feasible or pe.n_required != 299572:
        ok = False
        print(f"  [KP] planner 미달 경고 실패: {pe}")
    pe2 = plan_target(t, 300000)
    if not pe2.feasible:
        ok = False
        print(f"  [KP] planner 충분 판정 실패: {pe2}")
    ta = KpiTarget(name="av", kind="availability", metric="delivery",
                   basis="rtt-conservative", value=0.99999,
                   transfer_interval_ms=2.0, survival_time_ms=2.0)
    if plan_target(ta, 10**9).feasible:
        ok = False
        print("  [KP] availability 가 feasible 로 예고됨 — falsify 전용 위반")
    elif verbose:
        print(f"  [KP] planner: 5,950 표본→INCONCLUSIVE 예고 / 300,000→가능 / "
              f"availability 는 항상 입증불가 예고 OK")

    return ok


if __name__ == "__main__":
    print("KPI selftest:", "PASS" if selftest(verbose=True) else "FAIL")
