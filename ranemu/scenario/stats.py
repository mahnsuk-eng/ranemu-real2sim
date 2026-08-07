#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.stats — 적합성 판정을 뒷받침하는 통계.

왜 별도 모듈인가
================
3GPP 서비스 요구는 "왕복 1 ms 안에 **99.999%** 성공" 같은 형태다. 이런 주장을
검증하려면 표본이 얼마나 필요한지 생각해야 한다. 실패가 한 번도 없더라도,
n 개를 보고 말할 수 있는 것은 "실패율이 대략 3/n 보다 작다"까지다(rule of three).
따라서

    n = 10,000  → 실패율 상한 ≈ 3×10⁻⁴  → **99.99% 조차 확인 못 한다**
    n = 300,000 → 실패율 상한 ≈ 1×10⁻⁵  → 99.999% 를 겨우 확인한다

이 사실을 숨기고 "PASS" 를 찍는 계측기는 틀린 확신을 준다. 그래서 이 모듈은
**판정과 함께 그 판정이 표본으로 뒷받침되는지**를 항상 같이 낸다.

  - `wilson_lower` / `clopper_pearson_lower` — 성공률의 단측 하한(보수적).
  - `rule_of_three_upper` — 무실패 시 실패율 상한.
  - `required_samples` — 목표 신뢰도를 확인하는 데 필요한 최소 표본.
  - `ReliabilityClaim` — 관측치로부터 '무엇까지 말할 수 있는가' 를 계산.

의도적으로 scipy 에 의존하지 않는다(있으면 쓰고, 없으면 동등한 순수 파이썬 구현으로
떨어진다). 계측 도구가 선택적 의존성 때문에 못 도는 일은 없어야 한다.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Tuple

try:                                    # 정확한 베타 분위수가 있으면 쓴다
    from scipy.stats import beta as _beta      # type: ignore
    _HAVE_SCIPY = True
except Exception:                       # noqa: BLE001
    _beta = None
    _HAVE_SCIPY = False


# ─────────────────────────────────────────────────────────────────────────────
# 베타 분위수 (scipy 없을 때의 대체 구현)
# ─────────────────────────────────────────────────────────────────────────────
def _betacf(a: float, b: float, x: float, itmax: int = 300,
            eps: float = 3e-12) -> float:
    """연분수 전개 (Numerical Recipes §6.4)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    if abs(d) < 1e-30:
        d = 1e-30
    d = 1.0 / d
    h = d
    for m in range(1, itmax + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < 1e-30:
            d = 1e-30
        c = 1.0 + aa / c
        if abs(c) < 1e-30:
            c = 1e-30
        d = 1.0 / d
        de = d * c
        h *= de
        if abs(de - 1.0) < eps:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """정규화 불완전 베타 함수 I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
             + a * math.log(x) + b * math.log1p(-x))
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbeta) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbeta) * _betacf(b, a, 1.0 - x) / b


def beta_ppf(q: float, a: float, b: float) -> float:
    """베타 분위수. scipy 가 있으면 그것을, 없으면 이분법으로."""
    if a <= 0 or b <= 0:
        return float("nan")
    if _HAVE_SCIPY:
        return float(_beta.ppf(q, a, b))
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if betainc(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


# ─────────────────────────────────────────────────────────────────────────────
# 비율의 단측 하한
# ─────────────────────────────────────────────────────────────────────────────
def clopper_pearson_lower(successes: int, n: int, conf: float = 0.95) -> float:
    """성공률의 정확(exact) 단측 하한. 보수적이며 소표본에서도 유효하다."""
    if n <= 0:
        return 0.0
    if successes >= n:
        # 무실패: 하한은 (1-conf)^(1/n)
        return (1.0 - conf) ** (1.0 / n)
    if successes <= 0:
        return 0.0
    return beta_ppf(1.0 - conf, successes, n - successes + 1)


def clopper_pearson_upper(successes: int, n: int, conf: float = 0.95) -> float:
    """성공률의 정확 단측 상한.

    verdict.py 의 FAIL 게이트가 필요로 한다: FAIL 은 '상한조차 목표에 못 미침'
    (R_hi < target) 일 때만 낸다 — 하한 미달만으로 FAIL 을 찍으면 표본 부족을
    실패로 오판한다(INCONCLUSIVE 여야 함).
    """
    if n <= 0:
        return 1.0
    if successes >= n:
        return 1.0
    if successes <= 0:
        # 전실패: 상한은 1-(1-conf)^(1/n) (rule of three 의 쌍대)
        return 1.0 - (1.0 - conf) ** (1.0 / n)
    return beta_ppf(conf, successes + 1, n - successes)


def binom_cdf(k: int, n: int, p: float) -> float:
    """이항 CDF P[X ≤ k].  quantile 의 순서통계량 CI 랭크 계산용.

    직접 합산은 n=10⁶ 에서 불가능하므로 정규화 불완전 베타와의 항등식
    P[X ≤ k] = I_{1-p}(n-k, k+1) 을 쓴다 (scipy 불필요, betainc 는 2.7e-15
    수준으로 검증됨).
    """
    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    return betainc(n - k, k + 1, 1.0 - p)


def wilson_upper(successes: int, n: int, conf: float = 0.95) -> float:
    """Wilson 점수 단측 상한. p↔1-p 대칭성으로 하한 구현을 재사용한다."""
    if n <= 0:
        return 1.0
    return 1.0 - wilson_lower(n - successes, n, conf)


def newcombe_diff_ci(k1: int, n1: int, k2: int, n2: int,
                     conf: float = 0.95) -> Tuple[float, float]:
    """비율 차 p1-p2 의 Newcombe score 구간 (양측, 수준 conf).

    delta 술어(§6.3)용. Wald 구간은 극단 비율(신뢰도 0.999+)에서 붕괴하므로
    Wilson 경계를 조합하는 Newcombe 방식을 쓴다.
    """
    side = (1.0 + conf) / 2.0            # 양측 → 각 측 단측 수준
    p1 = k1 / n1 if n1 else 0.0
    p2 = k2 / n2 if n2 else 0.0
    l1, u1 = wilson_lower(k1, n1, side), wilson_upper(k1, n1, side)
    l2, u2 = wilson_lower(k2, n2, side), wilson_upper(k2, n2, side)
    d = p1 - p2
    lo = d - math.sqrt((p1 - l1) ** 2 + (u2 - p2) ** 2)
    hi = d + math.sqrt((u1 - p1) ** 2 + (p2 - l2) ** 2)
    return max(-1.0, lo), min(1.0, hi)


def wilson_lower(successes: int, n: int, conf: float = 0.95) -> float:
    """Wilson 점수 단측 하한. Clopper–Pearson 보다 덜 보수적이고 계산이 싸다."""
    if n <= 0:
        return 0.0
    z = _z_one_sided(conf)
    p = successes / n
    d = 1.0 + z * z / n
    centre = p + z * z / (2 * n)
    half = z * math.sqrt(max(0.0, p * (1 - p) / n + z * z / (4 * n * n)))
    return max(0.0, (centre - half) / d)


def _z_one_sided(conf: float) -> float:
    """표준정규 단측 분위수 (Acklam 근사)."""
    p = conf
    if p <= 0 or p >= 1:
        return 0.0
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]
    pl = 0.02425
    if p < pl:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p <= 1 - pl:
        q = p - 0.5
        r = q * q
        return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
               (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)
    q = math.sqrt(-2 * math.log(1 - p))
    return -((((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) /
             ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1))


def rule_of_three_upper(n: int, conf: float = 0.95) -> float:
    """무실패 n 회 관측 시 실패율의 단측 상한. conf=0.95 에서 ≈ 3/n."""
    if n <= 0:
        return 1.0
    return 1.0 - (1.0 - conf) ** (1.0 / n)


def required_samples(target_reliability: float, conf: float = 0.95) -> int:
    """무실패를 가정할 때 목표 신뢰도를 확인하는 데 필요한 최소 표본 수."""
    f = 1.0 - target_reliability
    if f <= 0.0:
        return 0
    return int(math.ceil(math.log(1.0 - conf) / math.log(1.0 - f)))


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ReliabilityClaim:
    """관측치로부터 '표본이 실제로 뒷받침하는 신뢰도' 를 계산한다.

    `verified` 는 **관측 성공률이 목표를 넘었는가** 가 아니라
    **하한이 목표를 넘었는가** 로 정한다. 전자는 표본이 적으면 언제든 만족되므로
    판정으로서 의미가 없다.
    """
    successes: int
    total: int
    target: float                       # 예: 0.99999
    confidence: float = 0.95

    @property
    def observed(self) -> float:
        return (self.successes / self.total) if self.total else 0.0

    @property
    def lower_bound(self) -> float:
        return clopper_pearson_lower(self.successes, self.total, self.confidence)

    @property
    def verified(self) -> bool:
        """표본이 목표를 뒷받침하는가(하한 ≥ 목표)."""
        return self.total > 0 and self.lower_bound >= self.target

    @property
    def samples_needed(self) -> int:
        return required_samples(self.target, self.confidence)

    @property
    def sample_limited(self) -> bool:
        """실패는 없지만 표본이 모자라 목표를 확인할 수 없는 상태."""
        return (self.successes == self.total and self.total > 0
                and not self.verified)

    @property
    def max_verifiable(self) -> float:
        """이 표본 수로 확인 가능한 최대 신뢰도(무실패 가정)."""
        return 1.0 - rule_of_three_upper(self.total, self.confidence)

    def as_dict(self) -> dict:
        return {
            "successes": self.successes, "total": self.total,
            "target": self.target, "confidence": self.confidence,
            "observed": round(self.observed, 9),
            "lower_bound": round(self.lower_bound, 9),
            "verified": self.verified,
            "sample_limited": self.sample_limited,
            "samples_needed": self.samples_needed,
            "max_verifiable": round(self.max_verifiable, 9),
        }

    def explain(self) -> str:
        if self.total == 0:
            return "표본 없음"
        if self.verified:
            return (f"목표 {self.target:.6g} 확인 "
                    f"(하한 {self.lower_bound:.6g}, n={self.total:,})")
        if self.sample_limited:
            return (f"실패 0건이지만 n={self.total:,} 로는 {self.max_verifiable:.6g} "
                    f"까지만 확인 가능 — 목표 {self.target:.6g} 에는 "
                    f"n≥{self.samples_needed:,} 필요")
        return (f"목표 미달: 관측 {self.observed:.6g}, 하한 {self.lower_bound:.6g} "
                f"< 목표 {self.target:.6g} (실패 {self.total - self.successes:,}건)")


# ─────────────────────────────────────────────────────────────────────────────
def percentile(sorted_vals, q: float) -> float:
    """정렬된 표본의 분위수(선형 보간 없음 — 보수적으로 위쪽 표본을 택한다)."""
    n = len(sorted_vals)
    if n == 0:
        return float("nan")
    i = min(n - 1, max(0, int(math.ceil(q * n)) - 1))
    return sorted_vals[i]


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    ok = True

    # 1) 무실패 하한: (1-conf)^(1/n)
    for n in (10, 100, 3000):
        lo = clopper_pearson_lower(n, n, 0.95)
        exp = 0.05 ** (1.0 / n)
        if abs(lo - exp) > 1e-9:
            ok = False
            print(f"  [ST] 무실패 하한 오류 n={n}: {lo} vs {exp}")

    # 2) rule of three: n=3000 이면 상한 ≈ 1e-3
    u = rule_of_three_upper(3000, 0.95)
    if not (9.0e-4 < u < 1.1e-3):
        ok = False
        print(f"  [ST] rule of three 이상: {u}")

    # 3) 필요한 표본 수 — 99.999% 는 3×10^5 규모여야 한다
    n5 = required_samples(0.99999, 0.95)
    if not (2.5e5 < n5 < 3.5e5):
        ok = False
        print(f"  [ST] 99.999% 필요표본 이상: {n5}")
    n3 = required_samples(0.999, 0.95)
    if not (2.5e3 < n3 < 3.5e3):
        ok = False
        print(f"  [ST] 99.9% 필요표본 이상: {n3}")

    # 4) 핵심 성질: 표본이 모자라면 무실패여도 verified 가 아니어야 한다
    c = ReliabilityClaim(successes=10000, total=10000, target=0.99999)
    if c.verified:
        ok = False
        print("  [ST] 표본 부족인데 verified — 틀린 확신을 준다")
    if not c.sample_limited:
        ok = False
        print("  [ST] sample_limited 로 표시되지 않음")
    if not (1e-4 < 1 - c.max_verifiable < 1e-3):
        ok = False
        print(f"  [ST] max_verifiable 이상: {c.max_verifiable}")

    # 5) 충분한 표본 + 무실패면 verified
    c2 = ReliabilityClaim(successes=400000, total=400000, target=0.99999)
    if not c2.verified:
        ok = False
        print(f"  [ST] 충분표본인데 미확인: {c2.explain()}")

    # 6) 실패가 있으면 하한이 관측치보다 낮아야 한다
    c3 = ReliabilityClaim(successes=9990, total=10000, target=0.999)
    if not (c3.lower_bound < c3.observed):
        ok = False
        print("  [ST] 하한이 관측치보다 크다")
    if c3.sample_limited:
        ok = False
        print("  [ST] 실패가 있는데 sample_limited")

    # 7) Wilson 은 Clopper–Pearson 보다 덜 보수적(하한이 더 높다)
    cp = clopper_pearson_lower(9990, 10000, 0.95)
    wl = wilson_lower(9990, 10000, 0.95)
    if not (wl >= cp - 1e-9):
        ok = False
        print(f"  [ST] Wilson({wl}) < Clopper-Pearson({cp})")

    # 8) scipy 없이도 같은 답 — 순수구현 경로 검증
    global _HAVE_SCIPY
    if _HAVE_SCIPY:
        saved = _HAVE_SCIPY
        try:
            _HAVE_SCIPY = False
            pure = clopper_pearson_lower(9990, 10000, 0.95)
        finally:
            _HAVE_SCIPY = saved
        if abs(pure - cp) > 1e-6:
            ok = False
            print(f"  [ST] scipy 유무로 결과가 다름: {cp} vs {pure}")
        elif verbose:
            print(f"  [ST] scipy/순수구현 일치 (차 {abs(pure-cp):.2e}) OK")

    # 9) 분위수
    v = list(range(1, 101))
    if percentile(v, 0.99) != 99 or percentile(v, 0.5) != 50:
        ok = False
        print("  [ST] 분위수 계산 오류")

    # 10) 상한: 무실패 → 1.0, 전실패 → rule-of-three 쌍대, k<n 이면 하한<관측<상한
    if clopper_pearson_upper(100, 100, 0.95) != 1.0:
        ok = False
        print("  [ST] 무실패 상한이 1.0 이 아님")
    u0 = clopper_pearson_upper(0, 3000, 0.95)
    if not (9.0e-4 < u0 < 1.1e-3):
        ok = False
        print(f"  [ST] 전실패 상한 이상: {u0}")
    lo9, hi9 = (clopper_pearson_lower(9990, 10000, 0.95),
                clopper_pearson_upper(9990, 10000, 0.95))
    if not (lo9 < 0.999 < hi9):
        ok = False
        print(f"  [ST] CP 구간이 관측치를 감싸지 않음: [{lo9}, {hi9}]")

    # 11) 이항 CDF — 소표본 직접 합산과 대조 (베타 항등식 검증)
    from math import comb
    for (k, n, p) in ((3, 10, 0.3), (0, 5, 0.5), (7, 8, 0.9)):
        direct = sum(comb(n, i) * p**i * (1-p)**(n-i) for i in range(k+1))
        via = binom_cdf(k, n, p)
        if abs(direct - via) > 1e-10:
            ok = False
            print(f"  [ST] binom_cdf({k},{n},{p}) = {via} vs 직접 {direct}")

    # 12) Newcombe 차이구간: 동일 비율이면 0 을 포함, 명확한 차이는 0 을 배제
    dlo, dhi = newcombe_diff_ci(990, 1000, 990, 1000, 0.95)
    if not (dlo < 0.0 < dhi):
        ok = False
        print(f"  [ST] 동일비율 차이구간이 0 을 제외: [{dlo}, {dhi}]")
    dlo2, dhi2 = newcombe_diff_ci(999, 1000, 900, 1000, 0.95)
    if not (dlo2 > 0.05):
        ok = False
        print(f"  [ST] 명확한 차이를 검출 못함: [{dlo2}, {dhi2}]")

    if ok and verbose:
        print(f"  [ST] 99.999% 확인에 필요한 표본 {n5:,}개, 99.9% 는 {n3:,}개")
        print(f"  [ST] {c.explain()}")
    return ok


if __name__ == "__main__":
    print("STATS selftest:", "PASS" if selftest(verbose=True) else "FAIL")
