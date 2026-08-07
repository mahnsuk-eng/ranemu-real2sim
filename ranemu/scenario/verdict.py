#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.verdict — 4치 판정 의미론 (설계 §5) + measurability matrix (§3.4).

판정값이 4개인 이유
===================
PASS/FAIL 이분법은 두 가지 거짓말을 강요한다:
(1) 표본이 모자라 판별이 안 되는 것을 어느 한쪽으로 찍는 거짓말 → **INCONCLUSIVE**,
(2) 배치가 그 metric 을 잴 수조차 없는데 값을 내는 거짓말 → **NOT_MEASURABLE**.
INCONCLUSIVE 는 "더 오래 돌리면 판별 가능"(required_samples 동봉),
NOT_MEASURABLE 은 "배치를 바꿔야 가능"(필요 최소 배치 동봉)이라는 점에서 서로 다르다.

measurability matrix 는 문서가 아니라 코드다 — unsync 배치에서 OWD 를 산출하는
경로는 이 모듈이 차단하며(§11-1), ISAC sensing accuracy 처럼 N2/N3 관측으로 원리적으로
불가능한 metric 은 어떤 배치에서도 NOT_MEASURABLE 이다(§11-3).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .kpi import (QuantileEstimate, ReliabilityEstimate, SurvivalReport,
                  delta_quantile_ci, delta_ratio_ci)

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"
NOT_MEASURABLE = "NOT_MEASURABLE"

# ─────────────────────────────────────────────────────────────────────────────
# §3.4 measurability matrix — 규범 테이블의 전사.
#   min_tier: 필요한 최소 배치 tier (§3.3: 0=무협조, 1=dumb echo, 2=ranemu reflector)
#   clocks:   None = 아무 clock_domain 이나 됨 / 집합 = 그중 하나여야 함
#   never:    어떤 배치로도 불가 (N2/N3 관측 한계 — 정직성 쇼케이스)
# ─────────────────────────────────────────────────────────────────────────────
_M = {
    # metric               min_tier  clocks               never
    "ul_sent":            (0, None, False),
    "ul_offered":         (0, None, False),
    "rtt_wire_ms":        (1, None, False),
    "rtt_ms":             (1, None, False),           # rtt_wire 의 별칭 (§2.2 예시)
    "rtt_net_ms":         (2, None, False),           # t2/t3 필요 → reflector
    "delivery":           (1, None, False),           # RTT basis 신뢰도
    "owd_ul_ms":          (2, ("shared", "ptp"), False),
    "owd_dl_ms":          (2, ("shared", "ptp"), False),
    "frame_delay_ms":     (2, None, False),           # t1/t4 단일클럭 — 동기 불필요
    "pdv_ms":             (2, None, False),           # rtt_net 파생
    "dl_goodput_mbps":    (2, None, False),           # echo 는 DL=UL 상한이라 부적격
    "ul_goodput_mbps":    (1, None, False),           # 회신확인 바이트
    "completion_s":       (2, None, False),           # stream 전송 완료시간
    "inventory_completion_s": (1, None, False),       # 첫 메시지 '전달' 확인 필요
    "reg_success":        (0, None, False),           # NAS 절차 — UeStats 에 이미 있음
    "setup_time_s":       (0, None, False),
    "sensing_accuracy":   (0, None, True),            # N2/N3 로 원리적 불가 (§11-3)
    "positioning_accuracy": (0, None, True),
    "energy_saving":      (0, None, True),            # 전력 실측 없음 (§11-5)
}

_TIER_NAME = {0: "T0(무협조)", 1: "T1(dumb echo)", 2: "T2(ranemu reflector)"}


def measurable(metric: str, tier: int, clock_domain: str) -> Tuple[bool, str]:
    """metric 이 이 배치에서 측정 가능한가. 불가면 필요한 최소 배치를 말해 준다."""
    spec = _M.get(metric)
    if spec is None:
        return False, f"미등록 metric {metric!r} — 측정 불가로 간주(안전측)"
    min_tier, clocks, never = spec
    if never:
        return False, (f"{metric} 은 N2/N3 관측으로 원리적으로 측정 불가 — "
                       f"어떤 배치 tier 로도 불가")
    if tier < min_tier:
        return False, (f"{metric} 에는 tier≥{min_tier} "
                       f"({_TIER_NAME[min_tier]}) 필요 — 현재 tier={tier}")
    if clocks is not None and clock_domain not in clocks:
        return False, (f"{metric} 에는 clock_domain∈{clocks} 필요 — "
                       f"현재 {clock_domain!r} (NTP 대칭가정 offset 은 OWD 근거로 "
                       f"쓰지 않는다, §3.2)")
    return True, ""


def basis_available(basis: str, tier: int, clock_domain: str) -> Tuple[bool, str]:
    """target.basis 요구를 배치가 제공하는가."""
    if basis in ("rtt-conservative", "measured-wire"):
        if tier < 1:
            return False, f"basis={basis} 에는 tier≥1 (회신 경로) 필요"
        return True, ""
    if basis in ("owd", "measured-shared-clock"):
        return measurable("owd_ul_ms", tier, clock_domain)
    if basis == "measured-ptp":
        if tier >= 2 and clock_domain == "ptp":
            return True, ""
        return False, "basis=measured-ptp 에는 tier≥2 + clock_domain=ptp 필요"
    if basis in ("composed", "modelled"):
        # 산출은 항상 가능하지만 판정 근거로는 쓰지 않는다(§3.5) — 호출측이
        # report 전용으로만 다룬다. 여기서 True 를 주되 판정 함수는 받지 않는다.
        return True, ""
    return False, f"알 수 없는 basis {basis!r}"


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class VerdictRecord:
    """verdict 단위 = (target × phase × population). §5 JSON 스키마와 1:1."""
    target: str
    phase: str
    population: str
    kind: str
    metric: str
    basis: str
    verdict: str
    reason: str = ""
    estimate: Optional[float] = None
    ci_lower: Optional[float] = None
    ci_upper: Optional[float] = None
    threshold: Optional[float] = None
    op: str = "<="
    confidence: float = 0.95
    n: Optional[int] = None
    k: Optional[int] = None
    pdb_ms: Optional[float] = None
    conservative: bool = False
    payload_inflated: bool = False
    max_failure_run: Optional[int] = None
    censored: Optional[int] = None
    required_samples: Optional[int] = None
    provenance: Dict[str, Any] = field(default_factory=dict)
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    extras: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items() if v not in (None, {}, "")}
        # 판정의 자기서술에 필수인 키는 값이 비어도 남긴다
        for must in ("target", "verdict", "kind", "metric", "basis",
                     "provenance", "fingerprint"):
            d[must] = getattr(self, must)
        return d


def _cmp_verdict(lo: float, hi: float, thr: float, op: str) -> str:
    """CI [lo,hi] 대 임계 thr 의 3치 비교 — PASS 는 CI 전체가 조건을 만족할 때만."""
    if op == "<=":
        if hi <= thr:
            return PASS
        if lo > thr:
            return FAIL
        return INCONCLUSIVE
    if lo >= thr:
        return PASS
    if hi < thr:
        return FAIL
    return INCONCLUSIVE


def _finish(rec: VerdictRecord) -> VerdictRecord:
    """공통 후처리: RTT-보수 basis 의 FAIL 은 과잉엄격일 수 있음을 부기(§3.5)."""
    if rec.basis == "rtt-conservative":
        rec.conservative = True
        if rec.verdict == FAIL:
            rec.reason += (" | conservative: owd_ul ≤ rtt_net 이므로 OWD 기준으로는 "
                           "통과할 수도 있음 — T2+shared 배치로 재시험 권장")
    return rec


def not_measurable_record(target, tier: int, clock_domain: str, reason: str,
                          phase: str = "*", population: str = "*") -> VerdictRecord:
    return VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=NOT_MEASURABLE,
        reason=reason, threshold=target.value, op=target.op,
        provenance=target.provenance.__dict__ if target.provenance else {})


def gate(target, tier: int, clock_domain: str,
         phase: str = "*", population: str = "*") -> Optional[VerdictRecord]:
    """측정가능성 게이트. 통과하면 None, 아니면 NOT_MEASURABLE 레코드."""
    ok, why = measurable(target.metric, tier, clock_domain)
    if not ok:
        return not_measurable_record(target, tier, clock_domain, why,
                                     phase, population)
    ok, why = basis_available(target.basis, tier, clock_domain)
    if not ok:
        return not_measurable_record(target, tier, clock_domain, why,
                                     phase, population)
    if target.basis in ("composed", "modelled"):
        # §3.5: composed/modelled 는 report 병기 전용 — 판정 근거 금지.
        return not_measurable_record(
            target, tier, clock_domain,
            f"basis={target.basis} 는 판정 근거로 쓰지 않는다(report 전용, §3.5)",
            phase, population)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# 판정 함수 — 추정치를 받아 4치 중 하나를 낸다 (측정가능성은 gate 가 선행)
# ─────────────────────────────────────────────────────────────────────────────
def decide_ratio(target, rel: ReliabilityEstimate, *, phase: str = "*",
                 population: str = "*", **meta) -> VerdictRecord:
    """§4.2: PASS iff R_lo ≥ target, FAIL iff R_hi < target, 그 외 INCONCLUSIVE."""
    thr = target.value
    if rel.n <= 0:
        v, reason = INCONCLUSIVE, "표본 0 — 평가 모집단이 비어 있음"
    else:
        v = _cmp_verdict(rel.lo, rel.hi, thr, target.op)
        if v == INCONCLUSIVE:
            need = rel.required_failure_free(thr)
            reason = (f"ci_lower {rel.lo:.7f} < threshold {thr:g} ≤ "
                      f"ci_upper — 무실패 기준 n≥{need:,} 필요 (현재 n={rel.n:,})")
        elif v == PASS:
            reason = f"ci_lower {rel.lo:.7f} ≥ {thr:g}"
        else:
            reason = f"ci_upper {rel.hi:.7f} < {thr:g} — 위반이 통계적으로 입증됨"
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=rel.estimate if rel.n else None, ci_lower=rel.lo if rel.n else None,
        ci_upper=rel.hi if rel.n else None, threshold=thr, op=target.op,
        confidence=target.confidence, n=rel.n, k=rel.k, pdb_ms=target.pdb_ms,
        required_samples=rel.required_failure_free(thr),
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras=dict(meta))
    for key in ("max_failure_run", "censored", "payload_inflated"):
        if key in meta:
            setattr(rec, key, meta.pop(key))
    return _finish(rec)


def decide_quantile(target, qe: QuantileEstimate, *, ptp_err_ms: float = 0.0,
                    phase: str = "*", population: str = "*", **meta) -> VerdictRecord:
    """§4.1 + §3.2 ptp 오차반영: PASS iff Q̂_u+err ≤ thr, FAIL iff Q̂_l−err > thr."""
    thr = target.value
    if qe.n <= 0:
        v, reason = INCONCLUSIVE, "표본 0"
        req = None
    elif not qe.gate_ok:
        v = INCONCLUSIVE
        req = qe.n_required
        reason = (f"표본 게이트 미달: n·(1−p) = {qe.n * (1 - qe.p):.1f} < 10 — "
                  f"p{qe.p:g} 판정에는 n≥{req:,} 필요")
    else:
        req = qe.n_required
        v = _cmp_verdict(qe.lo - ptp_err_ms, qe.hi + ptp_err_ms, thr, target.op)
        if v == INCONCLUSIVE:
            reason = (f"rank-CI [{qe.lo:g}, {qe.hi:g}]"
                      + (f" ± ptp_err {ptp_err_ms:g}" if ptp_err_ms else "")
                      + f" 가 임계 {thr:g} 를 걸침")
        else:
            reason = (f"p{qe.p:g} rank-CI [{qe.lo:g}, {qe.hi:g}] {target.op} {thr:g}"
                      + (f" (ptp_err {ptp_err_ms:g} 반영)" if ptp_err_ms else ""))
        if qe.source == "histogram":
            reason += " | histogram 경로(상단값, 분해능 ≤2.33%)"
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=qe.point if qe.n else None, ci_lower=qe.lo if qe.n else None,
        ci_upper=qe.hi if qe.n else None, threshold=thr, op=target.op,
        confidence=target.confidence, n=qe.n, required_samples=req,
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras=dict(meta))
    return _finish(rec)


def decide_survival(target, rep: SurvivalReport, *, phase: str = "*",
                    population: str = "*", **meta) -> VerdictRecord:
    """survival(§4.3 앞부분): down 사건은 관측된 결정론적 위반 → FAIL.
    사건 0 은 '위반 미관측' 이지 입증이 아니므로 INCONCLUSIVE — PASS 는 없다."""
    if rep.n_cycles <= 0:
        v, reason = INCONCLUSIVE, "cycle 관측 0"
    elif rep.events:
        v = FAIL
        reason = (f"survival time 위반 {len(rep.events)}건 관측 — 최장 "
                  f"{max(d for _, d in rep.events):.1f} ms, "
                  f"총 downtime {rep.downtime_ms:.1f} ms")
    else:
        v = INCONCLUSIVE
        reason = (f"down 사건 0 (cycle {rep.n_cycles:,}개) — 위반 미관측일 뿐 "
                  f"생존성 입증 아님 (falsify 전용 KPI)")
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=rep.availability if rep.n_cycles else None,
        threshold=target.value, op=target.op, confidence=target.confidence,
        n=rep.n_cycles,
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras={"downtime_ms": rep.downtime_ms, "events": rep.events, **meta})
    return _finish(rec)


def decide_availability(target, rep: SurvivalReport, *, phase: str = "*",
                        population: str = "*", **meta) -> VerdictRecord:
    """availability(§4.3): FAIL iff 관측 불가용도의 단측 하한 > 1−A_target.
    PASS 는 구조적으로 내지 않는다 — "99.999% 가용성 검증됨" 은 이 시스템에서
    나올 수 없는 문장이다(§11-2)."""
    a_thr = target.value
    if rep.n_cycles <= 0:
        v, reason = INCONCLUSIVE, "cycle 관측 0"
    else:
        u_lo = rep.unavailability_lower(target.confidence)
        if u_lo > 1.0 - a_thr:
            v = FAIL
            reason = (f"불가용도 단측 하한 {u_lo:.3g} > 허용 {1 - a_thr:.3g} — "
                      f"위반이 통계적으로 입증됨")
        else:
            v = INCONCLUSIVE
            reason = ("insufficient observation for availability claim — "
                      f"관측 A={rep.availability:.6f}, 하한으로 위반 입증 불가 "
                      f"(availability 는 falsify 전용)")
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=rep.availability if rep.n_cycles else None,
        threshold=a_thr, op=target.op, confidence=target.confidence,
        n=rep.n_cycles,
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras={"downtime_ms": rep.downtime_ms,
                "n_down_cycles": rep.n_down_cycles, **meta})
    return _finish(rec)


def decide_rate(target, value: float, n_obs: int, *, min_obs: int = 20,
                phase: str = "*", population: str = "*", **meta) -> VerdictRecord:
    """rate/population 술어 (goodput, completion, reg_success 비율 등 스칼라).

    분포 CI 가 없는 결정론적 집계이므로 정직하게 그렇게 표기한다. 관측이 너무
    적으면(기본 20 미만) 집계 자체가 무의미 → INCONCLUSIVE.
    """
    if n_obs < min_obs:
        v = INCONCLUSIVE
        reason = f"관측 {n_obs}건 < 최소 {min_obs}건 — 집계 무의미"
    elif (target.op == "<=" and value <= target.value) or \
         (target.op == ">=" and value >= target.value):
        v, reason = PASS, f"관측 {value:g} {target.op} {target.value:g} (CI 없는 전창 집계)"
    else:
        v, reason = FAIL, f"관측 {value:g} 이 임계 {target.value:g} 위반 (CI 없는 전창 집계)"
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=value, threshold=target.value, op=target.op, n=n_obs,
        confidence=target.confidence,
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras=dict(meta))
    return _finish(rec)


def decide_delta_ratio(target, k1: int, n1: int, k0: int, n0: int, *,
                       phase: str = "*", population: str = "*",
                       **meta) -> VerdictRecord:
    """delta(비율, §6.3). delta_mode=abs 는 |Δ| 로 판정한다.

    설계는 Δ = m(phase) − m(ref) 라고만 적었는데, delivery 가 부하로 **떨어질** 때
    Δ 는 음수가 되어 부호 그대로면 'Δ ≤ 0.001' 이 자동 만족된다 — 격리 SLA 의
    의도일 수 없다. 모호성은 보수적으로: 어느 방향이든 |Δ| 가 허용치를 넘으면
    위반으로 본다(주석으로 남기는 설계 해석).
    """
    d, lo, hi = delta_ratio_ci(k1, n1, k0, n0, target.confidence)
    thr = target.value
    if n1 <= 0 or n0 <= 0:
        v, reason = INCONCLUSIVE, "비교 표본 없음"
    else:
        abs_hi = max(abs(lo), abs(hi))            # CI 내 |Δ| 의 최대
        abs_lo = 0.0 if lo <= 0.0 <= hi else min(abs(lo), abs(hi))
        v = _cmp_verdict(abs_lo, abs_hi, thr, "<=")
        reason = (f"|Δ| CI [{abs_lo:.5f}, {abs_hi:.5f}] vs 허용 {thr:g} "
                  f"(Δ={d:+.5f}, ref={target.ref_phase})")
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=d, ci_lower=lo, ci_upper=hi, threshold=thr, op=target.op,
        confidence=target.confidence, n=n1,
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras={"ref_phase": target.ref_phase, "delta_mode": target.delta_mode,
                **meta})
    return _finish(rec)


def decide_delta_quantile(target, q1: QuantileEstimate, q0: QuantileEstimate, *,
                          phase: str = "*", population: str = "*",
                          **meta) -> VerdictRecord:
    """delta(quantile). rel 모드: 증가율 (예: rtt p99 delta ≤ +20%). 지연 증가만
    위반으로 본다(감소는 개선) — 비율 delta 와 달리 방향이 명확하다."""
    d, lo, hi = delta_quantile_ci(q1, q0, target.delta_mode)
    thr = target.value
    if not (q1.gate_ok and q0.gate_ok):
        v = INCONCLUSIVE
        reason = "표본 게이트 미달(비교 phase 중 하나 이상)"
    else:
        v = _cmp_verdict(lo, hi, thr, target.op)
        unit = "%" if target.delta_mode == "rel" else ""
        scale = 100.0 if target.delta_mode == "rel" else 1.0
        reason = (f"Δ{'rel' if target.delta_mode == 'rel' else ''} CI "
                  f"[{lo*scale:+.2f}{unit}, {hi*scale:+.2f}{unit}] vs "
                  f"{thr*scale:g}{unit} (ref={target.ref_phase})")
    rec = VerdictRecord(
        target=target.name, phase=phase, population=population, kind=target.kind,
        metric=target.metric, basis=target.basis, verdict=v, reason=reason,
        estimate=d, ci_lower=lo, ci_upper=hi, threshold=thr, op=target.op,
        confidence=target.confidence, n=q1.n,
        provenance=target.provenance.__dict__ if target.provenance else {},
        extras={"ref_phase": target.ref_phase, "delta_mode": target.delta_mode,
                **meta})
    return _finish(rec)


# ─────────────────────────────────────────────────────────────────────────────
# 집계와 렌더링 (§5)
# ─────────────────────────────────────────────────────────────────────────────
def aggregate(records: Sequence[VerdictRecord]) -> str:
    """FAIL > INCONCLUSIVE > PASS. NOT_MEASURABLE 은 집계 불참(보고서에는 목록화).

    측정 가능한 레코드가 하나도 없으면 시나리오 전체가 NOT_MEASURABLE 이다 —
    '아무것도 못 쟀는데 PASS' 는 성립할 수 없다.
    """
    participating = [r for r in records if r.verdict != NOT_MEASURABLE]
    if not participating:
        return NOT_MEASURABLE
    if any(r.verdict == FAIL for r in participating):
        return FAIL
    if any(r.verdict == INCONCLUSIVE for r in participating):
        return INCONCLUSIVE
    return PASS


def render_json(records: Sequence[VerdictRecord],
                fingerprint: Optional[Dict[str, Any]] = None) -> str:
    out = {
        "verdict": aggregate(records),
        "counts": {v: sum(1 for r in records if r.verdict == v)
                   for v in (PASS, FAIL, INCONCLUSIVE, NOT_MEASURABLE)},
        "not_measurable": [r.as_dict() for r in records
                           if r.verdict == NOT_MEASURABLE],
        "verdicts": [r.as_dict() for r in records
                     if r.verdict != NOT_MEASURABLE],
    }
    if fingerprint:
        out["fingerprint"] = fingerprint
    return json.dumps(out, ensure_ascii=False, indent=2)


def render_markdown(records: Sequence[VerdictRecord],
                    title: str = "Verdict report") -> str:
    """사람용 보고서. NOT_MEASURABLE 을 **앞에** 목록화한다 — 숨기지 않는다(§5)."""
    lines = [f"# {title}", "",
             f"**Overall: {aggregate(records)}**", ""]
    nm = [r for r in records if r.verdict == NOT_MEASURABLE]
    if nm:
        lines += ["## Not measurable in this deployment", ""]
        for r in nm:
            lines.append(f"- `{r.target}` ({r.metric}, basis={r.basis}): {r.reason}")
        lines.append("")
    lines += ["## Verdicts", "",
              "| target | phase | population | metric | verdict | estimate "
              "| CI | threshold | basis | provenance |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for r in records:
        if r.verdict == NOT_MEASURABLE:
            continue
        est = f"{r.estimate:.6g}" if r.estimate is not None else "—"
        ci = (f"[{r.ci_lower:.6g}, {r.ci_upper:.6g}]"
              if r.ci_lower is not None and r.ci_upper is not None else "—")
        prov = (f"{r.provenance.get('spec', '?')} "
                f"{r.provenance.get('version', '')} "
                f"({r.provenance.get('kind', '?')})") if r.provenance else "—"
        lines.append(f"| {r.target} | {r.phase} | {r.population} | {r.metric} "
                     f"| **{r.verdict}** | {est} | {ci} "
                     f"| {r.op} {r.threshold:g} | {r.basis} | {prov} |")
    lines += ["", "> reason 필드와 conservative/payload_inflated 플래그는 "
                  "verdict.json 에 전량 보존된다."]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    from .model import KpiProvenance, KpiTarget

    ok = True
    prov = KpiProvenance(spec="TS 22.104", version="19.2.0",
                         clause="Table 5.2-1", kind="service_requirement")

    # 1) measurability matrix 전수 — 설계 §3.4 표의 열(T0/T1/T2+unsync/T2+shared)
    #    을 문자 그대로 전사해 코드와 대조한다. ptp 열은 shared 와 동일해야 한다.
    cols = [(0, "unsync"), (1, "unsync"), (2, "unsync"), (2, "shared"), (2, "ptp")]
    table = {
        "ul_sent":         (True, True, True, True, True),
        "rtt_wire_ms":     (False, True, True, True, True),
        "rtt_net_ms":      (False, False, True, True, True),
        "delivery":        (False, True, True, True, True),
        "owd_ul_ms":       (False, False, False, True, True),
        "owd_dl_ms":       (False, False, False, True, True),
        "frame_delay_ms":  (False, False, True, True, True),
        "dl_goodput_mbps": (False, False, True, True, True),
        "reg_success":     (True, True, True, True, True),
        "sensing_accuracy": (False, False, False, False, False),
    }
    for metric, expect in table.items():
        for (tier, clock), e in zip(cols, expect):
            got, why = measurable(metric, tier, clock)
            if got != e:
                ok = False
                print(f"  [VD] matrix 불일치: {metric} @T{tier}+{clock} "
                      f"= {got} (기대 {e}) {why}")
    # 행렬 밖 조합: T1+shared 라도 owd 는 tier 미달로 불가
    if measurable("owd_ul_ms", 1, "shared")[0]:
        ok = False
        print("  [VD] T1+shared 에서 OWD 가 허용됨")
    if verbose and ok:
        print("  [VD] measurability matrix 전수(10 metric × 5 배치) 일치 OK")

    # 2) ratio 4치 전이
    t = KpiTarget(name="rel", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99999,
                  pdb_ms=1.0, provenance=prov)
    cases = [
        (ReliabilityEstimate(400000, 400000), PASS),        # 하한 ≥ 목표
        (ReliabilityEstimate(10000, 10000), INCONCLUSIVE),  # 무실패지만 표본 부족
        (ReliabilityEstimate(1000, 900), FAIL),             # 상한조차 미달
    ]
    for rel, expect in cases:
        r = decide_ratio(t, rel)
        if r.verdict != expect:
            ok = False
            print(f"  [VD] ratio n={rel.n} k={rel.k}: {r.verdict} (기대 {expect})")
        if expect == INCONCLUSIVE and (r.required_samples != 299572
                                       or "299,572" not in r.reason):
            ok = False
            print(f"  [VD] INCONCLUSIVE 에 필요표본 미동봉: {r.reason}")
    # NOT_MEASURABLE: T0 배치 게이트
    nm = gate(t, 0, "unsync")
    if nm is None or nm.verdict != NOT_MEASURABLE or "tier≥1" not in nm.reason:
        ok = False
        print(f"  [VD] ratio T0 게이트 실패: {nm}")
    # conservative 부기: FAIL 에 재시험 권고가 붙어야 한다
    rf = decide_ratio(t, ReliabilityEstimate(1000, 900))
    if not (rf.conservative and "T2+shared" in rf.reason):
        ok = False
        print(f"  [VD] conservative FAIL 부기 누락: {rf.reason}")
    elif verbose:
        print("  [VD] ratio 4치 전이 + conservative 부기 OK")

    # 3) quantile 4치 전이 + 표본 게이트 + ptp 오차 밴드
    from .kpi import QuantileEstimate as QE
    tq = KpiTarget(name="lat", kind="quantile", metric="owd_ul_ms", basis="owd",
                   op="<=", value=2.0, unit="ms", quantile=0.99, provenance=prov)
    vals_pass = [1.0] * 2000
    vals_fail = [3.0] * 2000
    if decide_quantile(tq, QE.from_samples(vals_pass, 0.99)).verdict != PASS:
        ok = False
        print("  [VD] quantile PASS 실패")
    if decide_quantile(tq, QE.from_samples(vals_fail, 0.99)).verdict != FAIL:
        ok = False
        print("  [VD] quantile FAIL 실패")
    small = decide_quantile(tq, QE.from_samples([1.0] * 100, 0.99))
    if small.verdict != INCONCLUSIVE or "게이트" not in small.reason:
        ok = False
        print(f"  [VD] quantile 표본 게이트 실패: {small.reason}")
    # ptp 밴드: Q̂=1.9±0 & err=0.2 → 1.9+0.2 > 2.0 이고 1.9−0.2 ≤ 2.0 → INCONCLUSIVE
    band = decide_quantile(tq, QE.from_samples([1.9] * 2000, 0.99), ptp_err_ms=0.2)
    if band.verdict != INCONCLUSIVE:
        ok = False
        print(f"  [VD] ptp 오차 밴드 오류: {band.verdict}")
    elif verbose:
        print("  [VD] quantile 4치 + ptp 밴드(INCONCLUSIVE) OK")

    # 4) survival / availability — PASS 는 어떤 입력으로도 나오지 않아야 한다
    from .kpi import SurvivalReport as SR
    ts = KpiTarget(name="surv", kind="survival", metric="delivery",
                   basis="rtt-conservative", transfer_interval_ms=2.0,
                   survival_time_ms=2.0, provenance=prov)
    ta = KpiTarget(name="avail", kind="availability", metric="delivery",
                   basis="rtt-conservative", op=">=", value=0.99999,
                   transfer_interval_ms=2.0, survival_time_ms=2.0, provenance=prov)
    perfect = SR([], 0.0, 600000.0, 300000, 0)
    violated = SR([(10.0, 6.0)], 6.0, 20.0, 11, 3)
    if decide_survival(ts, perfect).verdict != INCONCLUSIVE:
        ok = False
        print("  [VD] 무사건 survival 이 INCONCLUSIVE 가 아님")
    if decide_survival(ts, violated).verdict != FAIL:
        ok = False
        print("  [VD] down 사건이 FAIL 이 아님")
    if decide_availability(ta, perfect).verdict != INCONCLUSIVE:
        ok = False
        print("  [VD] availability 가 PASS/FAIL 을 냄 (무사건)")
    if decide_availability(ta, violated).verdict != FAIL:
        ok = False
        print("  [VD] availability 대규모 위반이 FAIL 이 아님")
    for rep in (perfect, violated, SR([], 0.0, 0.0, 0, 0)):
        for fn, tt in ((decide_survival, ts), (decide_availability, ta)):
            if fn(tt, rep).verdict == PASS:
                ok = False
                print(f"  [VD] {fn.__name__} 이 PASS 를 냄 — falsify 전용 위반")
    if verbose and ok:
        print("  [VD] survival/availability: FAIL|INCONCLUSIVE 만 (PASS 구조적 불가) OK")

    # 5) rate: 관측 부족 → INCONCLUSIVE, 충분 → 점 비교
    tr = KpiTarget(name="dlrate", kind="rate", metric="dl_goodput_mbps",
                   basis="measured-wire", op=">=", value=30.0, unit="mbps",
                   provenance=prov)
    if decide_rate(tr, 45.0, 5).verdict != INCONCLUSIVE:
        ok = False
        print("  [VD] rate 관측부족 게이트 실패")
    if decide_rate(tr, 45.0, 100).verdict != PASS \
            or decide_rate(tr, 20.0, 100).verdict != FAIL:
        ok = False
        print("  [VD] rate 점 비교 실패")

    # 6) delta: 격리 유지 → PASS, 명확한 열화 → FAIL, 경계 → INCONCLUSIVE
    td = KpiTarget(name="iso", kind="delta", metric="delivery",
                   basis="rtt-conservative", op="<=", value=0.001,
                   ref_phase="baseline", delta_mode="abs", provenance=prov)
    big = 2_000_000
    if decide_delta_ratio(td, big - 100, big, big - 100, big).verdict != PASS:
        ok = False
        print("  [VD] delta 격리유지 PASS 실패")
    if decide_delta_ratio(td, 9000, 10000, 9990, 10000).verdict != FAIL:
        ok = False
        print("  [VD] delta 열화 FAIL 실패")
    if decide_delta_ratio(td, 985, 1000, 990, 1000).verdict != INCONCLUSIVE:
        ok = False
        print("  [VD] delta 경계 INCONCLUSIVE 실패")
    # delta(quantile, rel): +20% 허용, +20% 정확 관측 → CI 가 걸침 → INCONCLUSIVE
    tdq = KpiTarget(name="latiso", kind="delta", metric="rtt_net_ms",
                    basis="rtt-conservative", op="<=", value=0.2,
                    ref_phase="baseline", delta_mode="rel", provenance=prov)
    vals = [i / 10.0 for i in range(1, 2001)]
    q0 = QE.from_samples(vals, 0.99)
    q1 = QE.from_samples([v * 1.2 for v in vals], 0.99)
    if decide_delta_quantile(tdq, q1, q0).verdict != INCONCLUSIVE:
        ok = False
        print("  [VD] delta quantile 경계 처리 오류")
    q2 = QE.from_samples([v * 2.0 for v in vals], 0.99)
    if decide_delta_quantile(tdq, q2, q0).verdict != FAIL:
        ok = False
        print("  [VD] delta quantile 2배 열화 FAIL 실패")

    # 7) 집계 규칙 (§5)
    def mk(v):
        return VerdictRecord(target="t", phase="p", population="u", kind="ratio",
                             metric="delivery", basis="rtt-conservative", verdict=v)
    agg_cases = [
        ([PASS, PASS], PASS),
        ([PASS, INCONCLUSIVE], INCONCLUSIVE),
        ([FAIL, INCONCLUSIVE, PASS], FAIL),
        ([PASS, NOT_MEASURABLE], PASS),            # NM 은 집계 불참
        ([NOT_MEASURABLE, NOT_MEASURABLE], NOT_MEASURABLE),  # 전부 NM → NM
    ]
    for vs, expect in agg_cases:
        got = aggregate([mk(v) for v in vs])
        if got != expect:
            ok = False
            print(f"  [VD] 집계 오류 {vs} → {got} (기대 {expect})")

    # 8) 렌더링: JSON 왕복 + 스키마 필수키, markdown 은 NM 을 앞에 목록화
    recs = [decide_ratio(t, ReliabilityEstimate(10000, 10000)),
            gate(KpiTarget(name="sense", kind="ratio", metric="sensing_accuracy",
                           basis="rtt-conservative", value=0.95, pdb_ms=1000.0,
                           provenance=prov), 2, "shared")]
    js = json.loads(render_json(recs, fingerprint={"seed": 42}))
    if (js["verdict"] != INCONCLUSIVE or len(js["not_measurable"]) != 1
            or js["fingerprint"]["seed"] != 42):
        ok = False
        print(f"  [VD] JSON 렌더 오류: {js['verdict']}, {js['counts']}")
    for must in ("target", "verdict", "kind", "metric", "basis", "provenance"):
        if must not in js["verdicts"][0]:
            ok = False
            print(f"  [VD] JSON 스키마 필수키 누락: {must}")
    md = render_markdown(recs)
    if md.index("Not measurable") > md.index("## Verdicts"):
        ok = False
        print("  [VD] markdown 에서 NM 목록이 앞에 오지 않음")
    if "sensing_accuracy" not in md or "INCONCLUSIVE" not in md:
        ok = False
        print("  [VD] markdown 내용 누락")
    elif verbose:
        print("  [VD] JSON/markdown 렌더(NM 선두 목록화) OK")

    return ok


if __name__ == "__main__":
    print("VERDICT selftest:", "PASS" if selftest(verbose=True) else "FAIL")
