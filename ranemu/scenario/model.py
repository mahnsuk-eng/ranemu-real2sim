#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.model — 서비스 시나리오 object model (설계 §2).

원칙
====
- **요구값은 코드가 아니라 데이터다.** KpiTarget 은 자유 텍스트가 아니라 검사 가능한
  술어(predicate)의 닫힌 집합이며, 종류별 필수 필드를 `validate()` 가 강제한다.
- **판본 없는 인용 금지.** KpiProvenance.version 이 비어 있으면 검증 실패다 —
  3GPP 표는 판본 간에 값이 이동한 전력이 있다(예: 5QI 87 PDB 를 30 ms 로 잘못 적은
  2차 출처가 실재; 원문 V20.2.0 은 5 ms).
- 로더는 config.py 의 `_build`/`_coerce` 재귀 관례를 그대로 따른다(중첩 dataclass 를
  타입표로 해석). config.py 의 것을 import 하지 않는 이유: 그쪽 `_resolve` 는 자기
  타입표에 폐쇄돼 있고, 기존 파일은 다른 작업자가 소유하므로 additive 하게 둔다.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict, fields, is_dataclass
from typing import Any, Dict, List, Optional

from ..util import get_logger

log = get_logger("ranemu.scenario.model")

# 닫힌 어휘 — verdict/kpi 가 이 집합에 의존한다
TARGET_KINDS = ("quantile", "ratio", "rate", "survival", "availability",
                "delta", "population")
PROVENANCE_KINDS = ("service_requirement", "qos_characteristic",
                    "evaluation_assumption", "industry_sla")
BASIS_SET = ("measured-wire", "measured-shared-clock", "measured-ptp",
             "rtt-conservative", "owd", "composed", "modelled")
CLOCK_DOMAINS = ("shared", "ptp", "unsync")
ROLES = ("sut", "background")


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class KpiProvenance:
    """요구값의 출처 — 판정 보고서까지 그대로 실려 역추적을 가능하게 한다."""
    spec: str = ""            # "TS 22.104"
    version: str = ""         # "19.2.0" — 필수. 판본 없는 인용 금지.
    clause: str = ""          # "Table 5.2-1, 'Motion control panel'"
    #: 방어장치: 이 값이 규범 요구인지, QoS 특성인지, 평가 가정인지, 산업 SLA 인지.
    #: 판정 보고서는 kind 를 병기해 "무엇에 대한 적합성" 인지 스스로 한정한다.
    kind: str = ""
    note: str = ""

    def validate(self, where: str = "") -> List[str]:
        errs = []
        for f in ("spec", "version", "clause", "kind"):
            if not getattr(self, f):
                errs.append(f"{where}provenance.{f} 누락 — 판본/조항 없는 인용 금지")
        if self.kind and self.kind not in PROVENANCE_KINDS:
            errs.append(f"{where}provenance.kind={self.kind!r} 는 "
                        f"{PROVENANCE_KINDS} 중 하나여야 함")
        return errs


@dataclass
class KpiTarget:
    """검사 가능한 술어. kind 가 술어 종류를, 종류별 필수 필드를 validate 가 강제."""
    name: str = ""
    kind: str = ""                    # TARGET_KINDS
    metric: str = ""                  # kpi §4 metric 레지스트리 키
    basis: str = ""                   # 요구 measurement basis — 미제공 배치는 NOT_MEASURABLE
    op: str = "<="                    # "<=" | ">="
    value: float = 0.0
    unit: str = ""
    # kind == "quantile"
    quantile: Optional[float] = None
    # kind == "ratio" (3GPP reliability: delivered AND delay ≤ PDB)
    pdb_ms: Optional[float] = None
    success_unit: str = "packet"      # "packet" | "frame"
    # kind == "survival" / "availability"
    transfer_interval_ms: Optional[float] = None
    survival_time_ms: Optional[float] = None
    # kind == "delta"
    ref_phase: Optional[str] = None
    delta_mode: str = "abs"           # "abs" | "rel"
    # 통계 게이트
    confidence: float = 0.95
    # 적용 범위
    applies_to: str = "*"
    phases: List[str] = field(default_factory=lambda: ["*"])
    #: 카탈로그 참조 — 지정되면 위 필드들은 KpiCatalog.materialize 로 채워진다.
    catalog_ref: Optional[str] = None
    provenance: KpiProvenance = field(default_factory=KpiProvenance)

    def is_resolved(self) -> bool:
        return bool(self.kind and self.metric)

    def validate(self, where: str = "") -> List[str]:  # noqa: C901
        if self.catalog_ref and not self.is_resolved():
            # 미해결 참조는 오류가 아니라 '해결 필요' 상태 — materialize 전 실행만 금지.
            return [f"{where}catalog_ref={self.catalog_ref!r} 미해결 — "
                    f"KpiCatalog.materialize 필요"]
        errs: List[str] = []
        if self.kind not in TARGET_KINDS:
            errs.append(f"{where}kind={self.kind!r} 는 {TARGET_KINDS} 중 하나여야 함")
        if not self.metric:
            errs.append(f"{where}metric 누락")
        if self.op not in ("<=", ">="):
            errs.append(f"{where}op={self.op!r} 는 <=|>= 만 허용")
        if self.basis not in BASIS_SET:
            errs.append(f"{where}basis={self.basis!r} 는 {BASIS_SET} 중 하나여야 함")
        if not (0.0 < self.confidence < 1.0):
            errs.append(f"{where}confidence 는 (0,1): {self.confidence}")
        if self.kind == "quantile":
            if self.quantile is None or not (0.0 < self.quantile < 1.0):
                errs.append(f"{where}quantile 술어에는 quantile∈(0,1) 필수")
        elif self.kind == "ratio":
            if not (0.0 < self.value <= 1.0):
                errs.append(f"{where}ratio 값은 (0,1]: {self.value}")
            if self.metric == "delivery" and (self.pdb_ms is None or self.pdb_ms <= 0):
                errs.append(f"{where}delivery ratio 에는 pdb_ms>0 필수 — "
                            f"PDB 없는 신뢰도는 raw loss 이지 3GPP reliability 가 아님")
            if self.success_unit not in ("packet", "frame"):
                errs.append(f"{where}success_unit={self.success_unit!r}")
        elif self.kind in ("survival", "availability"):
            if self.transfer_interval_ms is None or self.transfer_interval_ms <= 0:
                errs.append(f"{where}{self.kind} 에는 transfer_interval_ms>0 필수")
            if self.survival_time_ms is None or self.survival_time_ms <= 0:
                errs.append(f"{where}{self.kind} 에는 survival_time_ms>0 필수")
            if self.kind == "availability" and not (0.0 < self.value < 1.0):
                errs.append(f"{where}availability 값은 (0,1): {self.value}")
        elif self.kind == "delta":
            if not self.ref_phase:
                errs.append(f"{where}delta 에는 ref_phase 필수")
            if self.delta_mode not in ("abs", "rel"):
                errs.append(f"{where}delta_mode={self.delta_mode!r}")
        errs += self.provenance.validate(where)
        return errs


@dataclass
class UePopulation:
    """UeGroupConfig 를 감싸는 상위 개념 — 컴파일 시 UeGroupConfig 로 낮춰진다."""
    name: str = ""
    count: int = 1
    role: str = "sut"                 # "sut" (판정 대상) | "background" (부하만)
    features: List[str] = field(default_factory=list)
    feature_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    traffic: Dict[str, Any] = field(default_factory=dict)
    dnn: str = "internet"
    sst: int = 1
    sd: Optional[str] = None
    imsi_start: Optional[str] = None
    ramp_seconds: float = 0.0
    # 측정 설정
    stamp: bool = True
    #: 1.0 = 전 패킷 스탬프, <1 = 표본 스탬프(소형 메시지 팽창 회피, §3.6 정책 b)
    stamp_sample: float = 1.0
    #: 소형 메시지 정책: "inflate"(48 B 로 키움, verdict 에 payload_inflated 기록)
    stamp_policy: str = "inflate"     # "inflate" | "sample"

    def validate(self, where: str = "") -> List[str]:
        errs = []
        if not self.name:
            errs.append(f"{where}name 누락")
        if self.count <= 0:
            errs.append(f"{where}count 는 1 이상: {self.count}")
        if self.role not in ROLES:
            errs.append(f"{where}role={self.role!r} 는 {ROLES} 중 하나여야 함")
        if not (0.0 < self.stamp_sample <= 1.0):
            errs.append(f"{where}stamp_sample∈(0,1]: {self.stamp_sample}")
        if self.stamp_policy not in ("inflate", "sample"):
            errs.append(f"{where}stamp_policy={self.stamp_policy!r}")
        try:
            from ..features import unknown_features
            unknown = unknown_features(self.features)
            if unknown:
                errs.append(f"{where}알 수 없는 feature: {sorted(unknown)}")
        except Exception as e:  # noqa: BLE001 — 레지스트리 임포트 실패도 표면화
            errs.append(f"{where}feature 검증 실패: {e}")
        return errs


@dataclass
class ImpairmentSpec:
    """phase 전이 시 무선조건 변경 — 기존 shaper/radio 객체에 매핑된다(§6.2)."""
    target: str = "*"
    sinr_delta_db: Optional[float] = None
    loss_add: Optional[float] = None
    owd_add_ms: Optional[float] = None
    interrupt_period_s: Optional[float] = None
    interrupt_ms: Optional[float] = None


@dataclass
class Phase:
    name: str = ""
    duration_s: float = 0.0
    warmup_s: float = 5.0             # 측정창에서 제외(§3.7)
    load_scale: Dict[str, float] = field(default_factory=dict)
    active_scale: Dict[str, float] = field(default_factory=dict)
    impair: List[ImpairmentSpec] = field(default_factory=list)

    def validate(self, where: str = "") -> List[str]:
        errs = []
        if not self.name:
            errs.append(f"{where}name 누락")
        if self.duration_s <= 0:
            errs.append(f"{where}duration_s>0 필요: {self.duration_s}")
        if self.warmup_s < 0 or self.warmup_s >= self.duration_s:
            errs.append(f"{where}warmup_s({self.warmup_s}) 는 "
                        f"[0, duration_s) 이어야 함")
        return errs


@dataclass
class MeasurementConfig:
    """배치가 제공하는 측정 능력의 선언 — verdict 의 measurability 게이트 입력."""
    #: 이 시나리오가 요구하는 최소 배치 tier (§3.3). 미달 target 은 NOT_MEASURABLE.
    tier_min: int = 1
    #: 기본값은 가장 보수적인 unsync — 선언하지 않은 배치는 OWD 를 주장할 수 없다.
    clock_domain: str = "unsync"
    #: clock_domain=ptp 일 때 운영자가 선언하는 잔여오차 상한(§3.2). 동기 프로토콜을
    #: 구현하지 않는다는 금지목록 §11-8 에 따라 err 는 입력값이다.
    ptp_err_ms: float = 0.0
    radio_delay_physical: bool = False
    #: None 이면 stamp.FlowLedger 의 공식 max(4×PDB, 8×p95, 250 ms) 사용
    t_resolve_ms: Optional[float] = None
    reflector_addr: Optional[str] = None
    reflector_port: int = 9462
    stamp_checksum: str = "incremental"   # "incremental" | "zero" (RFC 768 폴백)

    def validate(self, where: str = "") -> List[str]:
        errs = []
        if self.tier_min not in (0, 1, 2):
            errs.append(f"{where}tier_min 은 0|1|2: {self.tier_min}")
        if self.clock_domain not in CLOCK_DOMAINS:
            errs.append(f"{where}clock_domain={self.clock_domain!r} 는 "
                        f"{CLOCK_DOMAINS} 중 하나여야 함")
        if self.clock_domain == "ptp" and self.ptp_err_ms <= 0:
            errs.append(f"{where}clock_domain=ptp 에는 ptp_err_ms>0 선언 필수")
        if self.t_resolve_ms is not None and self.t_resolve_ms <= 0:
            errs.append(f"{where}t_resolve_ms>0 필요")
        if self.stamp_checksum not in ("incremental", "zero"):
            errs.append(f"{where}stamp_checksum={self.stamp_checksum!r}")
        return errs


@dataclass
class ServiceScenario:
    id: str = ""
    title: str = ""
    service_class: str = ""           # "URLLC" | "XR" | "mMTC" | "NTN" | ...
    references: List[KpiProvenance] = field(default_factory=list)
    populations: List[UePopulation] = field(default_factory=list)
    phases: List[Phase] = field(default_factory=list)
    targets: List[KpiTarget] = field(default_factory=list)
    measurement: MeasurementConfig = field(default_factory=MeasurementConfig)
    seed: int = 42

    # ── 편의 ────────────────────────────────────────────────────────────
    def population(self, name: str) -> Optional[UePopulation]:
        for p in self.populations:
            if p.name == name:
                return p
        return None

    def total_duration_s(self) -> float:
        return sum(p.duration_s for p in self.phases)

    def validate(self) -> List[str]:  # noqa: C901
        errs: List[str] = []
        if not self.id:
            errs.append("id 누락")
        if not self.populations:
            errs.append("populations 비어 있음")
        if not self.phases:
            errs.append("phases 비어 있음")
        if not self.targets:
            errs.append("targets 비어 있음")

        pop_names = [p.name for p in self.populations]
        if len(set(pop_names)) != len(pop_names):
            errs.append(f"population 이름 중복: {pop_names}")
        phase_names = [p.name for p in self.phases]
        if len(set(phase_names)) != len(phase_names):
            errs.append(f"phase 이름 중복: {phase_names}")

        for i, p in enumerate(self.populations):
            errs += p.validate(f"populations[{i}].")
        for i, ph in enumerate(self.phases):
            errs += ph.validate(f"phases[{i}].")
            for scale in (ph.load_scale, ph.active_scale):
                for k in scale:
                    if k not in pop_names:
                        errs.append(f"phases[{ph.name}] 가 모르는 population "
                                    f"{k!r} 을 참조")
            for imp in ph.impair:
                if imp.target != "*" and imp.target not in pop_names:
                    errs.append(f"phases[{ph.name}].impair 가 모르는 population "
                                f"{imp.target!r} 을 참조")
        for i, t in enumerate(self.targets):
            errs += t.validate(f"targets[{i}].")
            if t.applies_to != "*" and t.applies_to not in pop_names:
                errs.append(f"targets[{i}].applies_to={t.applies_to!r} — "
                            f"해당 population 없음")
            for ph in t.phases:
                if ph != "*" and ph not in phase_names:
                    errs.append(f"targets[{i}].phases 의 {ph!r} — 해당 phase 없음")
            if t.is_resolved() and t.kind == "delta" and t.ref_phase \
                    and t.ref_phase not in phase_names:
                errs.append(f"targets[{i}].ref_phase={t.ref_phase!r} — 해당 phase 없음")

        errs += self.measurement.validate("measurement.")
        if not (0 <= self.seed < 2**63):
            errs.append(f"seed 범위 오류: {self.seed}")
        return errs

    def content_hash(self) -> str:
        """verdict 재현성 fingerprint.

        asdict + sort_keys 로 canonical JSON 을 만들므로 YAML/JSON 의 키 순서,
        딕셔너리 삽입 순서와 무관하게 **내용이 같으면 해시가 같다**. 리스트 순서는
        의미가 있으므로(phase 순서 등) 정렬하지 않는다.
        """
        blob = json.dumps(asdict(self), sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ─────────────────────────────────────────────────────────────────────────────
# 로딩 — config.py 의 _build/_coerce 관례
# ─────────────────────────────────────────────────────────────────────────────
def _build(cls, data: Any):
    """중첩 dataclass 를 재귀적으로 구성(리스트 원소 타입도 처리)."""
    if data is None:
        return cls()
    if not is_dataclass(cls):
        return data
    if not isinstance(data, dict):
        raise TypeError(f"{cls.__name__} 에는 매핑이 필요합니다 "
                        f"(got {type(data).__name__})")
    kwargs: Dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}
    for key, val in data.items():
        if key not in known:
            log.warning("시나리오에 알 수 없는 항목 무시: %s.%s", cls.__name__, key)
            continue
        ftype = known[key].type
        if isinstance(ftype, str):
            ftype = _resolve(ftype)
        kwargs[key] = _coerce(ftype, val)
    return cls(**kwargs)


_TYPE_TABLE = {
    "KpiProvenance": lambda: KpiProvenance, "KpiTarget": lambda: KpiTarget,
    "UePopulation": lambda: UePopulation, "ImpairmentSpec": lambda: ImpairmentSpec,
    "Phase": lambda: Phase, "MeasurementConfig": lambda: MeasurementConfig,
    "ServiceScenario": lambda: ServiceScenario,
}


def _resolve(ann: str):
    ann = ann.strip()
    for name, getter in _TYPE_TABLE.items():
        if ann == name:
            return getter()
        if ann.startswith("List[") and name in ann:
            return [getter()]
        if ann.startswith("Optional[") and ann == f"Optional[{name}]":
            return getter()
    return None


def _coerce(ftype, val):
    if ftype is None:
        return val
    if isinstance(ftype, list):
        inner = ftype[0]
        return [_build(inner, v) for v in (val or [])]
    if is_dataclass(ftype):
        return _build(ftype, val)
    return val


def loads(data: Dict[str, Any]) -> ServiceScenario:
    return _build(ServiceScenario, data)


def load(path: str) -> ServiceScenario:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        import yaml
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")
    sc = loads(data)
    log.info("시나리오 로드: %s (%s, 모집단 %d, phase %d, target %d)",
             path, sc.id, len(sc.populations), len(sc.phases), len(sc.targets))
    return sc


# ─────────────────────────────────────────────────────────────────────────────
def _valid_scenario() -> ServiceScenario:
    """selftest 용 최소 유효 시나리오."""
    prov = KpiProvenance(spec="TS 23.501", version="20.2.0",
                         clause="Table 5.7.4-1, 5QI 82", kind="qos_characteristic")
    return ServiceScenario(
        id="t-min", title="minimal", service_class="URLLC",
        references=[prov],
        populations=[UePopulation(name="a", count=2, features=["urllc"],
                                  traffic={"pattern": "periodic", "period_ms": 2})],
        phases=[Phase(name="baseline", duration_s=30.0, warmup_s=5.0),
                Phase(name="loaded", duration_s=60.0, warmup_s=5.0,
                      active_scale={"a": 1.0})],
        targets=[
            KpiTarget(name="rel", kind="ratio", metric="delivery",
                      basis="rtt-conservative", op=">=", value=0.9999,
                      pdb_ms=10.0, provenance=prov),
            KpiTarget(name="lat", kind="quantile", metric="rtt_net_ms",
                      basis="rtt-conservative", op="<=", value=10.0, unit="ms",
                      quantile=0.98, provenance=prov),
        ],
        measurement=MeasurementConfig(tier_min=2, clock_domain="shared"),
    )


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    import os
    import tempfile

    ok = True

    # 1) 유효 시나리오는 문제 0건
    sc = _valid_scenario()
    errs = sc.validate()
    if errs:
        ok = False
        print(f"  [MD] 유효 시나리오가 거부됨: {errs}")
    elif verbose:
        print("  [MD] 최소 유효 시나리오 validate OK")

    # 2) 중첩 로딩 — dict → dataclass 트리 (config.py 관례)
    sc2 = loads({
        "id": "t2", "service_class": "XR",
        "populations": [{"name": "p", "count": 3, "features": ["xr"],
                         "traffic": {"pattern": "periodic"}}],
        "phases": [{"name": "b", "duration_s": 10.0, "warmup_s": 1.0,
                    "impair": [{"target": "p", "sinr_delta_db": -5.0}]}],
        "targets": [{"name": "t", "kind": "quantile", "metric": "frame_delay_ms",
                     "basis": "measured-shared-clock", "quantile": 0.99,
                     "value": 10.0,
                     "provenance": {"spec": "TR 38.838", "version": "17.0.0",
                                    "clause": "§5", "kind": "evaluation_assumption"}}],
        "measurement": {"tier_min": 2, "clock_domain": "shared"},
    })
    if (not isinstance(sc2.populations[0], UePopulation)
            or not isinstance(sc2.phases[0].impair[0], ImpairmentSpec)
            or not isinstance(sc2.targets[0].provenance, KpiProvenance)
            or sc2.phases[0].impair[0].sinr_delta_db != -5.0):
        ok = False
        print("  [MD] 중첩 dataclass 구성 실패")
    elif sc2.validate():
        ok = False
        print(f"  [MD] 로드된 시나리오 검증 실패: {sc2.validate()}")
    elif verbose:
        print("  [MD] 중첩 로딩(impair/provenance 포함) OK")

    # 3) 술어 필수필드 강제 — 종류별로 하나씩 빠뜨려 본다
    bad_cases = [
        ({"kind": "quantile", "metric": "rtt_net_ms", "basis": "owd"},
         "quantile"),                                     # quantile 값 누락
        ({"kind": "ratio", "metric": "delivery", "basis": "rtt-conservative",
          "value": 0.999}, "pdb_ms"),                     # PDB 누락
        ({"kind": "survival", "metric": "delivery", "basis": "rtt-conservative",
          "transfer_interval_ms": 2.0}, "survival_time_ms"),
        ({"kind": "delta", "metric": "delivery", "basis": "rtt-conservative"},
         "ref_phase"),
        ({"kind": "ratio", "metric": "delivery", "basis": "rtt-conservative",
          "value": 0.999, "pdb_ms": 1.0,
          "provenance": {"spec": "TS X", "clause": "c",
                         "kind": "service_requirement"}}, "version"),  # 판본 누락
    ]
    for data, expect in bad_cases:
        t = _build(KpiTarget, data)
        problems = t.validate()
        if not any(expect in p for p in problems):
            ok = False
            print(f"  [MD] {expect} 누락이 검출되지 않음: {problems}")
    if verbose and ok:
        print("  [MD] 술어 필수필드 강제(5종) OK")

    # 4) 시나리오 수준 교차참조 검증
    bad = _valid_scenario()
    bad.targets[0].applies_to = "ghost"
    bad.phases[1].active_scale = {"ghost": 1.0}
    bad.measurement.clock_domain = "ptp"     # err 미선언
    problems = bad.validate()
    if len(problems) < 3:
        ok = False
        print(f"  [MD] 교차참조/ptp 오류 미검출: {problems}")
    elif verbose:
        print("  [MD] 교차참조·ptp err 필수 검증 OK")

    # 5) content_hash: 동일 내용 → 동일, 값 변경 → 상이, 키 순서 무관
    h1 = _valid_scenario().content_hash()
    h2 = _valid_scenario().content_hash()
    mod = _valid_scenario()
    mod.targets[0].value = 0.99999
    if h1 != h2 or h1 == mod.content_hash():
        ok = False
        print("  [MD] content_hash 안정성/민감성 오류")
    d1 = {"id": "h", "seed": 7, "title": "x"}
    d2 = {"title": "x", "id": "h", "seed": 7}
    if loads(d1).content_hash() != loads(d2).content_hash():
        ok = False
        print("  [MD] content_hash 가 키 순서에 의존")
    elif verbose:
        print(f"  [MD] content_hash 재현성 OK ({h1[:16]}…)")

    # 6) 파일 왕복(JSON) — load() 경로
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "sc.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(_valid_scenario()), fh, ensure_ascii=False)
        sc3 = load(path)
        if sc3.content_hash() != h1 or sc3.validate():
            ok = False
            print("  [MD] 파일 왕복 후 해시/검증 불일치")
        elif verbose:
            print("  [MD] JSON 파일 왕복(해시 보존) OK")

    # 7) 미해결 catalog_ref 는 '해결 필요' 로 표면화되어야 한다
    t = KpiTarget(catalog_ref="ts23501.5qi82.latency")
    msgs = t.validate()
    if not (len(msgs) == 1 and "materialize" in msgs[0]):
        ok = False
        print(f"  [MD] catalog_ref 미해결 처리 오류: {msgs}")

    return ok


if __name__ == "__main__":
    print("MODEL selftest:", "PASS" if selftest(verbose=True) else "FAIL")
