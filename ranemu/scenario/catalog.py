#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.catalog — KPI 요구값 전사 데이터 + 내장 시나리오 8종 (설계 §8).

전사 규율
=========
- **요구값은 코드가 아니라 데이터다.** 모든 값은 spec/version/clause/kind 의
  KpiProvenance 를 달고 들어온다. 판본 없는 인용은 model.validate 가 거부한다.
- `verified_against_source` 는 **EVIDENCE.md §7-B 에 spec+version+clause+값이
  원문 추출로 존재하는 항목만 True** 다. 설계 초안 표에서만 온 값, 2차 출처 경유
  값, 매핑으로 유도한 값은 전부 False — 조항 번호를 발명하지 않는다.
  (실제 사례: 5QI 87 의 PDB 를 30 ms 로 적은 2차 출처가 있었고 원문은 5 ms 였다.
  이 파일은 5 ms 를 싣는다.)
- `value_pending=True` 항목은 값 자체가 아직 원문 대조되지 않았다(예: TS 22.261
  Table 7.10 의 AI/ML 수치). resolve 가 기본 거부한다 — 자리표시자 값으로 판정이
  나가는 사고를 구조적으로 막는다(§12 의 'catalog verify 거부' 게이트).
- kind 는 EVIDENCE §7 의 규범/연구 구분을 따른다: TS → service_requirement 또는
  qos_characteristic, TR → evaluation_assumption, GSMA → industry_sla.
  TS 22.104 Table 5.2-1 은 규범 문서의 *characteristic parameter* 이므로
  kind 는 service_requirement 로 두되 note 에 그 성격을 병기한다(§2.1).
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .model import (ImpairmentSpec, KpiProvenance, KpiTarget, MeasurementConfig,
                    Phase, ServiceScenario, UePopulation)

# ─────────────────────────────────────────────────────────────────────────────
# 출처 상수 — 판본은 EVIDENCE.md §7-B 의 원문 확인 판본
# ─────────────────────────────────────────────────────────────────────────────
_CHAR_NOTE = ("characteristic parameter — 서비스 성격 기술값이지 "
              "규범 conformance 요구가 아님")


def _p23501(qi: int) -> KpiProvenance:
    return KpiProvenance(spec="TS 23.501", version="20.2.0",
                         clause=f"Table 5.7.4-1, 5QI {qi}",
                         kind="qos_characteristic")


def _p22104(row: str) -> KpiProvenance:
    return KpiProvenance(spec="TS 22.104", version="19.2.0",
                         clause=f"Table 5.2-1, '{row}'",
                         kind="service_requirement", note=_CHAR_NOTE)


_P22186_RD = KpiProvenance(spec="TS 22.186", version="19.1.0",
                           clause="Table 5.5-1 (remote driving)",
                           kind="service_requirement")
_P22261_RENDER = KpiProvenance(spec="TS 22.261", version="20.7.0",
                               clause="Table 7.6.1-1 (cloud/edge/split rendering)",
                               kind="service_requirement")
_P22261_AIML = KpiProvenance(spec="TS 22.261", version="20.7.0",
                             clause="§6.40 / Table 7.10 (AI/ML model transfer)",
                             kind="service_requirement",
                             note="수치는 원문 미대조 — value_pending")
_P38838 = KpiProvenance(spec="TR 38.838", version="17.0.0",
                        clause=("§5 — 조항 단위 인용 미확보; Gapeyenko et al., "
                                "IEEE Network 37:22-28 (2023), "
                                "doi:10.1109/MNET.003.2300062, Table I 경유"),
                        kind="evaluation_assumption")
_P38875 = KpiProvenance(spec="TR 38.875", version="unverified",
                        clause="설계 초안 전사 (조항 미확인)",
                        kind="evaluation_assumption")
_P38821 = KpiProvenance(spec="TR 38.821", version="unverified",
                        clause="설계 초안 전사 (GEO RTT ~541 ms; 조항 미확인)",
                        kind="evaluation_assumption")
_P38848 = KpiProvenance(spec="TR 38.848", version="18.0.0",
                        clause="§5.4-§5.6 (rate/message/latency)",
                        kind="evaluation_assumption")
_P22137 = KpiProvenance(spec="TS 22.137", version="19.1.0",
                        clause="Table 6.2-1, scenario 4 (factory)",
                        kind="service_requirement",
                        note="TR 22.837 은 연구지만 TS 22.137 은 규범이다")
_PNG116 = KpiProvenance(spec="GSMA NG.116", version="8.0",
                        clause="slice isolation attributes",
                        kind="industry_sla")
_P28541 = KpiProvenance(spec="TS 28.541", version="unverified",
                        clause="GST (값 미전사)", kind="industry_sla")


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class CatalogEntry:
    key: str
    target: KpiTarget
    #: EVIDENCE.md §7-B 원문 추출로 spec+version+clause+값이 확인된 항목만 True
    verified_against_source: bool = False
    #: 값 자체가 미전사 — resolve 기본 거부
    value_pending: bool = False
    note: str = ""


class KpiCatalog:
    """요구값 전사의 단일 출처. 시나리오는 키로 참조한다 — 스펙 개정 시 diff 가능."""

    def __init__(self, entries: List[CatalogEntry]):
        self._entries: Dict[str, CatalogEntry] = {}
        for e in entries:
            if e.key in self._entries:
                raise ValueError(f"카탈로그 키 중복: {e.key}")
            self._entries[e.key] = e

    def keys(self) -> List[str]:
        return sorted(self._entries)

    def get(self, key: str) -> CatalogEntry:
        if key not in self._entries:
            raise KeyError(f"카탈로그에 없는 키: {key}")
        return self._entries[key]

    def unverified_keys(self) -> List[str]:
        return sorted(k for k, e in self._entries.items()
                      if not e.verified_against_source)

    def resolve(self, key: str, *, applies_to: str = "*",
                phases: Optional[List[str]] = None, name: Optional[str] = None,
                allow_pending: bool = False, strict: bool = False) -> KpiTarget:
        """카탈로그 항목 → 시나리오 target (깊은 복사 + 적용범위 덮어쓰기).

        strict=True 는 §12 의 '대조 완료 플래그 없는 항목의 로드 거부' 게이트:
        verified_against_source=False 항목으로는 target 을 만들지 않는다.
        """
        e = self.get(key)
        if e.value_pending and not allow_pending:
            raise ValueError(f"{key}: 값 미전사(value_pending) — 원문 대조 전에는 "
                             f"판정 target 으로 쓸 수 없다")
        if strict and not e.verified_against_source:
            raise ValueError(f"{key}: 원문 대조 미완(verified_against_source=False)"
                             f" — strict 로드 거부")
        t = copy.deepcopy(e.target)
        t.catalog_ref = key
        t.applies_to = applies_to
        if phases is not None:
            t.phases = list(phases)
        if name is not None:
            t.name = name
        return t

    def verify_scenario(self, scenario: ServiceScenario) -> List[str]:
        """시나리오가 참조한 항목 중 원문 미대조/미전사 목록 — 숨기지 않고 보고."""
        problems = []
        for t in scenario.targets:
            if not t.catalog_ref:
                problems.append(f"{t.name}: 카탈로그 외 인라인 값 (검증 이력 없음)")
                continue
            e = self._entries.get(t.catalog_ref)
            if e is None:
                problems.append(f"{t.name}: 미지의 catalog_ref {t.catalog_ref}")
            elif e.value_pending:
                problems.append(f"{t.name}: {t.catalog_ref} 값 미전사")
            elif not e.verified_against_source:
                problems.append(f"{t.name}: {t.catalog_ref} 원문 대조 미완")
        return problems


# ─────────────────────────────────────────────────────────────────────────────
# 전사 데이터
# ─────────────────────────────────────────────────────────────────────────────
def _entries() -> List[CatalogEntry]:  # noqa: C901
    es: List[CatalogEntry] = []

    # ── TS 23.501 Table 5.7.4-1: delay-critical GBR 5QI (원문 대조 완료) ─────
    # 전사 규칙(§2.2): PDB 는 98% 신뢰수준 해석 → quantile 0.98.
    # PER 은 'PDB 내 미전달 비율' → ratio(value = 1-PER, pdb = PDB).
    for qi, pdb, per in ((82, 10.0, 1e-4), (83, 10.0, 1e-4), (84, 30.0, 1e-5),
                         (85, 5.0, 1e-5), (87, 5.0, 1e-3), (88, 10.0, 1e-3),
                         (89, 15.0, 1e-4), (90, 20.0, 1e-4)):
        es.append(CatalogEntry(
            f"ts23501.5qi{qi}.latency",
            KpiTarget(name=f"5qi{qi}-pdb", kind="quantile", metric="rtt_net_ms",
                      basis="rtt-conservative", op="<=", value=pdb, unit="ms",
                      quantile=0.98, provenance=_p23501(qi)),
            verified_against_source=True,
            note="GBR PDB 의 98% 신뢰수준 해석(TS 23.501) → quantile 0.98 전사"))
        es.append(CatalogEntry(
            f"ts23501.5qi{qi}.per",
            KpiTarget(name=f"5qi{qi}-per", kind="ratio", metric="delivery",
                      basis="rtt-conservative", op=">=", value=1.0 - per,
                      pdb_ms=pdb, provenance=_p23501(qi)),
            verified_against_source=True,
            note="delay-critical GBR PER → PDB 내 전달률로 전사"))

    # ── TS 22.104 Table 5.2-1 (원문 대조: EVIDENCE §7-B) ────────────────────
    # Motion control panel: CSA 99.999999%, 지연 1 ms, 전송간격 1 ms = 생존시간.
    # 지연에 분위수 규정이 없어 p99 를 전사 규칙으로 채택(주석으로 남는 우리 선택).
    es.append(CatalogEntry(
        "ts22104.5_2.motion_panel.latency",
        KpiTarget(name="mc-latency", kind="quantile", metric="rtt_ms",
                  basis="rtt-conservative", op="<=", value=1.0, unit="ms",
                  quantile=0.99, provenance=_p22104("Motion control panel")),
        verified_against_source=True,
        note=("값 1 ms 는 원문 확인. 분위수 p99 는 우리 전사 규칙. metric 은 "
              "rtt_ms(wire) — owd ≤ rtt_net ≤ rtt_wire 라 PASS 는 무조건 안전")))
    es.append(CatalogEntry(
        "ts22104.5_2.motion_panel.reliability",
        KpiTarget(name="mc-reliability", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99999, pdb_ms=1.0,
                  provenance=_p22104("Motion control panel")),
        verified_against_source=False,
        note=("행이 직접 주는 것은 CSA 99.999999% 다. 신뢰도 99.999% 는 "
              "Table 5.1-1 의 신뢰도↔CSA 대응에서 유도한 값 — 유도이므로 False")))
    es.append(CatalogEntry(
        "ts22104.5_2.motion_panel.survival",
        KpiTarget(name="mc-survival", kind="survival", metric="delivery",
                  basis="rtt-conservative", pdb_ms=1.0,
                  transfer_interval_ms=1.0, survival_time_ms=1.0,
                  provenance=_p22104("Motion control panel")),
        verified_against_source=True,
        note="전송간격 1 ms = 생존시간 (원문 명시). down 사건 관측 시 FAIL(falsify 전용)"))
    es.append(CatalogEntry(
        "ts22104.5_2.motion_panel.availability",
        KpiTarget(name="mc-availability", kind="availability", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99999999,
                  pdb_ms=1.0, transfer_interval_ms=1.0, survival_time_ms=1.0,
                  provenance=_p22104("Motion control panel")),
        verified_against_source=True,
        note=("CSA 99.999999% — falsify 전용: 짧은 런으로 입증 불가, "
              "예정 INCONCLUSIVE (정직성 데모)")))
    es.append(CatalogEntry(
        "ts22104.5_2.surgery.latency",
        KpiTarget(name="surgery-latency", kind="quantile", metric="rtt_ms",
                  basis="rtt-conservative", op="<=", value=2.0, unit="ms",
                  quantile=0.99, provenance=_p22104("Robotic aided surgery")),
        verified_against_source=True, note="지연 2 ms, 16 Mbit/s (원문 확인)"))

    # ── TS 22.186 V2X (원문 대조 완료; 시나리오 8종에는 미사용이나 전사 보존) ──
    es.append(CatalogEntry(
        "ts22186.5_5.remote_driving.reliability",
        KpiTarget(name="rd-reliability", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99999, pdb_ms=5.0,
                  provenance=_P22186_RD),
        verified_against_source=True, note="≤5 ms, 99.999% (원문 확인)"))
    es.append(CatalogEntry(
        "ts22186.5_5.remote_driving.ul_sustained",
        KpiTarget(name="rd-ul", kind="rate", metric="ul_goodput_mbps",
                  basis="measured-wire", op=">=", value=25.0, unit="mbps",
                  provenance=_P22186_RD),
        verified_against_source=True, note="UL 25 Mbit/s (원문 확인)"))

    # ── TS 22.261 rendering: UL+DL 합산 5 ms — RTT 측정과 직접 비교 가능 ─────
    es.append(CatalogEntry(
        "ts22261.7_6.rendering.reliability",
        KpiTarget(name="render-reliability", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.9999, pdb_ms=5.0,
                  provenance=_P22261_RENDER),
        verified_against_source=True,
        note=("UL+DL 합산 5 ms 예산은 왕복 측정과 동형 — rtt-conservative 가 "
              "하한이 아니라 거의 정합. 신뢰도는 병기값 99.99%/99.9% 중 엄격한 "
              "99.99% 채택(보수적)")))

    # ── TR 38.838 XR (2차 출처 경유 → 전부 False) ────────────────────────────
    es.append(CatalogEntry(
        "tr38838.xr.frame_reliability",
        KpiTarget(name="xr-frame-rel", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99, pdb_ms=10.0,
                  success_unit="frame", provenance=_P38838),
        verified_against_source=False,
        note=("TR 38.838 의 satisfied-UE 정의(PDB 내 PER ≤ 1%)와 구조 동일 — "
              "ratio(value 0.99, pdb 10 ms, frame 단위)로 전사")))
    es.append(CatalogEntry(
        "tr38838.xr.dl_sustained",
        KpiTarget(name="xr-dl", kind="rate", metric="dl_goodput_mbps",
                  basis="measured-wire", op=">=", value=30.0, unit="mbps",
                  provenance=_P38838),
        verified_against_source=False, note="AR/VR DL 30 Mbit/s @60 fps"))
    es.append(CatalogEntry(
        "tr38838.xr.pdv_p99",
        KpiTarget(name="xr-pdv", kind="quantile", metric="pdv_ms",
                  basis="rtt-conservative", op="<=", value=4.0, unit="ms",
                  quantile=0.99, provenance=_P38838),
        verified_against_source=False,
        note="설계 초안값. 3GPP 에 jitter 규범 정의 없음 — RFC 5481 PDV 로 전사"))

    # ── RedCap (설계 초안 — 조항/판본 미확인 → 전부 False) ───────────────────
    for key, tgt, note in (
        ("tr38875.redcap.reg_success",
         KpiTarget(name="rc-reg", kind="population", metric="reg_success",
                   basis="measured-wire", op=">=", value=0.99,
                   provenance=_P38875), "등록 성공률"),
        ("tr38875.redcap.setup_p95",
         KpiTarget(name="rc-setup", kind="quantile", metric="setup_time_s",
                   basis="measured-wire", op="<=", value=2.0, unit="s",
                   quantile=0.95, provenance=_P38875), "세션 수립 p95"),
        ("tr38875.redcap.dl_goodput",
         KpiTarget(name="rc-dl", kind="rate", metric="dl_goodput_mbps",
                   basis="measured-wire", op=">=", value=5.0, unit="mbps",
                   provenance=_P38875), "RedCap 목표 DL"),
        ("tr38875.redcap.rtt_p95",
         KpiTarget(name="rc-rtt", kind="quantile", metric="rtt_ms",
                   basis="rtt-conservative", op="<=", value=100.0, unit="ms",
                   quantile=0.95, provenance=_P38875), "왕복 p95"),
    ):
        es.append(CatalogEntry(key, tgt, verified_against_source=False, note=note))

    # ── NTN GEO (설계 초안 → False) ─────────────────────────────────────────
    es.append(CatalogEntry(
        "tr38821.geo.delivery",
        KpiTarget(name="geo-delivery", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99, pdb_ms=10000.0,
                  provenance=_P38821),
        verified_against_source=False, note="IoT 전달률, PDB 10 s"))
    es.append(CatalogEntry(
        "tr38821.geo.rtt_p95",
        KpiTarget(name="geo-rtt", kind="quantile", metric="rtt_net_ms",
                  basis="rtt-conservative", op="<=", value=1500.0, unit="ms",
                  quantile=0.95, provenance=_P38821),
        verified_against_source=False, note="GEO 편도 ~270 ms, RTT ~541 ms 전제"))
    es.append(CatalogEntry(
        "tr38821.geo.reg_success",
        KpiTarget(name="geo-reg", kind="population", metric="reg_success",
                  basis="measured-wire", op=">=", value=0.98,
                  provenance=_P38821),
        verified_against_source=False, note="연장 NAS 타이머 하 등록 성공률"))

    # ── Slice SLA (GSMA NG.116 — 산업 SLA, 값은 설계 초안 → False) ──────────
    es.append(CatalogEntry(
        "ng116.slice.delivery_delta",
        KpiTarget(name="slice-delivery-iso", kind="delta", metric="delivery",
                  basis="rtt-conservative", op="<=", value=0.001,
                  ref_phase="baseline", delta_mode="abs", pdb_ms=10.0,
                  provenance=_PNG116),
        verified_against_source=False,
        note="격리: 부하 phase 에서 전달률 |Δ| ≤ 0.001 (abs)"))
    es.append(CatalogEntry(
        "ng116.slice.latency_delta",
        KpiTarget(name="slice-latency-iso", kind="delta", metric="rtt_net_ms",
                  basis="rtt-conservative", op="<=", value=0.2,
                  ref_phase="baseline", delta_mode="rel", quantile=0.99,
                  provenance=_PNG116),
        verified_against_source=False, note="격리: rtt p99 증가 ≤ +20% (rel)"))
    es.append(CatalogEntry(
        "ts28541.gst.ul_sustained",
        KpiTarget(name="gst-ul", kind="rate", metric="ul_goodput_mbps",
                  basis="measured-wire", op=">=", value=0.0, unit="mbps",
                  provenance=_P28541),
        verified_against_source=False, value_pending=True,
        note="GST 값 미전사 — 원문 대조 전 판정 사용 금지"))

    # ── Ambient IoT (TR 38.848 — PDB 10 s 는 §5.6 확인, 비율은 초안 → False) ─
    es.append(CatalogEntry(
        "tr38848.aiot.delivery",
        KpiTarget(name="aiot-delivery", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99, pdb_ms=10000.0,
                  provenance=_P38848),
        verified_against_source=False,
        note="지연 10 s 는 §5.6 원문 확인, 전달률 0.99 는 설계 초안 → 합성값은 False"))
    es.append(CatalogEntry(
        "tr38848.aiot.inventory",
        KpiTarget(name="aiot-inventory", kind="rate",
                  metric="inventory_completion_s", basis="measured-wire",
                  op="<=", value=60.0, unit="s", provenance=_P38848),
        verified_against_source=False,
        note="모집단 99% 가 첫 메시지 전달까지 ≤ 60 s (설계 초안)"))
    es.append(CatalogEntry(
        "tr38848.aiot.reg_success",
        KpiTarget(name="aiot-reg", kind="population", metric="reg_success",
                  basis="measured-wire", op=">=", value=0.99,
                  provenance=_P38848),
        verified_against_source=False, note="설계 초안"))

    # ── ISAC (TS 22.137 규범 — 원문 대조 완료) ──────────────────────────────
    es.append(CatalogEntry(
        "ts22137.6_2.factory.delivery",
        KpiTarget(name="isac-delivery", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.99, pdb_ms=100.0,
                  provenance=_P22137),
        verified_against_source=True,
        note="신뢰도 99%, 지연 0.1–1 s — 범위 하한 0.1 s 채택(보수적)"))
    es.append(CatalogEntry(
        "ts22137.6_2.factory.sensing_accuracy",
        KpiTarget(name="isac-sensing", kind="rate", metric="sensing_accuracy",
                  basis="measured-wire", op="<=", value=0.5, unit="m",
                  provenance=_P22137),
        verified_against_source=True,
        note=("수평 정확도 0.5 m (원문 확인). **의도된 NOT_MEASURABLE**: 센싱 "
              "정확도는 N2/N3 관측으로 원리적으로 불가 — 판정 정직성 쇼케이스")))
    es.append(CatalogEntry(
        "ts22137.isac.rtt_p99",
        KpiTarget(name="isac-rtt", kind="quantile", metric="rtt_ms",
                  basis="rtt-conservative", op="<=", value=50.0, unit="ms",
                  quantile=0.99, provenance=KpiProvenance(
                      spec="TS 22.137", version="19.1.0",
                      clause="설계 초안 전사 (Table 6.2-1 에 없는 값)",
                      kind="service_requirement")),
        verified_against_source=False,
        note="설계 초안의 통신측 목표 — 원문 표에 이 값 없음"))

    # ── AI/ML model transfer (값 미전사 2건 + 초안 전달률) ───────────────────
    es.append(CatalogEntry(
        "ts22261.6_40.model_completion",
        KpiTarget(name="aiml-completion", kind="rate", metric="completion_s",
                  basis="measured-wire", op="<=", value=0.0, unit="s",
                  provenance=_P22261_AIML),
        verified_against_source=False, value_pending=True,
        note="Table 7.10 수치 미대조 — 판정 사용 금지"))
    es.append(CatalogEntry(
        "ts22261.6_40.dl_sustained",
        KpiTarget(name="aiml-dl", kind="rate", metric="dl_goodput_mbps",
                  basis="measured-wire", op=">=", value=0.0, unit="mbps",
                  provenance=_P22261_AIML),
        verified_against_source=False, value_pending=True,
        note="Table 7.10 수치 미대조 — 판정 사용 금지"))
    es.append(CatalogEntry(
        "ts22261.6_40.chunk_delivery",
        KpiTarget(name="aiml-chunk", kind="ratio", metric="delivery",
                  basis="rtt-conservative", op=">=", value=0.999, pdb_ms=60000.0,
                  provenance=_P22261_AIML),
        verified_against_source=False,
        note=("설계 초안 0.999. 원문에 청크 지연예산이 없어 PDB 60 s 는 '전달 "
              "여부' 의 근사(사실상 지연 무제약 전달률) — 발명값이 아니라 해석임을 명기")))
    return es


#: 모듈 수준 단일 카탈로그
CATALOG = KpiCatalog(_entries())


# ─────────────────────────────────────────────────────────────────────────────
# 내장 시나리오 8종 (설계 §8)
# ─────────────────────────────────────────────────────────────────────────────
def builtin_scenarios(catalog: Optional[KpiCatalog] = None) -> List[ServiceScenario]:  # noqa: C901
    c = catalog or CATALOG
    out: List[ServiceScenario] = []

    # 1) urllc-motion-control — 4 target 중 availability 는 예정 INCONCLUSIVE
    out.append(ServiceScenario(
        id="urllc-motion-control",
        title="URLLC motion control (TS 22.104 motion control panel)",
        service_class="URLLC",
        references=[_p22104("Motion control panel"), _p23501(82)],
        populations=[
            UePopulation(name="mc-ue", count=10, role="sut", features=["urllc"],
                         traffic={"pattern": "periodic", "period_ms": 1,
                                  "packet_size": 64}),
            UePopulation(name="bg-embb", count=8, role="background",
                         features=["embb"], stamp=False),
        ],
        phases=[
            Phase(name="baseline", duration_s=120.0, warmup_s=10.0,
                  active_scale={"bg-embb": 0.0}),
            Phase(name="loaded", duration_s=300.0, warmup_s=10.0,
                  active_scale={"bg-embb": 1.0}),
            Phase(name="degraded", duration_s=120.0, warmup_s=10.0,
                  impair=[ImpairmentSpec(target="mc-ue", sinr_delta_db=-10.0)]),
        ],
        targets=[
            c.resolve("ts22104.5_2.motion_panel.reliability", applies_to="mc-ue"),
            c.resolve("ts22104.5_2.motion_panel.latency", applies_to="mc-ue"),
            c.resolve("ts22104.5_2.motion_panel.survival", applies_to="mc-ue"),
            c.resolve("ts22104.5_2.motion_panel.availability", applies_to="mc-ue"),
            c.resolve("ng116.slice.delivery_delta", applies_to="mc-ue",
                      phases=["loaded"], name="isolation-check"),
        ],
        measurement=MeasurementConfig(tier_min=1, clock_domain="shared"),
    ))

    # 2) xr-cloud-gaming — DL 은 T2 stream 으로만 대표성 있음 → tier_min=2
    out.append(ServiceScenario(
        id="xr-cloud-gaming",
        title="XR / cloud gaming (TR 38.838 평가가정 + TS 22.261 rendering)",
        service_class="XR",
        references=[_P38838, _P22261_RENDER, _p23501(87)],
        populations=[UePopulation(
            name="xr-ue", count=4, role="sut", features=["xr"],
            traffic={"pattern": "periodic", "period_ms": 4, "packet_size": 100,
                     "stream_frame_bytes": 62500, "stream_fps": 60})],
        phases=[Phase(name="baseline", duration_s=120.0, warmup_s=10.0),
                Phase(name="loaded", duration_s=180.0, warmup_s=10.0,
                      load_scale={"xr-ue": 1.5})],
        targets=[
            c.resolve("tr38838.xr.frame_reliability", applies_to="xr-ue"),
            c.resolve("ts22261.7_6.rendering.reliability", applies_to="xr-ue"),
            c.resolve("tr38838.xr.dl_sustained", applies_to="xr-ue"),
            c.resolve("tr38838.xr.pdv_p99", applies_to="xr-ue"),
        ],
        measurement=MeasurementConfig(tier_min=2, clock_domain="shared"),
    ))

    # 3) redcap-wearable
    out.append(ServiceScenario(
        id="redcap-wearable",
        title="RedCap wearables (TR 38.875 초안값)",
        service_class="RedCap",
        references=[_P38875],
        populations=[UePopulation(
            name="wear-ue", count=50, role="sut", features=["redcap"],
            traffic={"pattern": "poisson"}, ramp_seconds=30.0)],
        phases=[Phase(name="baseline", duration_s=180.0, warmup_s=10.0)],
        targets=[
            c.resolve("tr38875.redcap.reg_success", applies_to="wear-ue"),
            c.resolve("tr38875.redcap.setup_p95", applies_to="wear-ue"),
            c.resolve("tr38875.redcap.dl_goodput", applies_to="wear-ue"),
            c.resolve("tr38875.redcap.rtt_p95", applies_to="wear-ue"),
        ],
        measurement=MeasurementConfig(tier_min=2, clock_domain="shared"),
    ))

    # 4) ntn-geo-iot — NAS 타이머 연장은 ntn feature 가 처리
    out.append(ServiceScenario(
        id="ntn-geo-iot",
        title="NTN GEO IoT (TR 38.821 초안값)",
        service_class="NTN",
        references=[_P38821],
        populations=[UePopulation(
            name="ntn-ue", count=100, role="sut", features=["ntn", "mmtc"],
            traffic={"pattern": "sporadic", "period_ms": 60000,
                     "packet_size": 100}, ramp_seconds=60.0)],
        phases=[Phase(name="baseline", duration_s=600.0, warmup_s=30.0)],
        targets=[
            c.resolve("tr38821.geo.delivery", applies_to="ntn-ue"),
            c.resolve("tr38821.geo.rtt_p95", applies_to="ntn-ue"),
            c.resolve("tr38821.geo.reg_success", applies_to="ntn-ue"),
        ],
        measurement=MeasurementConfig(tier_min=2, clock_domain="shared"),
    ))

    # 5) slice-sla-isolation — delta 술어가 격리를 1급 판정으로
    out.append(ServiceScenario(
        id="slice-sla-isolation",
        title="Slice SLA isolation (GSMA NG.116)",
        service_class="slicing",
        references=[_PNG116, _P28541],
        populations=[
            UePopulation(name="slice-a", count=10, role="sut",
                         features=["urllc", "slicing"], sst=1, sd="000001",
                         traffic={"pattern": "periodic", "period_ms": 2,
                                  "packet_size": 64}),
            UePopulation(name="slice-b", count=20, role="background",
                         features=["embb", "slicing"], sst=1, sd="000002",
                         stamp=False),
        ],
        phases=[
            Phase(name="baseline", duration_s=120.0, warmup_s=10.0,
                  active_scale={"slice-b": 0.0}),
            Phase(name="loaded", duration_s=180.0, warmup_s=10.0,
                  active_scale={"slice-b": 1.0}),
            Phase(name="overload", duration_s=180.0, warmup_s=10.0,
                  load_scale={"slice-b": 2.0}),
        ],
        targets=[
            c.resolve("ng116.slice.delivery_delta", applies_to="slice-a",
                      phases=["loaded", "overload"]),
            c.resolve("ng116.slice.latency_delta", applies_to="slice-a",
                      phases=["loaded", "overload"]),
            # ts28541.gst.ul_sustained 는 value_pending — 원문 대조 전에는 제외.
        ],
        measurement=MeasurementConfig(tier_min=2, clock_domain="shared"),
    ))

    # 6) ambient-iot-inventory — 소형 메시지라 sample 스탬프 정책
    out.append(ServiceScenario(
        id="ambient-iot-inventory",
        title="Ambient IoT inventory (TR 38.848)",
        service_class="mMTC",
        references=[_P38848],
        populations=[UePopulation(
            name="aiot-ue", count=500, role="sut", features=["ambient_iot"],
            traffic={"pattern": "sporadic", "packet_size": 125},
            stamp_policy="sample", stamp_sample=0.1, ramp_seconds=30.0)],
        phases=[Phase(name="inventory", duration_s=300.0, warmup_s=5.0)],
        targets=[
            c.resolve("tr38848.aiot.inventory", applies_to="aiot-ue"),
            c.resolve("tr38848.aiot.delivery", applies_to="aiot-ue"),
            c.resolve("tr38848.aiot.reg_success", applies_to="aiot-ue"),
        ],
        measurement=MeasurementConfig(tier_min=1, clock_domain="shared"),
    ))

    # 7) isac-sensing-report — sensing accuracy 는 의도된 NOT_MEASURABLE
    out.append(ServiceScenario(
        id="isac-sensing-report",
        title="ISAC sensing report (TS 22.137 — 규범)",
        service_class="ISAC",
        references=[_P22137],
        populations=[UePopulation(
            name="isac-ue", count=20, role="sut", features=["isac"],
            traffic={"pattern": "periodic", "period_ms": 100,
                     "packet_size": 200})],
        phases=[Phase(name="baseline", duration_s=180.0, warmup_s=10.0)],
        targets=[
            c.resolve("ts22137.6_2.factory.delivery", applies_to="isac-ue"),
            c.resolve("ts22137.isac.rtt_p99", applies_to="isac-ue"),
            c.resolve("ts22137.6_2.factory.sensing_accuracy",
                      applies_to="isac-ue"),
        ],
        measurement=MeasurementConfig(tier_min=1, clock_domain="shared"),
    ))

    # 8) aiml-model-transfer — completion/dl 목표는 value_pending 이라 제외,
    #    청크 전달률만 판정 (제외 사실은 IMPLEMENTATION-NOTES 에 명기)
    out.append(ServiceScenario(
        id="aiml-model-transfer",
        title="AI/ML model transfer (TS 22.261 §6.40)",
        service_class="AI",
        references=[_P22261_AIML],
        populations=[UePopulation(
            name="ai-ue", count=2, role="sut", features=["ai_ran"],
            traffic={"pattern": "periodic", "period_ms": 1000,
                     "packet_size": 100, "stream_model_bytes": 64_000_000})],
        phases=[Phase(name="transfer", duration_s=300.0, warmup_s=5.0)],
        targets=[
            c.resolve("ts22261.6_40.chunk_delivery", applies_to="ai-ue"),
        ],
        measurement=MeasurementConfig(tier_min=2, clock_domain="shared"),
    ))
    return out


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    from .verdict import measurable

    ok = True
    cat = CATALOG

    # 1) 전 항목: provenance 필수필드 + target 자체 검증 (pending 포함)
    for key in cat.keys():
        e = cat.get(key)
        probs = e.target.validate(f"{key}.")
        if probs:
            ok = False
            print(f"  [CT] {key} 검증 실패: {probs}")
        if e.verified_against_source and e.target.provenance.version in (
                "", "unverified"):
            ok = False
            print(f"  [CT] {key}: 판본 미확인인데 verified=True")

    # 2) 규범/연구 구분: TR 출처는 evaluation_assumption 이어야 한다 (EVIDENCE §7)
    for key in cat.keys():
        e = cat.get(key)
        spec = e.target.provenance.spec
        kind = e.target.provenance.kind
        if spec.startswith("TR ") and kind != "evaluation_assumption":
            ok = False
            print(f"  [CT] {key}: 연구문서({spec})가 {kind} 로 격상됨")
        if spec.startswith("GSMA") and kind != "industry_sla":
            ok = False
            print(f"  [CT] {key}: GSMA 출처 kind 오류 {kind}")
    if verbose and ok:
        n_v = len(cat.keys()) - len(cat.unverified_keys())
        print(f"  [CT] 전 {len(cat.keys())}항목 provenance/kind 정합 "
              f"(원문 대조 완료 {n_v}건 / 미완 {len(cat.unverified_keys())}건) OK")

    # 3) 원문 대조 회귀: 5QI 87 은 5 ms 다 (30 ms 로 적은 2차 출처가 실재했다)
    e87 = cat.get("ts23501.5qi87.latency")
    if e87.target.value != 5.0 or e87.target.quantile != 0.98 \
            or not e87.verified_against_source:
        ok = False
        print(f"  [CT] 5QI 87 회귀 실패: {e87.target.value}")
    e85 = cat.get("ts23501.5qi85.per")
    if abs(e85.target.value - 0.99999) > 1e-12 or e85.target.pdb_ms != 5.0:
        ok = False
        print(f"  [CT] 5QI 85 PER 전사 오류: {e85.target.value}")
    mc = cat.get("ts22104.5_2.motion_panel.availability")
    if mc.target.value != 0.99999999 or mc.target.survival_time_ms != 1.0:
        ok = False
        print(f"  [CT] motion panel CSA/ST 전사 오류")
    # 유도값은 verified=False 여야 한다
    if cat.get("ts22104.5_2.motion_panel.reliability").verified_against_source:
        ok = False
        print("  [CT] Table 5.1-1 유도값이 verified=True — 유도는 대조가 아니다")
    elif verbose:
        print("  [CT] 전사 회귀(5QI87=5ms, 유도값 False) OK")

    # 4) resolve: 덮어쓰기 / 원본 불변 / strict / pending 거부
    t = cat.resolve("ts23501.5qi82.latency", applies_to="mc-ue", phases=["loaded"])
    if t.applies_to != "mc-ue" or t.phases != ["loaded"] \
            or t.catalog_ref != "ts23501.5qi82.latency":
        ok = False
        print(f"  [CT] resolve 덮어쓰기 실패: {t.applies_to}, {t.phases}")
    if cat.get("ts23501.5qi82.latency").target.applies_to != "*":
        ok = False
        print("  [CT] resolve 가 카탈로그 원본을 오염시킴")
    try:
        cat.resolve("ts28541.gst.ul_sustained")
        ok = False
        print("  [CT] value_pending 이 resolve 됨 — §12 게이트 위반")
    except ValueError:
        pass
    try:
        cat.resolve("tr38838.xr.frame_reliability", strict=True)
        ok = False
        print("  [CT] 미대조 항목이 strict resolve 됨")
    except ValueError:
        pass
    if cat.resolve("ts23501.5qi82.latency", strict=True) is None:
        ok = False
        print("  [CT] 대조 완료 항목 strict resolve 실패")

    # 5) 내장 시나리오 8종: id / validate / 해시 안정성·유일성
    scenarios = builtin_scenarios()
    want_ids = ["urllc-motion-control", "xr-cloud-gaming", "redcap-wearable",
                "ntn-geo-iot", "slice-sla-isolation", "ambient-iot-inventory",
                "isac-sensing-report", "aiml-model-transfer"]
    if [s.id for s in scenarios] != want_ids:
        ok = False
        print(f"  [CT] 시나리오 id 불일치: {[s.id for s in scenarios]}")
    hashes = set()
    for s in scenarios:
        errs = s.validate()
        if errs:
            ok = False
            print(f"  [CT] {s.id} 검증 실패: {errs}")
        h1, h2 = s.content_hash(), s.content_hash()
        if h1 != h2:
            ok = False
            print(f"  [CT] {s.id} 해시 불안정")
        hashes.add(h1)
        if not any(p.role == "sut" for p in s.populations):
            ok = False
            print(f"  [CT] {s.id}: sut population 없음")
    if len(hashes) != len(scenarios):
        ok = False
        print("  [CT] 시나리오 간 해시 충돌")
    h_again = {s.id: s.content_hash() for s in builtin_scenarios()}
    for s in scenarios:
        if h_again[s.id] != s.content_hash():
            ok = False
            print(f"  [CT] {s.id} 재구성 해시 불일치 — 재현성 위반")
    if verbose and ok:
        print(f"  [CT] 내장 시나리오 8종 validate + 해시 재현성 OK")

    # 6) ISAC sensing target 은 어느 배치에서도 NOT_MEASURABLE (정직성 쇼케이스)
    sense = cat.get("ts22137.6_2.factory.sensing_accuracy").target
    for tier in (0, 1, 2):
        for clock in ("unsync", "shared", "ptp"):
            if measurable(sense.metric, tier, clock)[0]:
                ok = False
                print(f"  [CT] sensing_accuracy 가 T{tier}+{clock} 에서 측정가능?")
    if verbose and ok:
        print("  [CT] sensing accuracy 전 배치 NOT_MEASURABLE OK")

    # 7) verify_scenario: 미대조 참조를 숨기지 않고 보고해야 한다
    urllc = scenarios[0]
    probs = CATALOG.verify_scenario(urllc)
    if not any("motion_panel.reliability" in p for p in probs):
        ok = False
        print(f"  [CT] verify_scenario 가 유도값을 놓침: {probs}")
    isac_probs = CATALOG.verify_scenario(scenarios[6])
    if any("factory.delivery" in p for p in isac_probs):
        ok = False
        print(f"  [CT] 대조 완료 항목이 문제로 보고됨: {isac_probs}")

    return ok


if __name__ == "__main__":
    print("CATALOG selftest:", "PASS" if selftest(verbose=True) else "FAIL")
