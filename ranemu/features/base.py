#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.features.base — 5G-Advanced / 6G feature 플러그인 프레임워크.

핵심 개념
=========
feature 는 **기지국이 소유**한다. 코어는 feature 를 직접 알지 못하고, 두 가지 경로로만
그 존재를 관측한다:

    (a) 시그널링 경로 — NGAP/NAS IE 가 달라진다
        예) RedCap 단말은 낮은 UE-AMBR, mo-Data 확립사유, 축소된 UE 무선능력을 보고한다.
            NTN 셀은 TAC/셀ID 가 다르고 NAS 타이머가 연장된다.
            URLLC 는 5QI 82~85 와 낮은 PDB 로 QoS 흐름을 요구한다.

    (b) 거동 경로 — 사용자평면 트래픽의 물리적 성질이 달라진다
        예) RedCap 은 20MHz·1레이어·64QAM 이라 상한이 낮다.
            NTN GEO 는 편도 270ms 전파지연이 붙는다.
            NES 는 셀 DTX 로 가용시간이 줄어 스루풋이 주기적으로 꺼진다.

따라서 Feature 는 `apply()` 에서 세 개의 상태를 조정한다:
    RadioProfile   → 물리 파라미터 (radio.py 가 처리량/지연으로 환산)
    SignalingHints → NGAP/NAS IE
    TrafficHints   → 트래픽 생성 패턴

여러 feature 를 동시에 적용할 수 있다(예: redcap + ntn = 위성 IoT 단말).
적용 순서는 `order` 로 제어한다(낮을수록 먼저).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

from ..radio import RadioProfile


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class SignalingHints:
    """NGAP/NAS 로 흘러나갈 값들. gnb/ue 가 메시지를 만들 때 참조한다."""
    #: RRC 확립 사유 (TS 38.413 RRCEstablishmentCause)
    rrc_establishment_cause: str = "mo-Data"
    #: 기본 QoS 흐름의 5QI (TS 23.501 Table 5.7.4-1)
    five_qi: int = 9
    #: ARP 우선순위 (1=최고)
    arp_priority: int = 8
    #: UE 집계 최대 비트레이트 (bps) — 코어가 실제로 강제하는 상한
    ue_ambr_dl: int = 1_000_000_000
    ue_ambr_ul: int = 200_000_000
    #: 슬라이스 (없으면 그룹 설정 사용)
    sst: Optional[int] = None
    sd: Optional[str] = None
    #: RedCap 단말 표시 (Rel-17 NGAP/RRC)
    redcap: bool = False
    #: NTN 접속 표시 및 셀 종류
    ntn: bool = False
    ntn_orbit: Optional[str] = None
    #: 페이징 DRX / 확장 DRX 주기(ms)
    drx_cycle_ms: Optional[float] = None
    edrx_cycle_s: Optional[float] = None
    #: NAS 타이머 배율 (NTN 처럼 지연이 큰 접속에서 연장)
    nas_timer_scale: float = 1.0
    #: PDU 세션 타입 강제
    pdu_session_type: Optional[str] = None
    #: UE 무선능력(옥텟) — 코어는 불투명하게 저장/전달만 한다
    ue_radio_capability: Optional[bytes] = None
    #: 자유형 태그(manifest/로그용)
    tags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrafficHints:
    """사용자평면 생성기가 참조할 패턴."""
    #: fullbuffer | periodic | burst | poisson | sporadic
    pattern: str = "fullbuffer"
    packet_size: Optional[int] = None
    #: periodic/burst 용 주기(ms)
    period_ms: Optional[float] = None
    #: burst 당 패킷 수
    burst_packets: int = 1
    #: 오퍼드 레이트 상한(Mbps). None 이면 링크버짓을 그대로 쓴다.
    offered_ul_mbps: Optional[float] = None
    offered_dl_mbps: Optional[float] = None
    #: 활성/비활성 듀티(예: mMTC 는 아주 드물게 송신)
    active_ratio: float = 1.0
    tags: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureContext:
    """feature 적용 대상 상태 묶음."""
    profile: RadioProfile
    signaling: SignalingHints
    traffic: TrafficHints
    #: 단말 인덱스(그룹 내) — 위치/거리 분산 등에 사용
    ue_index: int = 0
    #: 재현성 난수
    rng: Any = None
    #: 사용자 지정 파라미터 (config.ue_groups[].feature_params[feature])
    params: Dict[str, Any] = field(default_factory=dict)

    def p(self, key: str, default: Any) -> Any:
        """파라미터 조회(설정 우선, 없으면 기본값)."""
        return self.params.get(key, default)


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Feature:
    """하나의 5G-A/6G 기능."""
    name: str
    title: str
    release: str
    category: str
    summary: str
    apply: Callable[[FeatureContext], None]
    #: 적용 순서(낮을수록 먼저). 기본 프로파일류는 음수, 변조자는 양수.
    order: int = 0
    #: 이 feature 가 조정하는 대표 파라미터 설명(문서/CLI 출력용)
    knobs: Dict[str, str] = field(default_factory=dict)
    #: 함께 쓰면 모순인 feature 들
    conflicts: List[str] = field(default_factory=list)

    def describe(self) -> Dict[str, Any]:
        d = {k: v for k, v in asdict(self).items() if k != "apply"}
        return d


# ─────────────────────────────────────────────────────────────────────────────
# 레지스트리
# ─────────────────────────────────────────────────────────────────────────────
_REGISTRY: Dict[str, Feature] = {}


def register(feature: Feature) -> Feature:
    if feature.name in _REGISTRY:
        raise ValueError(f"feature 이름 중복: {feature.name}")
    _REGISTRY[feature.name] = feature
    return feature


def get(name: str) -> Feature:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise KeyError(f"알 수 없는 feature: {name!r} "
                       f"(가능: {', '.join(sorted(_REGISTRY))})") from None


def all_features() -> Dict[str, Feature]:
    return dict(_REGISTRY)


def unknown_features(names: Iterable[str]) -> Set[str]:
    return {n for n in names if n not in _REGISTRY}


def check_conflicts(names: Iterable[str]) -> List[str]:
    """상호 모순 조합 검출 → 문제 설명 목록(쌍 중복 제거)."""
    present = [n for n in names if n in _REGISTRY]
    pairs: Set[frozenset] = set()
    for n in present:
        for c in _REGISTRY[n].conflicts:
            if c in present:
                pairs.add(frozenset((n, c)))
    return [f"{a} 와 {b} 는 함께 쓸 수 없음"
            for a, b in (sorted(p) for p in sorted(pairs, key=sorted))]


def apply_features(names: Iterable[str], ctx: FeatureContext) -> List[str]:
    """이름 목록을 order 순으로 적용. 적용된 이름 목록을 반환."""
    feats = sorted((get(n) for n in names), key=lambda f: (f.order, f.name))
    for f in feats:
        ctx.params = (ctx.params or {})
        f.apply(ctx)
    return [f.name for f in feats]
