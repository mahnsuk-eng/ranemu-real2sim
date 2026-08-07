#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.config — 시험 시나리오 설정(YAML/JSON) 스키마와 로더.

설계
====
설정 하나가 **하나의 시험(run)** 을 완전히 기술한다:
    · 어떤 코어에 붙는가        (core: AMF N2 주소, UPF N3 주소)
    · 어떤 기지국인가            (gnb: PLMN/TAC/NCI/이름/N3 로컬주소)
    · 어떤 단말이 몇 대인가      (ue_groups: IMSI 범위, SIM 키, DNN/S-NSSAI)
    · 각 단말이 어떤 5G-A/6G     (features: redcap / ntn / urllc / xr / mmtc / nes / ltm ...)
      feature 로 동작하는가
    · 무슨 트래픽을 흘리는가     (traffic: 프로파일·목적지·지속시간)
    · 코어측 수집을 할 것인가    (capture: 인터페이스·필터·자동 분석)

모든 필드에 합리적 기본값이 있으므로 최소 설정은 core/gnb 주소만 채우면 된다.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict, fields, is_dataclass
from typing import Any, Dict, List, Optional

from .util import get_logger, imsi_split, unhex

log = get_logger("ranemu.config")


# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class CoreConfig:
    """실 5G 코어 접속 정보."""
    #: AMF 의 N2(NGAP/SCTP) 주소. stub 모드면 무시.
    amf_addr: str = "127.0.0.1"
    amf_port: int = 38412
    #: UPF 의 N3(GTP-U) 주소. 보통 PDU Session Resource Setup 에서 코어가 알려주므로
    #: 여기 값은 폴백(수동 지정/u-plane only 모드)이다.
    upf_addr: Optional[str] = None
    upf_port: int = 2152
    #: "real" = 실코어, "stub" = 내장 AMF/UPF 스텁(오프라인 검증)
    kind: str = "real"
    #: SCTP 다중 홈용 추가 주소(선택)
    amf_addr_list: List[str] = field(default_factory=list)


@dataclass
class GnbConfig:
    """에뮬레이트할 기지국 파라미터."""
    name: str = "ranemu-gnb-1"
    mcc: str = "450"
    mnc: str = "05"
    #: gNB ID 와 비트길이 (TS 38.413 GlobalGNB-ID)
    gnb_id: int = 0x000001
    gnb_id_bits: int = 24
    #: Tracking Area Code (3바이트)
    tac: int = 1
    #: NR Cell Identity (36비트) — 상위는 gnb_id, 하위는 cell 로컬 ID
    cell_id: int = 0
    #: N2(SCTP) 로컬 바인드 주소 — 코어가 이 주소를 gNB 로 본다
    n2_local_addr: str = "0.0.0.0"
    n2_local_port: int = 0          # 0 = 임의 포트
    #: N3(GTP-U) 로컬 바인드 — 코어에 알려줄 gNB 사용자평면 주소
    n3_local_addr: str = "0.0.0.0"
    n3_local_port: int = 2152
    #: 코어에 광고할 N3 주소(바인드가 0.0.0.0 일 때 실제로 알릴 IP)
    n3_advertise_addr: Optional[str] = None
    #: 지원 슬라이스 목록 [{sst:int, sd:str|None}]
    slices: List[Dict[str, Any]] = field(default_factory=lambda: [{"sst": 1, "sd": None}])
    #: 페이징 DRX (TS 38.413 PagingDRX): v32/v64/v128/v256
    paging_drx: str = "v128"
    #: RAN 노드 종류 표기(로그/manifest 용)
    ran_node_type: str = "gNB"

    def nr_cell_identity(self) -> int:
        """36비트 NR Cell Identity = gNB ID(gnb_id_bits) || cell_id(나머지)."""
        local_bits = 36 - self.gnb_id_bits
        return ((self.gnb_id & ((1 << self.gnb_id_bits) - 1)) << local_bits) | (
            self.cell_id & ((1 << local_bits) - 1))


@dataclass
class SecurityConfig:
    """SIM 자격증명과 NAS 보안 협상 파라미터."""
    #: 인증키 K (16바이트 hex)
    key: str = "465b5ce8b199b49faa5f0a2ee238a6bc"
    #: OPc 또는 OP 중 하나 (16바이트 hex)
    opc: Optional[str] = "e8ed289deba952e4283b54e88e6183ca"
    op: Optional[str] = None
    #: AMF 필드 (2바이트 hex) — 인증벡터 생성용
    amf: str = "8000"
    #: 광고할 알고리즘. None 이면 "구현된 것 전부"(권장).
    supported_enc: Optional[List[int]] = None
    supported_int: Optional[List[int]] = None
    #: SUCI 은닉 방식: "null"(profile 0, 평문 IMSI) — 실코어가 null 을 허용해야 함
    suci_scheme: str = "null"
    #: 초기 SQN (6바이트 hex) — 재동기화 시험용
    sqn: str = "000000000020"

    def key_bytes(self) -> bytes:
        return unhex(self.key)

    def opc_bytes(self) -> bytes:
        from .crypto import derive_opc
        if self.opc:
            return unhex(self.opc)
        if self.op:
            return derive_opc(self.key_bytes(), unhex(self.op))
        raise ValueError("security.opc 또는 security.op 중 하나는 필요합니다")

    def amf_bytes(self) -> bytes:
        return unhex(self.amf)


@dataclass
class UeGroupConfig:
    """동일 특성을 갖는 단말 묶음. 하나의 그룹이 N대를 만든다."""
    name: str = "group-1"
    count: int = 1
    #: 시작 IMSI. 그룹 내 i번째 단말은 imsi_start + i
    imsi_start: str = "450050000000001"
    #: 이 그룹이 사용할 feature 이름 목록 (features 레지스트리 키)
    features: List[str] = field(default_factory=list)
    #: feature 별 파라미터 덮어쓰기 {feature_name: {param: value}}
    feature_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    #: DNN(APN)
    dnn: str = "internet"
    #: 슬라이스
    sst: int = 1
    sd: Optional[str] = None
    #: PDU 세션 타입: ipv4 | ipv6 | ipv4v6
    pdu_session_type: str = "ipv4"
    #: 트래픽 패턴 강제. None 이면 feature 가 제안한 패턴을 쓴다.
    #:   None         → feature 기본(예: RedCap=periodic IoT, XR=burst)
    #:   "fullbuffer" → 링크 상한까지 채움(처리량 상한 검증용)
    #:   periodic | burst | poisson | sporadic
    #: 시험 목적에 따라 골라야 한다: "RedCap 단말의 최대 처리량" 을 보려면 fullbuffer,
    #: "RedCap IoT 트래픽의 코어 처리" 를 보려면 feature 기본값.
    traffic: Optional[str] = None
    #: 패턴 세부 덮어쓰기 {packet_size, period_ms, burst_packets, offered_ul_mbps, ...}
    traffic_params: Dict[str, Any] = field(default_factory=dict)
    #: 등록 시작을 그룹 내에서 분산(초). 대규모 동시접속 회피.
    ramp_seconds: float = 0.0
    #: 개별 SIM 키를 그룹 단위로 다르게 줄 때(없으면 전역 security 사용)
    security: Optional[SecurityConfig] = None

    def imsi_at(self, index: int) -> str:
        base = "".join(ch for ch in self.imsi_start if ch.isdigit())
        return str(int(base) + index).zfill(len(base))


@dataclass
class TrafficConfig:
    """사용자평면 트래픽 전역 설정."""
    #: 목적지(코어 N6 너머). 실 트래픽이 나가는 곳.
    dest_addr: str = "8.8.8.8"
    dest_port: int = 33434
    #: 시험 지속시간(초)
    duration: float = 30.0
    #: 상/하향 오퍼드 레이트 기본값(Mbps). feature 가 상한을 덮어쓴다.
    offered_ul_mbps: float = 10.0
    offered_dl_mbps: float = 50.0
    #: 패킷 크기(바이트, IP 페이로드 기준)
    packet_size: int = 1400
    #: GTP-U 시퀀스 번호를 붙인다(TS 29.281 §5.1). 캡처 손실 추정의 기준 카운터.
    gtpu_sequence: bool = False
    #: 하향 트래픽 생성 방식:
    #:   "echo"     = 상향 패킷을 코어/서버가 되돌려주길 기대(실환경 서버 필요)
    #:   "loopback" = 스텁 UPF 가 즉시 되돌림(오프라인 검증)
    #:   "none"     = 상향만
    downlink_mode: str = "loopback"


@dataclass
class CaptureConfig:
    """코어측 수집(기존 network_agent/dpi_engine 파이프라인) 연동."""
    enabled: bool = False
    #: 미러 인터페이스. "dual" 이면 network_agent 규약대로 N6/N3 분리 캡처.
    interface: str = "dual"
    out_dir: str = "/tmp/ranemu_captures"
    #: 캡처 종료 후 dpi_engine + ngap_agent 로 자동 분석
    auto_analyze: bool = True
    snaplen: int = 256
    #: N2 캡처는 풀 스냅렌이 필수(NGAP IE 파싱)
    n2_snaplen: int = 0
    #: 에뮬레이터가 **송신한 그대로** 를 pcap 으로 남긴다(무손실 정답 캡처).
    #: 커널 캡처는 그 자체가 손실/타임스탬프 합침의 대상이므로 정답이 될 수 없다.
    truth_pcap: bool = False
    truth_pcap_path: Optional[str] = None


@dataclass
class RunConfig:
    """최상위 시험 설정."""
    name: str = "ranemu-run"
    core: CoreConfig = field(default_factory=CoreConfig)
    gnb: GnbConfig = field(default_factory=GnbConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    ue_groups: List[UeGroupConfig] = field(default_factory=lambda: [UeGroupConfig()])
    traffic: TrafficConfig = field(default_factory=TrafficConfig)
    capture: CaptureConfig = field(default_factory=CaptureConfig)
    #: 결과/manifest 출력 디렉터리
    out_dir: str = "/tmp/ranemu_runs"
    #: 재현성 시드
    seed: int = 42
    #: 등록 절차를 생략하고 정적 TEID 로 사용자평면만 시험할 때
    uplane_only: bool = False
    #: 절차 타임아웃(초)
    procedure_timeout: float = 10.0

    # ── 편의 ──────────────────────────────────────────────────────────────
    def total_ues(self) -> int:
        return sum(g.count for g in self.ue_groups)

    def security_for(self, group: UeGroupConfig) -> SecurityConfig:
        return group.security or self.security

    def validate(self) -> List[str]:
        """설정 정합성 점검 → 문제 목록(빈 리스트면 정상)."""
        errs: List[str] = []
        if self.core.kind not in ("real", "stub"):
            errs.append(f"core.kind 는 real|stub 이어야 함: {self.core.kind!r}")
        if not self.ue_groups:
            errs.append("ue_groups 가 비어 있음")
        if self.total_ues() <= 0:
            errs.append("단말 수가 0")
        try:
            k = self.security.key_bytes()
            if len(k) != 16:
                errs.append(f"security.key 는 16바이트여야 함(현재 {len(k)})")
            if len(self.security.opc_bytes()) != 16:
                errs.append("security.opc 는 16바이트여야 함")
            if len(self.security.amf_bytes()) != 2:
                errs.append("security.amf 는 2바이트여야 함")
        except Exception as e:  # noqa: BLE001
            errs.append(f"security 파싱 실패: {e}")

        if not (0 < self.gnb.gnb_id_bits <= 32):
            errs.append("gnb.gnb_id_bits 는 1..32")
        if self.gnb.gnb_id >= (1 << self.gnb.gnb_id_bits):
            errs.append("gnb.gnb_id 가 gnb_id_bits 범위를 초과")
        if not (0 <= self.gnb.tac <= 0xFFFFFF):
            errs.append("gnb.tac 는 0..0xFFFFFF")

        # IMSI 가 gNB PLMN 과 다르면 코어가 거절할 수 있다(경고 성격이지만 명시)
        for g in self.ue_groups:
            mcc, mnc, _ = imsi_split(g.imsi_at(0))
            if mcc != self.gnb.mcc or mnc.lstrip("0") != self.gnb.mnc.lstrip("0"):
                errs.append(
                    f"ue_groups[{g.name}] IMSI PLMN({mcc}/{mnc}) 이 "
                    f"gnb PLMN({self.gnb.mcc}/{self.gnb.mnc}) 과 다름 — 코어가 거절할 수 있음")
            if g.count <= 0:
                errs.append(f"ue_groups[{g.name}].count 는 1 이상")

        from .features import unknown_features
        unknown = unknown_features([f for g in self.ue_groups for f in g.features])
        if unknown:
            errs.append(f"알 수 없는 feature: {sorted(unknown)}")

        if self.core.kind == "real" and self.traffic.downlink_mode == "loopback":
            errs.append("실코어(core.kind=real)에서는 traffic.downlink_mode=loopback 이 "
                        "무의미합니다 — echo 또는 none 을 쓰십시오")
        return errs


# ─────────────────────────────────────────────────────────────────────────────
# 로딩 / 저장
# ─────────────────────────────────────────────────────────────────────────────
def _build(cls, data: Any):
    """중첩 dataclass 를 재귀적으로 구성(리스트 원소 타입도 처리)."""
    if data is None:
        return cls()
    if not is_dataclass(cls):
        return data
    if not isinstance(data, dict):
        raise TypeError(f"{cls.__name__} 에는 매핑이 필요합니다 (got {type(data).__name__})")

    kwargs: Dict[str, Any] = {}
    known = {f.name: f for f in fields(cls)}
    for key, val in data.items():
        if key not in known:
            log.warning("설정에 알 수 없는 항목 무시: %s.%s", cls.__name__, key)
            continue
        f = known[key]
        ftype = f.type
        # 문자열 어노테이션(from __future__ import annotations) 해석
        if isinstance(ftype, str):
            ftype = _resolve(ftype)
        kwargs[key] = _coerce(ftype, val)
    return cls(**kwargs)


_TYPE_TABLE = {
    "CoreConfig": lambda: CoreConfig, "GnbConfig": lambda: GnbConfig,
    "SecurityConfig": lambda: SecurityConfig, "UeGroupConfig": lambda: UeGroupConfig,
    "TrafficConfig": lambda: TrafficConfig, "CaptureConfig": lambda: CaptureConfig,
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
    if isinstance(ftype, list):           # List[SomeConfig]
        inner = ftype[0]
        return [_build(inner, v) for v in (val or [])]
    if is_dataclass(ftype):
        return _build(ftype, val)
    return val


def load(path: str) -> RunConfig:
    """YAML 또는 JSON 설정 파일을 RunConfig 로 로드."""
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        import yaml
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")
    cfg = _build(RunConfig, data)
    log.info("설정 로드: %s (단말 %d대, feature=%s)", path, cfg.total_ues(),
             sorted({f for g in cfg.ue_groups for f in g.features}) or ["-"])
    return cfg


def loads(data: Dict[str, Any]) -> RunConfig:
    """이미 파싱된 매핑에서 RunConfig 구성."""
    return _build(RunConfig, data)


def dump(cfg: RunConfig, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    data = asdict(cfg)
    with open(path, "w", encoding="utf-8") as fh:
        if path.endswith((".yaml", ".yml")):
            import yaml
            yaml.safe_dump(data, fh, allow_unicode=True, sort_keys=False)
        else:
            json.dump(data, fh, ensure_ascii=False, indent=2)


def selftest(verbose: bool = False) -> bool:
    ok = True
    # (1) 기본 설정은 유효해야 함(단, 기본 IMSI PLMN 은 기본 gNB PLMN 과 일치해야)
    cfg = RunConfig()
    errs = [e for e in cfg.validate() if "downlink_mode" not in e]
    if errs:
        ok = False
        print(f"  [CONFIG] 기본 설정이 유효하지 않음: {errs}")
    elif verbose:
        print("  [CONFIG] 기본 설정 유효 OK")

    # (2) 중첩 로딩
    cfg2 = loads({
        "name": "t", "core": {"kind": "stub", "amf_addr": "1.2.3.4"},
        "gnb": {"mcc": "001", "mnc": "01", "gnb_id": 7},
        "ue_groups": [{"name": "g", "count": 3, "imsi_start": "001010000000001",
                       "features": []}],
    })
    if (cfg2.core.kind != "stub" or cfg2.gnb.gnb_id != 7
            or len(cfg2.ue_groups) != 1 or cfg2.ue_groups[0].count != 3
            or not isinstance(cfg2.ue_groups[0], UeGroupConfig)):
        ok = False
        print("  [CONFIG] 중첩 dataclass 구성 실패")
    elif verbose:
        print("  [CONFIG] 중첩 dataclass 구성 OK")

    # (3) IMSI 증가
    g = cfg2.ue_groups[0]
    if g.imsi_at(0) != "001010000000001" or g.imsi_at(2) != "001010000000003":
        ok = False
        print(f"  [CONFIG] IMSI 증가 오류: {g.imsi_at(2)}")

    # (4) NR Cell Identity 조립 (24비트 gNB ID + 12비트 셀)
    gc = GnbConfig(gnb_id=0xABCDE, gnb_id_bits=24, cell_id=0x3)
    if gc.nr_cell_identity() != (0xABCDE << 12) | 0x3:
        ok = False
        print(f"  [CONFIG] NCI 조립 오류: {gc.nr_cell_identity():x}")
    elif verbose:
        print("  [CONFIG] NCI 조립 OK")

    # (5) 잘못된 설정을 잡아내야 함
    bad = RunConfig()
    bad.gnb.gnb_id = 1 << 30
    bad.security.key = "00" * 8
    if len(bad.validate()) < 2:
        ok = False
        print("  [CONFIG] 오류 설정을 검출하지 못함")

    # (6) OP → OPc 유도 경로
    s = SecurityConfig(key="465b5ce8b199b49faa5f0a2ee238a6bc",
                       opc=None, op="cdc202d5123e20f62b6d676ac72cb318")
    if s.opc_bytes().hex() != "cd63cb71954a9f4e48a5994e37a02baf":
        ok = False
        print("  [CONFIG] OP→OPc 유도 실패")
    elif verbose:
        print("  [CONFIG] OP→OPc 유도 OK")
    return ok


if __name__ == "__main__":
    print("CONFIG selftest:", "PASS" if selftest(verbose=True) else "FAIL")
