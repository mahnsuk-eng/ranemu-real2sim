#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.ue — 단말(UE) 컨텍스트와 NAS 5GS 상태머신.

상태 전이
=========
    DEREGISTERED
        │ RegistrationRequest(SUCI) ─────────────────────────────────► 코어
    REGISTERING
        │ ◄──────────────────────────────── AuthenticationRequest(RAND, AUTN)
        │ AUTN 검증 → RES* 계산 → AuthenticationResponse ────────────►
    AUTHENTICATING
        │ ◄──────────────────────────── SecurityModeCommand(알고리즘, ngKSI)
        │ K_NASenc/int 유도 → SecurityModeComplete(전체 등록요청 포함) ─►
    SECURING
        │ ◄─────────────────────────────────── RegistrationAccept(5G-GUTI)
        │ RegistrationComplete ──────────────────────────────────────►
    REGISTERED
        │ ULNASTransport(PDUSessionEstablishmentRequest) ────────────►
    SESSION_PENDING
        │ ◄──────────── PDUSessionResourceSetupRequest + Accept(UE IP)
    ACTIVE  ← 이 상태에서만 사용자평면(GTP-U) 트래픽이 흐른다

각 단말은 자기 feature 조합에 따른 RadioProfile/LinkBudget/쉐이퍼/트래픽생성기를 갖는다.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from . import features as feat
from .crypto import (
    DIRECTION_DL, DIRECTION_UL, Milenage, k_amf, k_ausf, k_gnb, k_seaf,
    nas_keys, res_star,
)
from .nas import nas5gs as nas
from .radio import LinkBudget, RadioProfile
from .shaper import LinkShaper
from .traffic import TrafficGenerator, from_hints
from .util import get_logger, imsi_split, serving_network_name

log = get_logger("ranemu.ue")


class UeState(Enum):
    DEREGISTERED = "deregistered"
    REGISTERING = "registering"
    AUTHENTICATING = "authenticating"
    SECURING = "securing"
    REGISTERED = "registered"
    SESSION_PENDING = "session_pending"
    ACTIVE = "active"
    FAILED = "failed"
    RELEASED = "released"


@dataclass
class UeStats:
    ul_packets: int = 0
    ul_bytes: int = 0
    dl_packets: int = 0
    dl_bytes: int = 0
    ul_dropped_rate: int = 0
    ul_dropped_loss: int = 0
    ul_dropped_interrupt: int = 0
    nas_sent: int = 0
    nas_recv: int = 0
    registration_time_s: Optional[float] = None
    session_time_s: Optional[float] = None
    first_ul_time: Optional[float] = None
    last_ul_time: Optional[float] = None

    def as_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


class Ue:
    """단말 하나. NAS 상태머신 + 무선 프로파일 + 사용자평면 상태를 모두 소유한다."""

    def __init__(self, *, imsi: str, key: bytes, opc: bytes, amf_field: bytes,
                 ran_ue_ngap_id: int, dnn: str = "internet",
                 sst: int = 1, sd: Optional[str] = None,
                 pdu_session_id: int = 1, pdu_session_type: str = "ipv4",
                 features: Optional[List[str]] = None,
                 feature_params: Optional[Dict[str, Dict[str, Any]]] = None,
                 ue_index: int = 0, seed: int = 42,
                 supported_enc: Optional[List[int]] = None,
                 supported_int: Optional[List[int]] = None,
                 group: str = "default",
                 traffic_pattern: Optional[str] = None,
                 traffic_params: Optional[Dict[str, Any]] = None):
        self.imsi = imsi
        self.supi = imsi
        self.group = group
        self.mcc, self.mnc, self.msin = imsi_split(imsi)
        self.snn = serving_network_name(self.mcc, self.mnc)
        self.milenage = Milenage(key, opc)
        self.amf_field = amf_field
        self.dnn = dnn
        self.sst = sst
        self.sd = sd
        self.pdu_session_id = pdu_session_id
        self.pdu_session_type = pdu_session_type
        self.ue_index = ue_index

        # ── NGAP 식별자 ───────────────────────────────────────────────────
        self.ran_ue_ngap_id = ran_ue_ngap_id
        self.amf_ue_ngap_id: Optional[int] = None

        # ── 보안 상태 ─────────────────────────────────────────────────────
        from .crypto import IMPLEMENTED_ENC, IMPLEMENTED_INT
        self.supported_enc = list(supported_enc if supported_enc is not None
                                  else IMPLEMENTED_ENC)
        self.supported_int = list(supported_int if supported_int is not None
                                  else IMPLEMENTED_INT)
        self.ngksi = 7                       # 7 = 사용 가능한 키 없음
        self.k_ausf: Optional[bytes] = None
        self.k_seaf: Optional[bytes] = None
        self.k_amf: Optional[bytes] = None
        self.k_nas_enc: bytes = b""
        self.k_nas_int: bytes = b""
        self.k_gnb: Optional[bytes] = None
        self.enc_alg = 0
        self.int_alg = 0
        self.security_active = False
        self.ul_count = 0
        self.dl_count = 0
        self.abba = b"\x00\x00"
        self._last_registration_request: bytes = b""

        # ── 세션 상태 ─────────────────────────────────────────────────────
        self.state = UeState.DEREGISTERED
        self.guti: Optional[bytes] = None
        self.ue_ip: Optional[str] = None
        self.ul_teid: Optional[int] = None      # UPF 방향(우리가 보낼 때 쓰는 TEID)
        self.upf_addr: Optional[str] = None
        self.dl_teid: Optional[int] = None      # gNB 측(코어가 우리에게 보낼 때)
        self.qfis: List[int] = [1]
        self.failure_reason: Optional[str] = None
        #: GTP-U 시퀀스 번호는 **터널별**로 증가한다(TS 29.281 §5.1).
        #: 전역 카운터로 두면 다중 단말이 교차할 때 터널마다 빈틈이 생겨,
        #: 캡처 손실 추정기가 무손상 스트림을 손실로 오판한다(실측으로 확인).
        self.gtpu_seq = 0

        # ── 무선/트래픽 프로파일 ──────────────────────────────────────────
        self.features = list(features or [])
        self.rng = random.Random(seed * 1_000_003 + ue_index)
        built = feat.build_profile(self.features, ue_index=ue_index,
                                   params=feature_params or {}, rng=self.rng)
        self.profile: RadioProfile = built["profile"]
        self.signaling: feat.SignalingHints = built["signaling"]
        self.traffic_hints: feat.TrafficHints = built["traffic"]

        # 설정이 트래픽 패턴을 강제하면 feature 제안을 덮어쓴다.
        # fullbuffer 로 바꾸면 feature 가 정한 주기/버스트 대신 링크 상한까지 채우므로
        # "이 feature 단말이 낼 수 있는 최대 처리량" 을 검증할 수 있다.
        if traffic_pattern:
            self.traffic_hints.pattern = traffic_pattern
            if traffic_pattern == "fullbuffer":
                self.traffic_hints.period_ms = None
                self.traffic_hints.burst_packets = 1
                self.traffic_hints.active_ratio = 1.0
                # 링크버짓이 상한을 정하도록 오퍼드 제한 해제
                self.traffic_hints.offered_ul_mbps = None
                self.traffic_hints.offered_dl_mbps = None
        for k, v in (traffic_params or {}).items():
            if hasattr(self.traffic_hints, k):
                setattr(self.traffic_hints, k, v)
        self.link: LinkBudget = built["link"]
        self.applied_features: List[str] = built["applied"]

        # feature 가 슬라이스를 지정했으면 그것을 따른다
        if self.signaling.sst is not None:
            self.sst = self.signaling.sst
            self.sd = self.signaling.sd
        if self.signaling.pdu_session_type:
            self.pdu_session_type = self.signaling.pdu_session_type

        self.ul_shaper: Optional[LinkShaper] = None
        self.dl_shaper: Optional[LinkShaper] = None
        self.generator: Optional[TrafficGenerator] = None
        self.stats = UeStats()
        self._t_start: Optional[float] = None

    # ── 표시 ──────────────────────────────────────────────────────────────
    def __repr__(self) -> str:  # pragma: no cover
        return (f"<UE {self.imsi} {self.state.value} ip={self.ue_ip} "
                f"features={self.applied_features}>")

    @property
    def is_active(self) -> bool:
        return self.state is UeState.ACTIVE

    # ── 사용자평면 준비 ───────────────────────────────────────────────────
    def setup_uplane(self, now: float, *, default_ul_mbps: float,
                     default_dl_mbps: float, packet_size: int) -> None:
        """링크버짓과 트래픽 힌트로 쉐이퍼/생성기를 만든다."""
        h = self.traffic_hints
        ul_rate = min(self.link.ul_mbps,
                      h.offered_ul_mbps if h.offered_ul_mbps is not None else default_ul_mbps)
        dl_rate = min(self.link.dl_mbps,
                      h.offered_dl_mbps if h.offered_dl_mbps is not None else default_dl_mbps)
        # 코어가 강제하는 UE-AMBR 도 상한이다
        ul_rate = min(ul_rate, self.signaling.ue_ambr_ul / 1e6)
        dl_rate = min(dl_rate, self.signaling.ue_ambr_dl / 1e6)

        interruption_s = h.tags.get("interruption_period_s")
        interruption_ms = float(h.tags.get("interruption_ms", 0.0) or 0.0)
        # NES 셀 DTX 도 단절로 표현
        if "nes_dtx_period_ms" in h.tags and not interruption_s:
            period = float(h.tags["nes_dtx_period_ms"]) / 1000.0
            on_ratio = float(h.tags.get("nes_on_ratio", 0.6))
            interruption_s = period
            interruption_ms = period * (1.0 - on_ratio) * 1000.0

        self.ul_shaper = LinkShaper(
            ul_rate, self.link.owd_ms, self.link.jitter_ms, self.link.loss_rate,
            rng=self.rng, interrupt_period_s=interruption_s,
            interrupt_ms=interruption_ms, now=now)
        self.dl_shaper = LinkShaper(
            dl_rate, self.link.owd_ms, self.link.jitter_ms, self.link.loss_rate,
            rng=self.rng, interrupt_period_s=interruption_s,
            interrupt_ms=interruption_ms, now=now)
        self.generator = from_hints(h, default_rate_mbps=ul_rate,
                                    default_size=packet_size, rng=self.rng, start=now)
        self.generator.set_rate(ul_rate)
        log.debug("UE %s 사용자평면 준비: UL %.2f / DL %.2f Mbps, OWD %.1f ms",
                  self.imsi, ul_rate, dl_rate, self.link.owd_ms)

    # ═════════════════════════════════════════════════════════════════════
    # NAS 송신 헬퍼
    # ═════════════════════════════════════════════════════════════════════
    def _protect(self, plain: bytes, *, new_context: bool = False) -> bytes:
        """보안 컨텍스트가 있으면 감싸고, 없으면 평문 그대로."""
        if not self.security_active:
            return plain
        sht = (nas.SHT_INTEGRITY_CIPHERED_NEW_CTX if new_context
               else nas.SHT_INTEGRITY_CIPHERED)
        out = nas.encode_secured(
            plain, security_header_type=sht, enc_alg=self.enc_alg,
            int_alg=self.int_alg, k_nas_enc=self.k_nas_enc, k_nas_int=self.k_nas_int,
            count=self.ul_count, direction=DIRECTION_UL)
        self.ul_count = (self.ul_count + 1) & 0xFFFFFF
        return out

    def build_registration_request(self, now: float) -> bytes:
        """초기 등록요청(SUCI 포함). 보안 이전이므로 평문."""
        self._t_start = now
        suci = nas.enc_suci_imsi(self.imsi)
        plain = nas.encode_registration_request(
            mobile_identity=suci, reg_type=nas.REG_TYPE_INITIAL, ngksi=self.ngksi,
            follow_on=True, enc_algs=self.supported_enc, int_algs=self.supported_int,
            requested_nssai=[(self.sst, self.sd)])
        self._last_registration_request = plain
        self.state = UeState.REGISTERING
        self.stats.nas_sent += 1
        return plain

    # ═════════════════════════════════════════════════════════════════════
    # NAS 수신 처리 — (응답 NAS, 설명) 을 돌려준다. 응답이 없으면 None.
    # ═════════════════════════════════════════════════════════════════════
    def handle_nas(self, data: bytes, now: float) -> Tuple[Optional[bytes], str]:
        """코어가 보낸 NAS 메시지를 처리하고 필요하면 응답을 만든다."""
        self.stats.nas_recv += 1
        try:
            if nas.is_security_protected(data):
                if not self.security_active:
                    # 보안 수립 전인데 보호된 메시지가 오면 MAC 검증은 건너뛴다
                    msg, _info = nas.decode_secured(
                        data, enc_alg=0, int_alg=0, k_nas_enc=b"", k_nas_int=b"",
                        count=self.dl_count, direction=DIRECTION_DL, verify_mac=False)
                else:
                    msg, info = nas.decode_secured(
                        data, enc_alg=self.enc_alg, int_alg=self.int_alg,
                        k_nas_enc=self.k_nas_enc, k_nas_int=self.k_nas_int,
                        count=self.dl_count, direction=DIRECTION_DL)
                    self.dl_count = info["count"] + 1
            else:
                msg = nas.decode(data)
        except nas.NasDecodeError as e:
            return None, f"NAS 디코딩 실패: {e}"

        handler = {
            nas.MT_AUTHENTICATION_REQUEST: self._on_authentication_request,
            nas.MT_SECURITY_MODE_COMMAND: self._on_security_mode_command,
            nas.MT_REGISTRATION_ACCEPT: self._on_registration_accept,
            nas.MT_REGISTRATION_REJECT: self._on_registration_reject,
            nas.MT_DL_NAS_TRANSPORT: self._on_dl_nas_transport,
            nas.MT_IDENTITY_REQUEST: self._on_identity_request,
            nas.MT_AUTHENTICATION_REJECT: self._on_authentication_reject,
            nas.MT_CONFIGURATION_UPDATE_COMMAND: self._on_configuration_update,
        }.get(msg.message_type)
        if handler is None:
            return None, f"{msg.name} (처리 없음)"
        return handler(msg, now)

    # ── 개별 처리기 ───────────────────────────────────────────────────────
    def _on_authentication_request(self, msg: nas.NasMessage, now: float):
        rand = msg.fields.get("rand")
        autn = msg.fields.get("autn")
        self.abba = msg.fields.get("abba") or b"\x00\x00"
        self.ngksi = msg.fields.get("ngksi", 0)
        if not rand or not autn:
            self.state = UeState.FAILED
            self.failure_reason = "AuthenticationRequest 에 RAND/AUTN 없음"
            return None, self.failure_reason

        good, sqn, vec = self.milenage.verify_autn(rand, autn)
        if not good:
            # 재동기화(AUTS) 대신 명시적 실패 — 시험 목적상 원인이 드러나야 한다
            self.state = UeState.FAILED
            self.failure_reason = "AUTN MAC 불일치(K/OPc/AMF 불일치 가능성)"
            auts = self.milenage.auts(rand, sqn)
            return nas.encode_authentication_failure(0x15, auts), self.failure_reason

        # 5G 키계층 유도
        sqn_xor_ak = autn[0:6]
        self.k_ausf = k_ausf(vec.ck, vec.ik, self.snn, sqn_xor_ak)
        self.k_seaf = k_seaf(self.k_ausf, self.snn)
        self.k_amf = k_amf(self.k_seaf, self.supi, self.abba)
        rs = res_star(vec.ck, vec.ik, self.snn, rand, vec.res)
        self.state = UeState.AUTHENTICATING
        self.stats.nas_sent += 1
        return nas.encode_authentication_response(rs), "AuthenticationResponse 송신"

    def _on_security_mode_command(self, msg: nas.NasMessage, now: float):
        self.enc_alg = msg.fields.get("enc_alg", 0)
        self.int_alg = msg.fields.get("int_alg", 0)
        self.ngksi = msg.fields.get("ngksi", self.ngksi)
        if self.k_amf is None:
            self.state = UeState.FAILED
            self.failure_reason = "인증 전에 SecurityModeCommand 수신"
            return None, self.failure_reason

        # 코어가 우리가 광고하지 않은 알고리즘을 골랐는지 검사(시험 항목)
        replayed = msg.fields.get("replayed_caps") or {}
        if replayed and set(replayed.get("enc", [])) != set(self.supported_enc):
            log.warning("UE %s: 재생된 보안능력이 광고와 다름 %s vs %s",
                        self.imsi, replayed.get("enc"), self.supported_enc)
        if self.enc_alg not in self.supported_enc or self.int_alg not in self.supported_int:
            self.state = UeState.FAILED
            self.failure_reason = (f"코어가 미광고 알고리즘 선택 "
                                   f"(enc={self.enc_alg}, int={self.int_alg})")
            return None, self.failure_reason

        self.k_nas_enc, self.k_nas_int = nas_keys(self.k_amf, self.enc_alg, self.int_alg)
        self.k_gnb = k_gnb(self.k_amf, self.ul_count)
        self.security_active = True
        self.ul_count = 0                       # 새 보안 컨텍스트 → 카운터 초기화
        self.state = UeState.SECURING

        # SecurityModeComplete 는 전체 등록요청을 NAS 컨테이너에 담아야 한다
        plain = nas.encode_security_mode_complete(
            nas_message_container=self._last_registration_request)
        self.stats.nas_sent += 1
        return self._protect(plain, new_context=True), \
            (f"SecurityModeComplete (enc={self.enc_alg}, int={self.int_alg})")

    def _on_registration_accept(self, msg: nas.NasMessage, now: float):
        self.guti = msg.fields.get("guti")
        self.state = UeState.REGISTERED
        if self._t_start is not None:
            self.stats.registration_time_s = now - self._t_start
        self.stats.nas_sent += 1
        return self._protect(nas.encode_registration_complete()), \
            "RegistrationComplete 송신 (등록 완료)"

    def _on_registration_reject(self, msg: nas.NasMessage, now: float):
        cause = msg.fields.get("cause")
        self.state = UeState.FAILED
        self.failure_reason = f"등록 거절 (5GMM cause={cause})"
        return None, self.failure_reason

    def _on_authentication_reject(self, msg: nas.NasMessage, now: float):
        self.state = UeState.FAILED
        self.failure_reason = "인증 거절(AuthenticationReject) — SIM 자격증명 확인 필요"
        return None, self.failure_reason

    def _on_identity_request(self, msg: nas.NasMessage, now: float):
        idtype = msg.fields.get("identity_type")
        if idtype == nas.ID_TYPE_SUCI:
            self.stats.nas_sent += 1
            return self._protect(nas.encode_identity_response(
                nas.enc_suci_imsi(self.imsi))), "IdentityResponse(SUCI) 송신"
        return None, f"IdentityRequest(type={idtype}) — 미지원 신원유형"

    def _on_configuration_update(self, msg: nas.NasMessage, now: float):
        return None, "ConfigurationUpdateCommand 수신(응답 불필요)"

    def _on_dl_nas_transport(self, msg: nas.NasMessage, now: float):
        """DL NAS Transport 안의 5GSM 메시지 처리."""
        payload = msg.fields.get("payload") or b""
        if not payload:
            return None, "DLNASTransport 페이로드 없음"
        try:
            sm = nas.decode(payload)
        except nas.NasDecodeError as e:
            return None, f"5GSM 디코딩 실패: {e}"
        return self.handle_5gsm(sm, now)

    def handle_5gsm(self, sm: nas.NasMessage, now: float) -> Tuple[Optional[bytes], str]:
        """5GSM(세션 관리) 메시지 처리 — PDU 세션 수립 결과에서 UE IP 를 얻는다."""
        if sm.message_type == nas.MT_PDU_SESSION_EST_ACCEPT:
            self.ue_ip = sm.fields.get("ue_ipv4") or self.ue_ip
            if self.ue_ip is None and sm.fields.get("ue_ipv6_ifid"):
                self.ue_ip = sm.fields["ue_ipv6_ifid"]
            self.session_ambr = sm.fields.get("session_ambr", {})
            if self.state in (UeState.REGISTERED, UeState.SESSION_PENDING):
                self.state = UeState.SESSION_PENDING
            if self._t_start is not None:
                self.stats.session_time_s = now - self._t_start
            return None, f"PDUSessionEstablishmentAccept (UE IP={self.ue_ip})"
        if sm.message_type == nas.MT_PDU_SESSION_EST_REJECT:
            self.state = UeState.FAILED
            self.failure_reason = f"PDU 세션 거절 (5GSM cause={sm.fields.get('cause')})"
            return None, self.failure_reason
        return None, f"{sm.name} (처리 없음)"

    # ── PDU 세션 요청 ─────────────────────────────────────────────────────
    def build_pdu_session_request(self) -> bytes:
        """UL NAS Transport 로 감싼 PDU Session Establishment Request."""
        sm = nas.encode_pdu_session_establishment_request(
            pdu_session_id=self.pdu_session_id, pti=1,
            pdu_session_type=self.pdu_session_type, ssc_mode=1)
        plain = nas.encode_ul_nas_transport(
            payload=sm, pdu_session_id=self.pdu_session_id,
            request_type=nas.REQUEST_TYPE_INITIAL,
            sst=self.sst, sd=self.sd, dnn=self.dnn)
        self.state = UeState.SESSION_PENDING
        self.stats.nas_sent += 1
        return self._protect(plain)

    def build_deregistration(self) -> bytes:
        mid = self.guti if self.guti else nas.enc_suci_imsi(self.imsi)
        plain = nas.encode_deregistration_request(
            ngksi=self.ngksi, mobile_identity=mid, switch_off=True)
        self.stats.nas_sent += 1
        return self._protect(plain)

    # ── 사용자평면 활성화 ─────────────────────────────────────────────────
    def activate(self, now: float) -> None:
        if self.ue_ip and self.upf_addr and self.ul_teid is not None:
            self.state = UeState.ACTIVE
            log.info("UE %s ACTIVE: ip=%s → UPF %s TEID=0x%08x (%s, DL %.1f/UL %.1f Mbps)",
                     self.imsi, self.ue_ip, self.upf_addr, self.ul_teid,
                     "+".join(self.applied_features), self.link.dl_mbps, self.link.ul_mbps)

    # ── manifest 용 요약 ──────────────────────────────────────────────────
    def manifest_entry(self) -> Dict[str, Any]:
        """정답(ground truth) 기록 — 코어측 측정 결과와 대조할 기준값."""
        return {
            "imsi": self.imsi, "supi": self.supi, "group": self.group,
            "state": self.state.value, "failure_reason": self.failure_reason,
            "ue_ip": self.ue_ip,
            "ran_ue_ngap_id": self.ran_ue_ngap_id,
            "amf_ue_ngap_id": self.amf_ue_ngap_id,
            "ul_teid": self.ul_teid, "dl_teid": self.dl_teid,
            "upf_addr": self.upf_addr,
            "pdu_session_id": self.pdu_session_id,
            "dnn": self.dnn, "sst": self.sst, "sd": self.sd,
            "qfis": self.qfis,
            "features": self.applied_features,
            "radio": {
                "label": self.profile.label,
                "bandwidth_mhz": self.profile.bandwidth_mhz,
                "scs_khz": self.profile.scs_khz,
                "dl_layers": self.profile.dl_layers,
                "ul_layers": self.profile.ul_layers,
                "duplex": self.profile.duplex,
                "half_duplex": self.profile.half_duplex,
                "freq_ghz": self.profile.freq_ghz,
                "propagation_delay_ms": self.profile.propagation_delay_ms,
                "notes": self.profile.notes,
            },
            "link_budget": {
                "dl_mbps": round(self.link.dl_mbps, 3),
                "ul_mbps": round(self.link.ul_mbps, 3),
                "peak_dl_mbps": round(self.link.peak_dl_mbps, 3),
                "peak_ul_mbps": round(self.link.peak_ul_mbps, 3),
                "sinr_db": round(self.link.sinr_db, 2),
                "cqi": self.link.cqi,
                "rtt_ms": round(self.link.rtt_ms, 3),
                "jitter_ms": round(self.link.jitter_ms, 3),
                "loss_rate": self.link.loss_rate,
                "n_prb": self.link.n_prb,
            },
            "signaling": {
                "five_qi": self.signaling.five_qi,
                "ue_ambr_dl": self.signaling.ue_ambr_dl,
                "ue_ambr_ul": self.signaling.ue_ambr_ul,
                "rrc_establishment_cause": self.signaling.rrc_establishment_cause,
                "redcap": self.signaling.redcap,
                "ntn": self.signaling.ntn,
                "ntn_orbit": self.signaling.ntn_orbit,
                "nas_timer_scale": self.signaling.nas_timer_scale,
                "tags": self.signaling.tags,
            },
            "traffic": {
                "pattern": self.traffic_hints.pattern,
                "packet_size": self.traffic_hints.packet_size,
                "period_ms": self.traffic_hints.period_ms,
                "burst_packets": self.traffic_hints.burst_packets,
                "offered_ul_mbps": (self.ul_shaper.rate_mbps if self.ul_shaper else None),
                "offered_dl_mbps": (self.dl_shaper.rate_mbps if self.dl_shaper else None),
            },
            "security": {
                "enc_alg": self.enc_alg, "int_alg": self.int_alg,
                "advertised_enc": self.supported_enc,
                "advertised_int": self.supported_int,
            },
            "stats": self.stats.as_dict(),
            "shaper": {
                "ul": self.ul_shaper.stats.as_dict() if self.ul_shaper else {},
                "dl": self.dl_shaper.stats.as_dict() if self.dl_shaper else {},
            },
        }


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    """UE 상태머신을 '가상의 코어' 와 대화시켜 검증(네트워크 불필요)."""
    ok = True
    key = bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc")
    opc = bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf")
    amf_field = bytes.fromhex("8000")
    imsi = "450050000000001"

    ue = Ue(imsi=imsi, key=key, opc=opc, amf_field=amf_field, ran_ue_ngap_id=1,
            features=["redcap"], ue_index=0)

    # (1) 초기 상태
    if ue.state is not UeState.DEREGISTERED:
        ok = False
        print("  [UE] 초기 상태 오류")

    # (2) 등록요청 → SUCI 가 IMSI 를 담는가
    rr = ue.build_registration_request(now=0.0)
    parsed = nas.decode(rr)
    if parsed.fields.get("identity", {}).get("imsi") != imsi:
        ok = False
        print(f"  [UE] 등록요청 SUCI 오류: {parsed.fields.get('identity')}")
    if ue.state is not UeState.REGISTERING:
        ok = False
        print("  [UE] REGISTERING 전이 실패")
    elif verbose:
        print("  [UE] RegistrationRequest(SUCI) OK")

    # (3) 인증: 네트워크 역할로 AUTN 생성 → UE 가 RES* 로 응답
    rand = bytes(range(16))
    sqn = bytes.fromhex("000000000020")
    net = Milenage(key, opc)
    autn = net.autn(rand, sqn, amf_field)
    auth_req = bytearray([nas.EPD_5GMM, 0x00, nas.MT_AUTHENTICATION_REQUEST,
                          0x01, 0x02, 0x00, 0x00])
    auth_req += bytes([0x21]) + rand
    auth_req += bytes([0x20, 0x10]) + autn
    resp, why = ue.handle_nas(bytes(auth_req), now=0.1)
    if resp is None or ue.state is not UeState.AUTHENTICATING:
        ok = False
        print(f"  [UE] 인증 처리 실패: {why}")
    else:
        rmsg = nas.decode(resp)
        # 네트워크가 계산한 XRES* 와 일치해야 한다
        vec = net.f2345(rand)
        expect = res_star(vec.ck, vec.ik, ue.snn, rand, vec.res)
        if rmsg.fields.get("res_star") != expect:
            ok = False
            print("  [UE] RES* 가 네트워크 XRES* 와 불일치")
        elif verbose:
            print("  [UE] 5G-AKA RES*=XRES* 일치 OK")

    # (4) 잘못된 AUTN 은 거부해야 한다
    ue_bad = Ue(imsi=imsi, key=key, opc=opc, amf_field=amf_field, ran_ue_ngap_id=2)
    ue_bad.build_registration_request(0.0)
    bad_autn = bytearray(autn); bad_autn[10] ^= 0xFF
    bad_req = bytearray([nas.EPD_5GMM, 0x00, nas.MT_AUTHENTICATION_REQUEST,
                         0x01, 0x02, 0x00, 0x00])
    bad_req += bytes([0x21]) + rand + bytes([0x20, 0x10]) + bytes(bad_autn)
    r2, why2 = ue_bad.handle_nas(bytes(bad_req), now=0.1)
    if ue_bad.state is not UeState.FAILED or r2 is None:
        ok = False
        print(f"  [UE] 잘못된 AUTN 을 수락함: {why2}")
    else:
        f = nas.decode(r2)
        if f.message_type != nas.MT_AUTHENTICATION_FAILURE:
            ok = False
            print("  [UE] AUTN 실패 시 AuthenticationFailure 를 보내지 않음")
        elif verbose:
            print("  [UE] 잘못된 AUTN 거부 + AuthenticationFailure(AUTS) OK")

    # (5) SecurityModeCommand → SecurityModeComplete (보안 활성)
    replayed = nas.enc_ue_security_capability(ue.supported_enc, ue.supported_int)
    smc = bytearray([nas.EPD_5GMM, 0x00, nas.MT_SECURITY_MODE_COMMAND])
    smc.append((2 << 4) | 2)                        # NEA2 / NIA2
    smc.append(0x01)
    smc.append(len(replayed)); smc += replayed
    resp, why = ue.handle_nas(bytes(smc), now=0.2)
    if not ue.security_active or resp is None:
        ok = False
        print(f"  [UE] SecurityModeCommand 처리 실패: {why}")
    else:
        if not nas.is_security_protected(resp):
            ok = False
            print("  [UE] SecurityModeComplete 가 보호되지 않음")
        # 네트워크 역할로 복호 검증
        back, info = nas.decode_secured(
            resp, enc_alg=ue.enc_alg, int_alg=ue.int_alg, k_nas_enc=ue.k_nas_enc,
            k_nas_int=ue.k_nas_int, count=0, direction=DIRECTION_UL)
        if not info["mac_ok"] or back.message_type != nas.MT_SECURITY_MODE_COMPLETE:
            ok = False
            print(f"  [UE] SecurityModeComplete 검증 실패: {info}")
        elif back.fields.get("nas_message_container") != rr:
            ok = False
            print("  [UE] SecurityModeComplete 에 전체 등록요청이 없음")
        elif verbose:
            print("  [UE] SecurityModeComplete(보호+등록요청 재전송) OK")

    # (6) 코어가 미광고 알고리즘을 고르면 실패해야 한다(시험 항목)
    ue_alg = Ue(imsi=imsi, key=key, opc=opc, amf_field=amf_field, ran_ue_ngap_id=3,
                supported_enc=[0, 2], supported_int=[0, 2])
    ue_alg.build_registration_request(0.0)
    ue_alg.handle_nas(bytes(auth_req), now=0.1)
    smc_bad = bytearray([nas.EPD_5GMM, 0x00, nas.MT_SECURITY_MODE_COMMAND])
    smc_bad.append((1 << 4) | 1)                    # NEA1/NIA1 — 광고 안 함
    smc_bad.append(0x01); smc_bad.append(len(replayed)); smc_bad += replayed
    _r, why = ue_alg.handle_nas(bytes(smc_bad), now=0.2)
    if ue_alg.state is not UeState.FAILED:
        ok = False
        print("  [UE] 미광고 알고리즘 선택을 통과시킴")
    elif verbose:
        print(f"  [UE] 미광고 알고리즘 탐지 OK ({why})")

    # (7) RegistrationAccept → RegistrationComplete
    ra = bytearray([nas.EPD_5GMM, 0x00, nas.MT_REGISTRATION_ACCEPT, 0x01, 0x01])
    guti = nas.enc_5g_guti("450", "05", 2, 1, 0, 0x12345678)
    ra += bytes([0x77]) + len(guti).to_bytes(2, "big") + guti
    ue.dl_count = 0
    resp, why = ue.handle_nas(bytes(ra), now=0.3)
    if ue.state is not UeState.REGISTERED or resp is None:
        ok = False
        print(f"  [UE] RegistrationAccept 처리 실패: {why}")
    elif ue.guti != guti:
        ok = False
        print("  [UE] 5G-GUTI 저장 실패")
    elif verbose:
        print(f"  [UE] RegistrationAccept → REGISTERED (등록 {ue.stats.registration_time_s:.3f}s) OK")

    # (8) PDU 세션 요청 생성
    req = ue.build_pdu_session_request()
    back, info = nas.decode_secured(req, enc_alg=ue.enc_alg, int_alg=ue.int_alg,
                                    k_nas_enc=ue.k_nas_enc, k_nas_int=ue.k_nas_int,
                                    count=ue.ul_count - 1, direction=DIRECTION_UL)
    if back.message_type != nas.MT_UL_NAS_TRANSPORT:
        ok = False
        print("  [UE] PDU 세션 요청이 ULNASTransport 가 아님")
    else:
        inner = nas.decode(back.fields["payload"])
        if inner.message_type != nas.MT_PDU_SESSION_EST_REQUEST:
            ok = False
            print("  [UE] 내부 5GSM 메시지가 세션수립 요청이 아님")
        elif back.fields.get("dnn") != "internet":
            ok = False
            print(f"  [UE] DNN 누락: {back.fields.get('dnn')}")
        elif verbose:
            print("  [UE] PDUSessionEstablishmentRequest(ULNASTransport) OK")

    # (9) Accept 처리 → UE IP 획득
    acc = bytearray([nas.EPD_5GSM, ue.pdu_session_id, 0, nas.MT_PDU_SESSION_EST_ACCEPT])
    acc.append((1 << 4) | nas.PDU_TYPE_IPV4)
    qos = bytes([0x01, 0x20, 0x01, 0x00])
    acc += len(qos).to_bytes(2, "big") + qos
    ambr = nas.enc_session_ambr(100_000_000, 50_000_000)
    acc += bytes([len(ambr)]) + ambr
    acc += bytes([0x29, 0x05, nas.PDU_TYPE_IPV4, 10, 45, 0, 7])
    _r, why = ue.handle_5gsm(nas.decode(bytes(acc)), now=0.4)
    if ue.ue_ip != "10.45.0.7":
        ok = False
        print(f"  [UE] UE IP 획득 실패: {ue.ue_ip} ({why})")
    elif verbose:
        print(f"  [UE] PDU 세션 Accept → UE IP {ue.ue_ip} OK")

    # (10) 사용자평면 활성화
    ue.upf_addr = "10.1.16.60"
    ue.ul_teid = 0x00000123
    ue.dl_teid = 0x00000456
    ue.setup_uplane(0.5, default_ul_mbps=50.0, default_dl_mbps=100.0, packet_size=1400)
    ue.activate(0.5)
    if not ue.is_active:
        ok = False
        print("  [UE] ACTIVE 전이 실패")
    # RedCap 이므로 상한이 낮아야 한다
    if ue.ul_shaper and ue.ul_shaper.rate_mbps > 50.0:
        ok = False
        print(f"  [UE] RedCap UL 상한이 과다: {ue.ul_shaper.rate_mbps}")
    elif verbose:
        print(f"  [UE] ACTIVE (UL {ue.ul_shaper.rate_mbps:.1f} / "
              f"DL {ue.dl_shaper.rate_mbps:.1f} Mbps) OK")

    # (11) manifest 항목이 정답을 담는가
    entry = ue.manifest_entry()
    for k in ("imsi", "ue_ip", "ul_teid", "dl_teid", "features", "link_budget", "radio"):
        if k not in entry:
            ok = False
            print(f"  [UE] manifest 에 {k} 없음")
    if entry["signaling"]["redcap"] is not True:
        ok = False
        print("  [UE] manifest 에 RedCap 표시 누락")
    elif verbose:
        print("  [UE] manifest 정답 기록 OK")

    # (12) NTN 단말은 큰 RTT 를 가져야 한다
    ntn_ue = Ue(imsi=imsi, key=key, opc=opc, amf_field=amf_field, ran_ue_ngap_id=9,
                features=["ntn"], feature_params={"ntn": {"orbit": "geo"}})
    if ntn_ue.link.rtt_ms < 400:
        ok = False
        print(f"  [UE] NTN GEO RTT 이상: {ntn_ue.link.rtt_ms}")
    elif verbose:
        print(f"  [UE] NTN GEO 단말 RTT {ntn_ue.link.rtt_ms:.0f} ms OK")
    return ok


if __name__ == "__main__":
    print("UE selftest:", "PASS" if selftest(verbose=True) else "FAIL")
