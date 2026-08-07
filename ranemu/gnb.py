#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.gnb — 기지국(gNB) 에뮬레이터. 이 패키지의 오케스트레이터.

역할
====
1. **N2 수립**: AMF 에 SCTP 연결 → NGSetupRequest/Response
2. **단말 수용**: 그룹 설정대로 UE 를 만들고 RAN-UE-NGAP-ID / DL TEID 를 배정
3. **NAS 릴레이**: UE 가 만든 NAS 를 InitialUEMessage/UplinkNASTransport 로 올리고,
   코어가 내린 NAS 를 해당 UE 에 전달
4. **N3 종단**: PDUSessionResourceSetupRequest 에서 UPF 주소/TEID 를 받아
   PDUSessionResourceSetupResponse 로 gNB 측 TEID 를 알려준 뒤, 그 터널로 실제
   사용자평면 패킷을 흘린다
5. **feature 반영**: 단말별 무선 프로파일이 정한 속도/지연/손실/단절을 쉐이퍼로 적용

전부 **단일 이벤트 루프**다(스레드 없음). SCTP·GTP-U 소켓을 select 로 감시하고,
트래픽 송신 시각은 쉐이퍼가 계산한 다음 시각으로 잡는다.
"""
from __future__ import annotations

import os
import random
import select
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import features as feat
from .config import RunConfig
from .nas import nas5gs as nas
from .ngap import messages as ngap
from .transport.gtpu import GtpuSocket, Ipv4UdpTemplate, MSG_ECHO_REQUEST, MSG_GPDU
from .transport.gtpu import echo_response
from .transport.sctp import SctpClient, SctpError
from .ue import Ue, UeState
from .util import get_logger, human_bps, mono, plmn_encode

log = get_logger("ranemu.gnb")


@dataclass
class GnbStats:
    ngap_sent: int = 0
    ngap_recv: int = 0
    ul_packets: int = 0
    ul_bytes: int = 0
    dl_packets: int = 0
    dl_bytes: int = 0
    dl_unmatched: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        d = dict(self.__dict__)
        dur = max(1e-9, (self.end_time or mono()) - self.start_time)
        d["duration_s"] = round(dur, 3)
        d["ul_mbps"] = round(self.ul_bytes * 8 / dur / 1e6, 3)
        d["dl_mbps"] = round(self.dl_bytes * 8 / dur / 1e6, 3)
        return d


class Gnb:
    """기지국 에뮬레이터."""

    def __init__(self, cfg: RunConfig):
        self.cfg = cfg
        self.plmn = plmn_encode(cfg.gnb.mcc, cfg.gnb.mnc)
        self.nci = cfg.gnb.nr_cell_identity()
        self.rng = random.Random(cfg.seed)
        self.sctp: Optional[SctpClient] = None
        self.gtpu: Optional[GtpuSocket] = None
        self.ues: List[Ue] = []
        self.by_ran_id: Dict[int, Ue] = {}
        self.by_dl_teid: Dict[int, Ue] = {}
        self.stats = GnbStats()
        self.ng_setup_ok = False
        self.events: List[Dict[str, Any]] = []       # 진단 로그(manifest 에 포함)
        self._next_ran_id = 1
        self._next_teid = 0x00000001
        self._n3_advertise = (cfg.gnb.n3_advertise_addr or cfg.gnb.n3_local_addr)
        #: (ue_ip, size) → 패킷 템플릿 (체크섬 재계산 회피)
        self._pkt_templates: Dict[Tuple[str, int], Ipv4UdpTemplate] = {}
        #: 무손실 정답 캡처
        self._truth_pcap = None
        self._truth_framer = None
        #: 시나리오 계층 훅(선택). None 이면 gnb 는 시나리오의 존재를 모른다 —
        #: 계측 계층을 얹어도 기존 경로가 한 바이트도 달라지지 않도록 하는 장치.
        self.hooks: Any = None
        #: 템플릿 캐시 절제 스위치(실험용). True 면 패킷마다 IP/UDP 를 처음부터
        #: 만든다 — 캐시의 이득을 주장 대신 대조군으로 재기 위한 것이며, 정상
        #: 실행에서는 건드리지 않는다.
        self.no_template_cache: bool = False

    # ── 로그 ──────────────────────────────────────────────────────────────
    def _event(self, kind: str, **kw: Any) -> None:
        rec = {"t": round(mono() - self.stats.start_time, 4), "kind": kind}
        rec.update(kw)
        self.events.append(rec)
        if len(self.events) > 20000:                # 폭주 방지
            self.events = self.events[-10000:]

    # ═════════════════════════════════════════════════════════════════════
    # 설정
    # ═════════════════════════════════════════════════════════════════════
    def build_ues(self) -> List[Ue]:
        """설정의 ue_groups 로부터 단말들을 만든다."""
        ues: List[Ue] = []
        for g in self.cfg.ue_groups:
            sec = self.cfg.security_for(g)
            key, opc, amf_field = sec.key_bytes(), sec.opc_bytes(), sec.amf_bytes()
            for i in range(g.count):
                ue = Ue(imsi=g.imsi_at(i), key=key, opc=opc, amf_field=amf_field,
                        ran_ue_ngap_id=self._alloc_ran_id(),
                        dnn=g.dnn, sst=g.sst, sd=g.sd,
                        pdu_session_id=1, pdu_session_type=g.pdu_session_type,
                        features=g.features, feature_params=g.feature_params,
                        ue_index=len(ues), seed=self.cfg.seed,
                        supported_enc=sec.supported_enc, supported_int=sec.supported_int,
                        group=g.name, traffic_pattern=g.traffic,
                        traffic_params=g.traffic_params)
                ue.dl_teid = self._alloc_teid()
                ues.append(ue)
                self.by_ran_id[ue.ran_ue_ngap_id] = ue
                self.by_dl_teid[ue.dl_teid] = ue
        self.ues = ues
        log.info("단말 %d대 생성 (그룹 %d개)", len(ues), len(self.cfg.ue_groups))
        return ues

    def _alloc_ran_id(self) -> int:
        v = self._next_ran_id
        self._next_ran_id += 1
        return v

    def _alloc_teid(self) -> int:
        v = self._next_teid
        self._next_teid += 1
        return v

    # ═════════════════════════════════════════════════════════════════════
    # N2 / N3 개통
    # ═════════════════════════════════════════════════════════════════════
    def connect(self) -> None:
        """SCTP 연결 + NGSetup + GTP-U 소켓."""
        self.stats.start_time = mono()
        c = self.cfg
        self.sctp = SctpClient(local_addr=c.gnb.n2_local_addr,
                               local_port=c.gnb.n2_local_port,
                               timeout=c.procedure_timeout)
        self.sctp.connect(c.core.amf_addr, c.core.amf_port)

        self.gtpu = GtpuSocket(local_addr=c.gnb.n3_local_addr,
                               local_port=c.gnb.n3_local_port)
        self.gtpu.open()
        self._open_truth_pcap()
        if self._n3_advertise in ("0.0.0.0", "", None):
            self._n3_advertise = self._guess_local_ip(c.core.amf_addr)
        log.info("N3 광고 주소: %s:%d", self._n3_advertise, self.gtpu.local_port)

        self.ng_setup()

    def _open_truth_pcap(self) -> None:
        """송신 GTP-U 를 무손실로 기록할 pcap 을 연다(정답 캡처)."""
        cap = self.cfg.capture
        if not cap.truth_pcap:
            return
        from .pcapio import GtpuFramer, PcapWriter
        path = cap.truth_pcap_path or os.path.join(cap.out_dir,
                                                   f"{self.cfg.name}.truth.pcap")
        self._truth_pcap = PcapWriter(path)
        # dpi_engine 은 외부 UDP 2152 로 GTP-U 를 식별하므로 그 포트로 프레이밍한다
        self._truth_framer = GtpuFramer(self._n3_advertise or "10.0.0.1",
                                        self.cfg.core.upf_addr or "10.0.0.2")
        log.info("정답 캡처 기록: %s", path)

    @staticmethod
    def _guess_local_ip(peer: str) -> str:
        """코어로 나가는 경로의 로컬 IP 를 알아낸다(패킷은 보내지 않는다)."""
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((peer, 9))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            s.close()

    def ng_setup(self) -> bool:
        """NGSetupRequest → Response 대기."""
        c = self.cfg.gnb
        slices = [(s.get("sst", 1), s.get("sd")) for s in c.slices] or [(1, None)]
        pdu = ngap.ng_setup_request(
            plmn=self.plmn, gnb_id=c.gnb_id, gnb_id_bits=c.gnb_id_bits, tac=c.tac,
            slices=slices, ran_node_name=c.name, paging_drx=c.paging_drx)
        self._send_ngap(pdu, "NGSetupRequest")

        deadline = mono() + self.cfg.procedure_timeout
        while mono() < deadline:
            data = self.sctp.recv_until(deadline)
            if data is None:
                break
            self.stats.ngap_recv += 1
            try:
                resp = ngap.parse_pdu(data)
            except ngap.NgapError as e:
                log.warning("NGSetup 응답 파싱 실패: %s", e)
                continue
            if resp.procedure_code != ngap.PROC_NG_SETUP:
                continue
            if resp.pdu_type == ngap.PDU_SUCCESSFUL:
                self.ng_setup_ok = True
                amf_name = ""
                raw = resp.ies.get(ngap.IE_AMF_NAME)
                if raw:
                    try:
                        from .ngap.aper import BitReader
                        amf_name = BitReader(raw).printable_string(1, 150)
                    except Exception:  # noqa: BLE001
                        amf_name = ""
                log.info("NGSetupResponse 수신 — AMF '%s' 와 N2 수립 완료", amf_name)
                self._event("ng_setup", ok=True, amf_name=amf_name)
                return True
            cause = resp.ies.get(ngap.IE_CAUSE)
            log.error("NGSetupFailure 수신 (cause=%s)", cause.hex() if cause else "?")
            self._event("ng_setup", ok=False)
            return False
        log.error("NGSetupResponse 시간초과(%.1fs)", self.cfg.procedure_timeout)
        self._event("ng_setup", ok=False, reason="timeout")
        return False

    def _send_ngap(self, pdu: bytes, what: str) -> None:
        if self.sctp is None:
            raise SctpError("N2 미연결")
        self.sctp.send(pdu)
        self.stats.ngap_sent += 1
        log.debug("→ NGAP %s (%dB)", what, len(pdu))

    # ═════════════════════════════════════════════════════════════════════
    # 등록 개시
    # ═════════════════════════════════════════════════════════════════════
    def start_registration(self, ue: Ue, now: float) -> None:
        nas_pdu = ue.build_registration_request(now)
        pdu = ngap.initial_ue_message(
            ran_ue_ngap_id=ue.ran_ue_ngap_id, nas_pdu=nas_pdu, plmn=self.plmn,
            nr_cell_identity=self.nci, tac=self.cfg.gnb.tac,
            rrc_cause=ue.signaling.rrc_establishment_cause, ue_context_request=True)
        self._send_ngap(pdu, f"InitialUEMessage[{ue.imsi}]")
        self._event("registration_start", imsi=ue.imsi, ran_ue_ngap_id=ue.ran_ue_ngap_id,
                    features=ue.applied_features)

    def _send_ul_nas(self, ue: Ue, nas_pdu: bytes) -> None:
        if ue.amf_ue_ngap_id is None:
            log.warning("UE %s: AMF-UE-NGAP-ID 미확보 상태에서 UL NAS 시도", ue.imsi)
            return
        pdu = ngap.uplink_nas_transport(
            amf_ue_ngap_id=ue.amf_ue_ngap_id, ran_ue_ngap_id=ue.ran_ue_ngap_id,
            nas_pdu=nas_pdu, plmn=self.plmn, nr_cell_identity=self.nci,
            tac=self.cfg.gnb.tac)
        self._send_ngap(pdu, f"UplinkNASTransport[{ue.imsi}]")

    # ═════════════════════════════════════════════════════════════════════
    # NGAP 수신 처리
    # ═════════════════════════════════════════════════════════════════════
    def handle_ngap(self, data: bytes, now: float) -> None:
        self.stats.ngap_recv += 1
        try:
            pdu = ngap.parse_pdu(data)
        except ngap.NgapError as e:
            log.warning("NGAP 파싱 실패(무시): %s", e)
            return
        common = ngap.extract_common(pdu)
        ue = self._resolve_ue(pdu, common)
        log.debug("← NGAP %s/%s ue=%s", pdu.type_name, pdu.name,
                  ue.imsi if ue else "-")

        if ue is not None and common.get("amf_ue_ngap_id") is not None:
            ue.amf_ue_ngap_id = common["amf_ue_ngap_id"]

        proc = pdu.procedure_code
        if proc == ngap.PROC_DOWNLINK_NAS_TRANSPORT:
            self._on_dl_nas(ue, common.get("nas_pdu"), now)
        elif proc == ngap.PROC_INITIAL_CONTEXT_SETUP:
            self._on_initial_context_setup(ue, pdu, common, now)
        elif proc == ngap.PROC_PDU_SESSION_RESOURCE_SETUP:
            self._on_pdu_session_setup(ue, pdu, common, now)
        elif proc == ngap.PROC_UE_CONTEXT_RELEASE:
            self._on_ue_context_release(ue, pdu, now)
        elif proc == ngap.PROC_PAGING:
            self._event("paging")
        elif proc == ngap.PROC_ERROR_INDICATION:
            log.warning("코어가 ErrorIndication 을 보냄")
            self._event("error_indication")
        else:
            log.debug("처리하지 않는 NGAP 절차: %s", pdu.name)

    def _resolve_ue(self, pdu: ngap.NgapPdu, common: Dict[str, Any]) -> Optional[Ue]:
        ran_id = common.get("ran_ue_ngap_id")
        if ran_id is None and pdu.procedure_code == ngap.PROC_UE_CONTEXT_RELEASE:
            ran_id = ngap.extract_ue_ngap_ids(pdu).get("ran_ue_ngap_id")
        if ran_id is not None:
            return self.by_ran_id.get(ran_id)
        # AMF-UE-NGAP-ID 로만 온 경우
        amf_id = common.get("amf_ue_ngap_id")
        if amf_id is not None:
            for u in self.ues:
                if u.amf_ue_ngap_id == amf_id:
                    return u
        return None

    def _on_dl_nas(self, ue: Optional[Ue], nas_pdu: Optional[bytes], now: float) -> None:
        if ue is None or not nas_pdu:
            return
        resp, why = ue.handle_nas(nas_pdu, now)
        log.debug("UE %s: %s", ue.imsi, why)
        self._event("nas", imsi=ue.imsi, detail=why, state=ue.state.value)
        if resp:
            self._send_ul_nas(ue, resp)
        self._maybe_request_session(ue, now)

    def _maybe_request_session(self, ue: Ue, now: float) -> None:
        """등록이 끝나면 곧바로 PDU 세션을 요청한다."""
        if ue.state is UeState.REGISTERED and not self.cfg.uplane_only:
            self._send_ul_nas(ue, ue.build_pdu_session_request())
            self._event("pdu_session_request", imsi=ue.imsi)

    def _on_initial_context_setup(self, ue: Optional[Ue], pdu: ngap.NgapPdu,
                                  common: Dict[str, Any], now: float) -> None:
        if ue is None:
            return
        # 안에 NAS 가 실려 있으면 먼저 처리(등록수락이 여기 오는 코어도 있다)
        if common.get("nas_pdu"):
            resp, why = ue.handle_nas(common["nas_pdu"], now)
            self._event("nas", imsi=ue.imsi, detail=why, state=ue.state.value)
            if resp:
                self._send_ul_nas(ue, resp)

        # PDU 세션이 함께 왔으면 터널을 세운다
        items = ngap.extract_pdu_session_setup_request(pdu)
        setup_items = self._accept_sessions(ue, items, now)
        self._send_ngap(ngap.initial_context_setup_response(
            amf_ue_ngap_id=ue.amf_ue_ngap_id or 0, ran_ue_ngap_id=ue.ran_ue_ngap_id,
            setup_items=setup_items or None), f"InitialContextSetupResponse[{ue.imsi}]")
        self._event("initial_context_setup", imsi=ue.imsi, sessions=len(setup_items))
        self._maybe_request_session(ue, now)

    def _on_pdu_session_setup(self, ue: Optional[Ue], pdu: ngap.NgapPdu,
                              common: Dict[str, Any], now: float) -> None:
        if ue is None:
            return
        items = ngap.extract_pdu_session_setup_request(pdu)
        setup_items = self._accept_sessions(ue, items, now)
        self._send_ngap(ngap.pdu_session_resource_setup_response(
            amf_ue_ngap_id=ue.amf_ue_ngap_id or 0, ran_ue_ngap_id=ue.ran_ue_ngap_id,
            setup_items=setup_items), f"PDUSessionResourceSetupResponse[{ue.imsi}]")
        self._event("pdu_session_setup", imsi=ue.imsi, sessions=len(setup_items),
                    upf=ue.upf_addr, ul_teid=ue.ul_teid, dl_teid=ue.dl_teid)

    def _accept_sessions(self, ue: Ue, items: List[Dict[str, Any]],
                         now: float) -> List[Tuple[int, bytes]]:
        """코어가 요청한 PDU 세션들을 수락하고 gNB 측 터널을 만든다."""
        out: List[Tuple[int, bytes]] = []
        for item in items:
            # 안에 실린 NAS 에서 UE IP 를 얻는다.
            # 주의: 이 NAS 는 보안 컨텍스트 수립 이후이므로 **보호되어 있다**.
            # 평문 디코더로 열면 실패하므로 반드시 UE 의 handle_nas 를 거쳐야 한다
            # (DL NAS Transport → 내부 5GSM → PDU 주소 추출 경로를 UE 가 안다).
            if item.get("nas_pdu"):
                resp, why = ue.handle_nas(item["nas_pdu"], now)
                log.debug("UE %s: %s", ue.imsi, why)
                if resp:
                    self._send_ul_nas(ue, resp)
            if item.get("upf_addr"):
                ue.upf_addr = item["upf_addr"]
                ue.ul_teid = item["upf_teid"]
            if item.get("qfis"):
                ue.qfis = item["qfis"]
            psi = item.get("pdu_session_id", ue.pdu_session_id)
            ue.pdu_session_id = psi
            transfer = ngap.enc_pdu_session_resource_setup_response_transfer(
                self._n3_advertise, ue.dl_teid or 0, ue.qfis)
            out.append((psi, transfer))

        if out:
            ue.setup_uplane(now, default_ul_mbps=self.cfg.traffic.offered_ul_mbps,
                            default_dl_mbps=self.cfg.traffic.offered_dl_mbps,
                            packet_size=self.cfg.traffic.packet_size)
            ue.activate(now)
        return out

    def _on_ue_context_release(self, ue: Optional[Ue], pdu: ngap.NgapPdu,
                               now: float) -> None:
        ids = ngap.extract_ue_ngap_ids(pdu)
        if ue is None and ids.get("ran_ue_ngap_id") is not None:
            ue = self.by_ran_id.get(ids["ran_ue_ngap_id"])
        if ue is None:
            return
        self._send_ngap(ngap.ue_context_release_complete(
            amf_ue_ngap_id=ue.amf_ue_ngap_id or ids.get("amf_ue_ngap_id", 0),
            ran_ue_ngap_id=ue.ran_ue_ngap_id), f"UEContextReleaseComplete[{ue.imsi}]")
        ue.state = UeState.RELEASED
        self._event("ue_context_release", imsi=ue.imsi)

    # ═════════════════════════════════════════════════════════════════════
    # 사용자평면
    # ═════════════════════════════════════════════════════════════════════
    def _pump_uplink(self, now: float) -> float:
        """활성 단말의 상향 트래픽을 쉐이핑해 전송. 다음 처리 시각을 반환."""
        next_wake = now + 0.05
        t_cfg = self.cfg.traffic
        for ue in self.ues:
            if not ue.is_active or ue.generator is None or ue.ul_shaper is None:
                continue
            events = ue.generator.next_events(now, max_events=512)
            for ev in events:
                good, why = ue.ul_shaper.try_send(ev.size, now)
                if not good:
                    if why == "rate":
                        ue.stats.ul_dropped_rate += 1
                    elif why == "loss":
                        ue.stats.ul_dropped_loss += 1
                    elif why == "interrupt":
                        ue.stats.ul_dropped_interrupt += 1
                    continue
                self._send_user_packet(ue, ev.size, now,
                                       sched=getattr(ev, "time", now))
            nt = ue.generator.next_time()
            if nt > now:
                next_wake = min(next_wake, nt)
        return next_wake

    def _send_user_packet(self, ue: Ue, size: int, now: float,
                          sched: Optional[float] = None) -> None:
        """단말의 IP 패킷을 만들어 GTP-U 로 UPF 에 보낸다.

        패킷은 단말·크기별 템플릿에서 만든다. 매번 전체 체크섬을 다시 계산하면
        파이썬 루프가 사용자평면 처리량의 병목이 된다(실측: 생성시간의 88%).
        """
        if self.gtpu is None or not ue.ue_ip or not ue.upf_addr or ue.ul_teid is None:
            return
        t = self.cfg.traffic
        if self.no_template_cache:
            # 템플릿 캐시 절제(ablation) — 논문의 가속 주장을 손으로 적은 값이 아니라
            # 같은 조건에서 재는 대조군으로 만들기 위해서만 존재한다. 계측 훅과는
            # 함께 쓰지 않는다(스탬프는 템플릿에 새기므로).
            from .transport.gtpu import build_ipv4_udp
            inner = build_ipv4_udp(ue.ue_ip, t.dest_addr,
                                   40000 + (ue.ue_index & 0x3FFF), t.dest_port,
                                   bytes(max(0, size - 28)),
                                   ident=ue.stats.ul_packets & 0xFFFF)
            self._send_inner(ue, inner, t, now)
            return
        key = (ue.ue_ip, size)
        tmpl = self._pkt_templates.get(key)
        if tmpl is None:
            tmpl = Ipv4UdpTemplate(ue.ue_ip, t.dest_addr,
                                   40000 + (ue.ue_index & 0x3FFF), t.dest_port,
                                   payload_len=max(0, size - 28))   # IP(20)+UDP(8)
            self._pkt_templates[key] = tmpl
        # 시나리오 계층이 붙어 있으면 페이로드 앞에 계측 스탬프를 새긴다.
        # 훅이 없으면(hooks=None) 아래 한 줄이 건너뛰어져 기존 경로와 바이트 단위로
        # 동일하다 — 계측을 위해 기존 동작을 바꾸지 않는다는 것이 이 설계의 전제다.
        if self.hooks is not None:
            # sched(생성 예정 시각)를 함께 넘긴다. now−sched 는 **에뮬레이터 자신이
            # 붙인 지연**이라, 이것이 크면 측정된 왕복지연은 코어가 아니라 우리
            # 이벤트 루프를 재고 있다는 뜻이 된다. 계측기가 병목이 아님을 스스로
            # 증명할 수 있어야 판정에 의미가 있다.
            self.hooks.stamp_template(ue, tmpl, now, sched=sched)
        inner = tmpl.build(ue.stats.ul_packets & 0xFFFF)
        self._send_inner(ue, inner, t, now)

    def _send_inner(self, ue: Ue, inner: bytes, t: Any, now: float) -> None:
        """완성된 내부 IP 데이터그램을 GTP-U 로 실어 보내고 계상한다."""
        qfi = ue.qfis[0] if ue.qfis else 1
        seq = None
        if t.gtpu_sequence:
            ue.gtpu_seq = (ue.gtpu_seq + 1) & 0xFFFF   # 터널별 카운터
            seq = ue.gtpu_seq
        try:
            n = self.gtpu.send_gpdu(ue.ul_teid, inner, ue.upf_addr,
                                    self.cfg.core.upf_port, qfi=qfi, sequence=seq)
        except OSError as e:
            log.debug("GTP-U 송신 실패(무시): %s", e)
            return
        if self._truth_pcap is not None:
            from .transport.gtpu import encode as _gtpu_encode, MSG_GPDU as _MSG_GPDU
            self._truth_pcap.write(
                now, self._truth_framer.frame(
                    _gtpu_encode(_MSG_GPDU, ue.ul_teid, inner, sequence=seq, qfi=qfi)))
        ue.stats.ul_packets += 1
        ue.stats.ul_bytes += len(inner)
        if ue.stats.first_ul_time is None:
            ue.stats.first_ul_time = now
        ue.stats.last_ul_time = now
        self.stats.ul_packets += 1
        self.stats.ul_bytes += n

    def _pump_downlink(self, now: float, budget: int = 512) -> None:
        """UPF 가 보낸 GTP-U 를 받아 단말별로 계상한다."""
        if self.gtpu is None:
            return
        for _ in range(budget):
            got = self.gtpu.recvfrom(timeout=0.0)
            if got is None:
                return
            pkt, peer = got
            if pkt.message_type == MSG_ECHO_REQUEST:
                try:
                    self.gtpu.sendto(echo_response(pkt.sequence or 0), peer[0], peer[1])
                except OSError:
                    pass
                continue
            if pkt.message_type != MSG_GPDU:
                continue
            ue = self.by_dl_teid.get(pkt.teid)
            if ue is None:
                self.stats.dl_unmatched += 1
                continue
            # 하향도 무선 특성을 겪는다(지연/손실은 통계에만 반영)
            if ue.dl_shaper is not None:
                good, _why = ue.dl_shaper.try_send(len(pkt.payload), now)
                if not good:
                    continue
            ue.stats.dl_packets += 1
            ue.stats.dl_bytes += len(pkt.payload)
            self.stats.dl_packets += 1
            self.stats.dl_bytes += len(pkt.payload)
            # 돌아온 패킷에 스탬프가 있으면 왕복지연으로 해소한다.
            if self.hooks is not None:
                self.hooks.on_dl_payload(ue, pkt.payload, now)

    # ═════════════════════════════════════════════════════════════════════
    # 메인 루프
    # ═════════════════════════════════════════════════════════════════════
    def run(self) -> Dict[str, Any]:
        """등록 → 세션수립 → 트래픽 → 결과 반환."""
        self.build_ues()
        self.connect()
        if not self.ng_setup_ok:
            return self.result(failed="NGSetup 실패 — 코어 주소/PLMN/TAC 를 확인하십시오")

        t0 = mono()
        # 그룹별 램프업 시각 계산
        schedule: List[Tuple[float, Ue]] = []
        idx = 0
        for g in self.cfg.ue_groups:
            for i in range(g.count):
                delay = (g.ramp_seconds * i / max(1, g.count - 1)) if g.ramp_seconds else 0.0
                schedule.append((t0 + delay, self.ues[idx]))
                idx += 1
        schedule.sort(key=lambda x: x[0])
        pending = list(schedule)

        duration = self.cfg.traffic.duration
        end_time = t0 + duration + self.cfg.procedure_timeout
        log.info("시험 시작: 단말 %d대, 지속 %.1fs", len(self.ues), duration)

        last_report = t0
        while mono() < end_time:
            now = mono()

            # 1) 예정된 단말 등록 개시
            while pending and pending[0][0] <= now:
                _t, ue = pending.pop(0)
                try:
                    self.start_registration(ue, now)
                except SctpError as e:
                    log.error("등록 개시 실패: %s", e)
                    return self.result(failed=str(e))

            # 2) 사용자평면
            if self.hooks is not None:
                self.hooks.on_tick(now)          # phase 전환·만료 처리
            next_tx = self._pump_uplink(now)
            self._pump_downlink(now)

            # 3) 모든 단말이 끝났고 트래픽 시간이 지났으면 종료
            if not pending and now - t0 >= duration:
                break

            # 4) 소켓 대기(다음 송신 시각까지)
            timeout = max(0.0, min(next_tx - mono(), 0.05))
            rlist = [s for s in (self.sctp.sock if self.sctp else None,
                                 self.gtpu.sock if self.gtpu else None) if s]
            if rlist:
                try:
                    ready, _w, _x = select.select(rlist, [], [], timeout)
                except (OSError, ValueError):
                    ready = []
                for s in ready:
                    if self.sctp and s is self.sctp.sock:
                        try:
                            data = self.sctp.recv(timeout=0.0)
                        except SctpError as e:
                            log.error("N2 연결 끊김: %s", e)
                            return self.result(failed=f"N2 연결 끊김: {e}")
                        if data:
                            self.handle_ngap(data, mono())
                    elif self.gtpu and s is self.gtpu.sock:
                        self._pump_downlink(mono())
            else:
                time.sleep(timeout)

            # 5) 주기 보고
            if now - last_report >= 5.0:
                last_report = now
                act = sum(1 for u in self.ues if u.is_active)
                log.info("경과 %.0fs — 활성 %d/%d, UL %s, DL %s",
                         now - t0, act, len(self.ues),
                         human_bps(self.stats.ul_bytes * 8 / max(1e-9, now - t0)),
                         human_bps(self.stats.dl_bytes * 8 / max(1e-9, now - t0)))

        self.stats.end_time = mono()
        return self.result()

    # ═════════════════════════════════════════════════════════════════════
    def result(self, failed: Optional[str] = None) -> Dict[str, Any]:
        """시험 결과 + 정답 manifest."""
        if not self.stats.end_time:
            self.stats.end_time = mono()
        active = [u for u in self.ues if u.is_active]
        registered = [u for u in self.ues if u.state in
                      (UeState.REGISTERED, UeState.SESSION_PENDING, UeState.ACTIVE)]
        failedu = [u for u in self.ues if u.state is UeState.FAILED]
        return {
            "name": self.cfg.name,
            "failed": failed,
            "gnb": {
                "name": self.cfg.gnb.name, "mcc": self.cfg.gnb.mcc,
                "mnc": self.cfg.gnb.mnc, "gnb_id": self.cfg.gnb.gnb_id,
                "tac": self.cfg.gnb.tac, "nr_cell_identity": self.nci,
                "n3_advertise": self._n3_advertise,
                "n3_port": self.gtpu.local_port if self.gtpu else None,
                "ng_setup_ok": self.ng_setup_ok,
            },
            "core": {"kind": self.cfg.core.kind, "amf": self.cfg.core.amf_addr,
                     "amf_port": self.cfg.core.amf_port},
            "summary": {
                "ue_total": len(self.ues),
                "ue_registered": len(registered),
                "ue_active": len(active),
                "ue_failed": len(failedu),
                "failures": sorted({u.failure_reason for u in failedu if u.failure_reason}),
            },
            "stats": self.stats.as_dict(),
            "gtpu": self.gtpu.stats() if self.gtpu else {},
            "ues": [u.manifest_entry() for u in self.ues],
            "events": self.events[-2000:],
            # 시나리오 계층이 있으면 측정·판정을 additive 키로만 싣는다.
            # manifest.compare() 는 이 키를 보지 않으므로 기존 대조 경로는 무영향.
            **({"scenario": self.hooks.result_fragment()}
               if self.hooks is not None else {}),
        }

    def close(self) -> None:
        if self._truth_pcap is not None:
            log.info("정답 캡처 종료: %d패킷 / %.1f MB",
                     self._truth_pcap.count, self._truth_pcap.bytes / 1e6)
            self._truth_pcap.close()
            self._truth_pcap = None
        if self.sctp:
            self.sctp.close()
        if self.gtpu:
            self.gtpu.close()

    def __enter__(self) -> "Gnb":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
