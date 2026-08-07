#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.core.stub — 오프라인 검증용 최소 코어(AMF + SMF + UPF).

왜 필요한가
===========
실 5G 코어에 붙이기 전에, 에뮬레이터의 **전 경로**(NGAP → NAS → 5G-AKA → PDU 세션 →
GTP-U 사용자평면)가 스스로 동작함을 증명해야 한다. 스텁 코어는 그 기준선이다.
실제 코어 연동에서 문제가 생겼을 때 "우리 쪽인가 코어 쪽인가" 를 가르는 기준도 된다.

주의: 이것은 **시험용 최소 구현**이지 코어 제품이 아니다. 가입자 DB 는 설정의
K/OPc 하나를 모든 IMSI 에 쓰고, 정책·과금·이동성은 없다.

절차
====
    gNB                                  스텁 코어
     │ NGSetupRequest ───────────────────►│
     │◄─────────────────── NGSetupResponse│
     │ InitialUEMessage(RegistrationReq) ►│  SUCI→IMSI, 인증벡터 생성
     │◄──── DL NAS(AuthenticationRequest) │
     │ UL NAS(AuthenticationResponse) ───►│  RES* == XRES* 검증
     │◄──── DL NAS(SecurityModeCommand)   │  NEA2/NIA2 선택
     │ UL NAS(SecurityModeComplete) ─────►│  MAC 검증
     │◄──── DL NAS(RegistrationAccept)    │  5G-GUTI 배정
     │ UL NAS(RegistrationComplete) ─────►│
     │ UL NAS(PDUSessionEstablishmentReq)►│  UE IP/TEID 배정
     │◄── PDUSessionResourceSetupRequest  │  (세션수립 수락 NAS 동봉)
     │ PDUSessionResourceSetupResponse ──►│  gNB TEID 기록 → UPF 터널 개통
     │ ═══════════ GTP-U 사용자평면 ══════►│  (loopback 이면 되돌림)
"""
from __future__ import annotations

import os
import random
import select
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..crypto import (
    DIRECTION_DL, DIRECTION_UL, Milenage, k_amf, k_ausf, k_seaf, nas_keys, xres_star,
)
from ..nas import nas5gs as nas
from ..ngap import messages as ngap
from ..transport.gtpu import (
    GtpuSocket, MSG_ECHO_REQUEST, MSG_GPDU, decode as gtpu_decode, echo_response,
    parse_ipv4,
)
from ..transport.sctp import SctpClient, SctpServer
from ..util import get_logger, plmn_encode, serving_network_name

log = get_logger("ranemu.stub")


def _ip_to_int(a: str) -> int:
    o = [int(x) for x in a.split(".")]
    if len(o) != 4 or any(not 0 <= x <= 255 for x in o):
        raise ValueError(f"IPv4 주소가 아님: {a}")
    return (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]


def _int_to_ip(n: int) -> str:
    if not 0 <= n <= 0xFFFFFFFF:
        raise ValueError(f"IPv4 범위를 벗어남: {n}")
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


@dataclass
class StubSubscriber:
    """스텁 코어가 보는 가입자 상태."""
    imsi: str
    ran_ue_ngap_id: int
    amf_ue_ngap_id: int
    rand: bytes = b""
    xres_star: bytes = b""
    k_amf: Optional[bytes] = None
    k_nas_enc: bytes = b""
    k_nas_int: bytes = b""
    enc_alg: int = 0
    int_alg: int = 0
    security_active: bool = False
    ul_count: int = 0
    dl_count: int = 0
    ue_ip: Optional[str] = None
    ul_teid: Optional[int] = None       # UPF 측(단말→코어)
    gnb_teid: Optional[int] = None      # gNB 측(코어→단말)
    gnb_addr: Optional[str] = None
    pdu_session_id: int = 1
    registered: bool = False
    session_up: bool = False


class StubCore:
    """AMF + SMF + UPF 를 한 프로세스에서 흉내내는 최소 코어."""

    def __init__(self, *, key: bytes, opc: bytes, amf_field: bytes = b"\x80\x00",
                 mcc: str = "450", mnc: str = "05",
                 amf_addr: str = "127.0.0.1", amf_port: int = 0,
                 upf_addr: str = "127.0.0.1", upf_port: int = 0,
                 ue_ip_base: str = "10.45.0.", downlink_mode: str = "loopback",
                 enc_alg: int = 2, int_alg: int = 2, seed: int = 42):
        self.key, self.opc, self.amf_field = key, opc, amf_field
        self.mcc, self.mnc = mcc, mnc
        self.plmn = plmn_encode(mcc, mnc)
        self.snn = serving_network_name(mcc, mnc)
        self.amf_addr, self.amf_port = amf_addr, amf_port
        self.upf_addr, self.upf_port = upf_addr, upf_port
        self.ue_ip_base = ue_ip_base
        self.downlink_mode = downlink_mode
        self.enc_alg, self.int_alg = enc_alg, int_alg
        self.rng = random.Random(seed)

        self.server: Optional[SctpServer] = None
        self.conn: Optional[SctpClient] = None
        self.upf: Optional[GtpuSocket] = None
        self.subs: Dict[int, StubSubscriber] = {}     # ran_ue_ngap_id → 가입자
        self.by_ul_teid: Dict[int, StubSubscriber] = {}
        self._next_amf_id = 1
        self._next_teid = 0x00010000
        # UE IP 는 마지막 옥텟만 늘리면 246번째 단말에서 10.45.0.256 이 되어
        # 세션 수립이 조용히 실패한다(실제로 500대 시나리오에서 그렇게 됐다).
        # 32비트 정수로 더해 /16 이상을 자연스럽게 넘어가도록 한다.
        self._ip_base = _ip_to_int(ue_ip_base.rstrip(".") + ".0")
        self._next_ip = 10
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = {"ngap_recv": 0, "ngap_sent": 0, "ul_packets": 0, "ul_bytes": 0,
                      "dl_packets": 0, "dl_bytes": 0, "registrations": 0, "sessions": 0}
        self.errors: List[str] = []

    # ── 개통/종료 ─────────────────────────────────────────────────────────
    def start(self) -> Tuple[str, int, str, int]:
        """SCTP/UPF 소켓을 열고 백그라운드 스레드에서 동작. → (amf주소,포트,upf주소,포트)"""
        self.server = SctpServer(addr=self.amf_addr, port=self.amf_port)
        self.amf_addr, self.amf_port = self.server.listen()
        self.upf = GtpuSocket(local_addr=self.upf_addr, local_port=self.upf_port)
        self.upf_addr, self.upf_port = self.upf.open()
        log.info("스텁 코어 기동: AMF %s:%d, UPF %s:%d (하향모드=%s)",
                 self.amf_addr, self.amf_port, self.upf_addr, self.upf_port,
                 self.downlink_mode)
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="ranemu-stub-core")
        self._thread.start()
        return self.amf_addr, self.amf_port, self.upf_addr, self.upf_port

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        if self.conn:
            self.conn.close()
        if self.server:
            self.server.close()
        if self.upf:
            self.upf.close()

    def __enter__(self) -> "StubCore":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ── 메인 루프 ─────────────────────────────────────────────────────────
    def _loop(self) -> None:
        while not self._stop.is_set() and self.conn is None:
            try:
                self.conn = self.server.accept(timeout=0.5)
            except OSError as e:
                self.errors.append(f"accept 실패: {e}")
                return
        while not self._stop.is_set():
            socks = [s for s in (self.conn.sock if self.conn else None,
                                 self.upf.sock if self.upf else None) if s]
            if not socks:
                break
            try:
                ready, _w, _x = select.select(socks, [], [], 0.05)
            except (OSError, ValueError):
                break
            for s in ready:
                if self.conn and s is self.conn.sock:
                    try:
                        data = self.conn.recv(timeout=0.0)
                    except OSError:
                        return
                    if data:
                        try:
                            self._on_ngap(data)
                        except Exception as e:  # noqa: BLE001
                            self.errors.append(f"NGAP 처리 예외: {e}")
                            log.exception("스텁 코어 NGAP 처리 실패")
                elif self.upf and s is self.upf.sock:
                    self._on_gtpu()

    def _send(self, pdu: bytes, what: str) -> None:
        if self.conn is None:
            return
        self.conn.send(pdu)
        self.stats["ngap_sent"] += 1
        log.debug("스텁→gNB %s (%dB)", what, len(pdu))

    # ── NGAP 처리 ─────────────────────────────────────────────────────────
    def _on_ngap(self, data: bytes) -> None:
        self.stats["ngap_recv"] += 1
        pdu = ngap.parse_pdu(data)
        log.debug("gNB→스텁 %s/%s", pdu.type_name, pdu.name)
        proc = pdu.procedure_code

        if proc == ngap.PROC_NG_SETUP:
            self._send(ngap.ng_setup_response(plmn=self.plmn), "NGSetupResponse")
            return

        common = ngap.extract_common(pdu)
        ran_id = common.get("ran_ue_ngap_id")

        if proc == ngap.PROC_INITIAL_UE_MESSAGE and ran_id is not None:
            sub = StubSubscriber(imsi="", ran_ue_ngap_id=ran_id,
                                 amf_ue_ngap_id=self._alloc_amf_id())
            self.subs[ran_id] = sub
            self._on_uplink_nas(sub, common.get("nas_pdu"))
            return

        sub = self.subs.get(ran_id) if ran_id is not None else None
        if sub is None:
            return

        if proc == ngap.PROC_UPLINK_NAS_TRANSPORT:
            self._on_uplink_nas(sub, common.get("nas_pdu"))
        elif proc == ngap.PROC_PDU_SESSION_RESOURCE_SETUP and \
                pdu.pdu_type == ngap.PDU_SUCCESSFUL:
            self._on_setup_response(sub, pdu)
        elif proc == ngap.PROC_INITIAL_CONTEXT_SETUP and \
                pdu.pdu_type == ngap.PDU_SUCCESSFUL:
            self._on_setup_response(sub, pdu)

    def _alloc_amf_id(self) -> int:
        v = self._next_amf_id
        self._next_amf_id += 1
        return v

    def _dl_nas(self, sub: StubSubscriber, plain: bytes, *, protect: bool = True,
                new_context: bool = False) -> None:
        """DL NAS Transport 로 NAS 를 내려보낸다."""
        payload = plain
        if protect and sub.security_active:
            sht = (nas.SHT_INTEGRITY_CIPHERED_NEW_CTX if new_context
                   else nas.SHT_INTEGRITY_CIPHERED)
            payload = nas.encode_secured(
                plain, security_header_type=sht, enc_alg=sub.enc_alg,
                int_alg=sub.int_alg, k_nas_enc=sub.k_nas_enc, k_nas_int=sub.k_nas_int,
                count=sub.dl_count, direction=DIRECTION_DL)
            sub.dl_count += 1
        self._send(ngap.downlink_nas_transport(
            amf_ue_ngap_id=sub.amf_ue_ngap_id, ran_ue_ngap_id=sub.ran_ue_ngap_id,
            nas_pdu=payload), "DownlinkNASTransport")

    def _on_uplink_nas(self, sub: StubSubscriber, nas_pdu: Optional[bytes]) -> None:
        if not nas_pdu:
            return
        try:
            if nas.is_security_protected(nas_pdu):
                msg, info = nas.decode_secured(
                    nas_pdu, enc_alg=sub.enc_alg, int_alg=sub.int_alg,
                    k_nas_enc=sub.k_nas_enc, k_nas_int=sub.k_nas_int,
                    count=sub.ul_count, direction=DIRECTION_UL,
                    verify_mac=sub.security_active)
                if sub.security_active and not info["mac_ok"]:
                    self.errors.append(f"{sub.imsi}: 상향 NAS MAC 불일치")
                sub.ul_count = info["count"] + 1
            else:
                msg = nas.decode(nas_pdu)
        except nas.NasDecodeError as e:
            self.errors.append(f"NAS 디코딩 실패: {e}")
            return

        mt = msg.message_type
        if mt == nas.MT_REGISTRATION_REQUEST:
            self._on_registration_request(sub, msg)
        elif mt == nas.MT_AUTHENTICATION_RESPONSE:
            self._on_authentication_response(sub, msg)
        elif mt == nas.MT_SECURITY_MODE_COMPLETE:
            self._on_security_mode_complete(sub, msg)
        elif mt == nas.MT_REGISTRATION_COMPLETE:
            sub.registered = True
            self.stats["registrations"] += 1
            log.info("스텁 코어: %s 등록 완료", sub.imsi)
        elif mt == nas.MT_UL_NAS_TRANSPORT:
            self._on_ul_nas_transport(sub, msg)
        elif mt == nas.MT_AUTHENTICATION_FAILURE:
            self.errors.append(f"{sub.imsi}: 단말이 인증 실패를 보고")

    def _on_registration_request(self, sub: StubSubscriber, msg: nas.NasMessage) -> None:
        ident = msg.fields.get("identity") or {}
        sub.imsi = ident.get("imsi") or ""
        if not sub.imsi:
            self.errors.append("등록요청에서 IMSI 를 얻지 못함")
            return
        # 인증벡터 생성 (5G-AKA)
        m = Milenage(self.key, self.opc)
        rand = bytes(self.rng.getrandbits(8) for _ in range(16))
        sqn = bytes.fromhex("000000000020")
        autn = m.autn(rand, sqn, self.amf_field)
        vec = m.f2345(rand)
        sub.rand = rand
        sub.xres_star = xres_star(vec.ck, vec.ik, self.snn, rand, vec.res)
        kausf = k_ausf(vec.ck, vec.ik, self.snn, autn[0:6])
        sub.k_amf = k_amf(k_seaf(kausf, self.snn), sub.imsi, b"\x00\x00")

        req = bytearray([nas.EPD_5GMM, 0x00, nas.MT_AUTHENTICATION_REQUEST,
                         0x00, 0x02, 0x00, 0x00])      # ngKSI=0, ABBA=0000
        req += bytes([0x21]) + rand
        req += bytes([0x20, 0x10]) + autn
        self._dl_nas(sub, bytes(req), protect=False)
        log.debug("스텁 코어: %s 인증요청 송신", sub.imsi)

    def _on_authentication_response(self, sub: StubSubscriber,
                                    msg: nas.NasMessage) -> None:
        got = msg.fields.get("res_star")
        if got != sub.xres_star:
            self.errors.append(f"{sub.imsi}: RES* 불일치(인증 실패)")
            self._dl_nas(sub, bytes([nas.EPD_5GMM, 0x00, nas.MT_AUTHENTICATION_REJECT]),
                         protect=False)
            return
        # 보안 모드 명령
        sub.enc_alg, sub.int_alg = self.enc_alg, self.int_alg
        sub.k_nas_enc, sub.k_nas_int = nas_keys(sub.k_amf, sub.enc_alg, sub.int_alg)
        replayed = nas.enc_ue_security_capability([0, 2], [0, 2])
        smc = bytearray([nas.EPD_5GMM, 0x00, nas.MT_SECURITY_MODE_COMMAND])
        smc.append((sub.enc_alg << 4) | sub.int_alg)
        smc.append(0x00)                              # ngKSI = 0
        smc.append(len(replayed)); smc += replayed
        # SMC 자체는 새 컨텍스트로 무결성 보호(암호화 없음)
        protected = nas.encode_secured(
            bytes(smc), security_header_type=nas.SHT_INTEGRITY_NEW_CTX,
            enc_alg=sub.enc_alg, int_alg=sub.int_alg, k_nas_enc=sub.k_nas_enc,
            k_nas_int=sub.k_nas_int, count=0, direction=DIRECTION_DL)
        sub.security_active = True
        sub.dl_count = 1
        sub.ul_count = 0
        self._send(ngap.downlink_nas_transport(
            amf_ue_ngap_id=sub.amf_ue_ngap_id, ran_ue_ngap_id=sub.ran_ue_ngap_id,
            nas_pdu=protected), "DownlinkNASTransport(SecurityModeCommand)")

    def _on_security_mode_complete(self, sub: StubSubscriber,
                                   msg: nas.NasMessage) -> None:
        if not msg.fields.get("nas_message_container"):
            self.errors.append(f"{sub.imsi}: SecurityModeComplete 에 등록요청 없음")
        # 등록 수락
        guti = nas.enc_5g_guti(self.mcc, self.mnc, 2, 1, 0,
                               self.rng.getrandbits(32))
        ra = bytearray([nas.EPD_5GMM, 0x00, nas.MT_REGISTRATION_ACCEPT, 0x01, 0x01])
        ra += bytes([0x77]) + len(guti).to_bytes(2, "big") + guti
        ra += bytes([0x15, 0x02, 0x01, 0x01])          # Allowed NSSAI: SST=1
        self._dl_nas(sub, bytes(ra))

    def _on_ul_nas_transport(self, sub: StubSubscriber, msg: nas.NasMessage) -> None:
        payload = msg.fields.get("payload") or b""
        if not payload:
            return
        try:
            sm = nas.decode(payload)
        except nas.NasDecodeError as e:
            self.errors.append(f"5GSM 디코딩 실패: {e}")
            return
        if sm.message_type != nas.MT_PDU_SESSION_EST_REQUEST:
            return

        psi = sm.fields.get("pdu_session_id", 1)
        sub.pdu_session_id = psi
        sub.ue_ip = _int_to_ip(self._ip_base + self._next_ip)
        self._next_ip += 1
        sub.ul_teid = self._next_teid
        self._next_teid += 1
        self.by_ul_teid[sub.ul_teid] = sub

        # PDU Session Establishment Accept (UE IP 포함)
        acc = bytearray([nas.EPD_5GSM, psi, sm.fields.get("pti", 1),
                         nas.MT_PDU_SESSION_EST_ACCEPT])
        acc.append((1 << 4) | nas.PDU_TYPE_IPV4)
        qos = bytes([0x01, 0x20, 0x01, 0x00])
        acc += len(qos).to_bytes(2, "big") + qos
        ambr = nas.enc_session_ambr(1_000_000_000, 200_000_000)
        acc += bytes([len(ambr)]) + ambr
        octets = [int(x) for x in sub.ue_ip.split(".")]
        acc += bytes([0x29, 0x05, nas.PDU_TYPE_IPV4]) + bytes(octets)
        acc += bytes([0x25, len(nas.enc_dnn("internet"))]) + nas.enc_dnn("internet")

        # 보안 보호된 DL NAS 를 PDU 세션 자원설정 요청 안에 실어 보낸다
        protected = nas.encode_secured(
            bytes([nas.EPD_5GMM, 0x00, nas.MT_DL_NAS_TRANSPORT, 0x01])
            + len(acc).to_bytes(2, "big") + bytes(acc) + bytes([0x12, psi]),
            security_header_type=nas.SHT_INTEGRITY_CIPHERED,
            enc_alg=sub.enc_alg, int_alg=sub.int_alg, k_nas_enc=sub.k_nas_enc,
            k_nas_int=sub.k_nas_int, count=sub.dl_count, direction=DIRECTION_DL)
        sub.dl_count += 1

        transfer = ngap.enc_pdu_session_resource_setup_request_transfer(
            self.upf_addr, sub.ul_teid, qfis=[1])
        self._send(ngap.pdu_session_resource_setup_request(
            amf_ue_ngap_id=sub.amf_ue_ngap_id, ran_ue_ngap_id=sub.ran_ue_ngap_id,
            pdu_session_id=psi, nas_pdu=protected, transfer=transfer),
            "PDUSessionResourceSetupRequest")
        log.info("스텁 코어: %s 세션 배정 ip=%s ul_teid=0x%08x",
                 sub.imsi, sub.ue_ip, sub.ul_teid)

    def _on_setup_response(self, sub: StubSubscriber, pdu: ngap.NgapPdu) -> None:
        """gNB 가 알려준 N3 종단(주소/TEID)을 기록 → 하향 경로 개통."""
        raw = (pdu.ies.get(ngap.IE_PDU_SESSION_RESOURCE_SETUP_LIST_SU_RES)
               or pdu.ies.get(ngap.IE_PDU_SESSION_RESOURCE_SETUP_LIST_CXT_RES))
        if not raw:
            return
        from ..ngap.aper import AperError, BitReader
        try:
            r = BitReader(raw)
            count = r.sequence_of_count(1, ngap.MAX_PDU_SESSIONS)
            for _ in range(count):
                r.sequence_preamble(True, 1)
                _psi = r.constrained_int(0, 255)
                transfer = r.octet_string()
                info = self._find_tunnel_in_transfer(transfer)
                if info:
                    sub.gnb_addr = info["addr"]
                    sub.gnb_teid = info["teid"]
                    sub.session_up = True
                    self.stats["sessions"] += 1
                    log.info("스텁 코어: %s 하향터널 확보 %s TEID=0x%08x",
                             sub.imsi, sub.gnb_addr, sub.gnb_teid)
        except AperError as e:
            self.errors.append(f"SetupResponse 파싱 실패: {e}")

    @staticmethod
    def _find_tunnel_in_transfer(transfer: bytes) -> Optional[Dict[str, Any]]:
        """PDUSessionResourceSetupResponseTransfer 에서 GTPTunnel 을 찾는다."""
        from ..ngap.aper import AperError, BitReader
        try:
            r = BitReader(transfer)
            r.sequence_preamble(True, 4)      # ResponseTransfer
            r.sequence_preamble(True, 1)      # QosFlowPerTNLInformation
            r.choice_index(1)                 # UPTransportLayerInformation
            r.sequence_preamble(True, 1)      # GTPTunnel
            val, nbits = r.bit_string(1, 160, extensible=True)
            if nbits % 8:
                return None
            import ipaddress
            addr = str(ipaddress.ip_address(val.to_bytes(nbits // 8, "big")))
            teid = int.from_bytes(r.octet_string(4, 4), "big")
            return {"addr": addr, "teid": teid}
        except (AperError, ValueError):
            return None

    # ── UPF (사용자평면) ──────────────────────────────────────────────────
    def _on_gtpu(self) -> None:
        for _ in range(256):
            got = self.upf.recvfrom(timeout=0.0)
            if got is None:
                return
            pkt, peer = got
            if pkt.message_type == MSG_ECHO_REQUEST:
                try:
                    self.upf.sendto(echo_response(pkt.sequence or 0), peer[0], peer[1])
                except OSError:
                    pass
                continue
            if pkt.message_type != MSG_GPDU:
                continue
            sub = self.by_ul_teid.get(pkt.teid)
            if sub is None:
                continue
            self.stats["ul_packets"] += 1
            self.stats["ul_bytes"] += len(pkt.payload)

            # loopback 모드: N6 너머 서버 대신 코어가 즉시 되돌려 준다
            if (self.downlink_mode == "loopback" and sub.gnb_teid is not None
                    and sub.gnb_addr):
                inner = self._reflect(pkt.payload)
                try:
                    self.upf.send_gpdu(sub.gnb_teid, inner, sub.gnb_addr,
                                       peer[1], qfi=pkt.qfi or 1)
                    self.stats["dl_packets"] += 1
                    self.stats["dl_bytes"] += len(inner)
                except OSError:
                    pass

    def _reflect(self, ip_packet: bytes) -> bytes:
        """되돌릴 패킷을 만든다. 계측 스탬프가 있으면 t2/t3 를 기입한다.

        스텁 코어는 gnb 와 **같은 프로세스**에서 돌므로 CLOCK_MONOTONIC 의 epoch 가
        같다. 따라서 여기서 찍은 t2/t3 는 gnb 의 t1/t4 와 직접 비교 가능하고,
        오프라인에서도 편도지연(one-way delay) 경로를 검증할 수 있다. 실 배치에서는
        같은 역할을 N6 너머의 reflector 가 자기 클럭으로 수행한다.
        """
        out = self._swap_ip(ip_packet)
        try:
            from ..scenario import stamp as _st
        except Exception:                        # noqa: BLE001
            return out                           # 시나리오 계층 없이도 동작해야 한다
        if len(out) < 28 or (out[0] >> 4) != 4:
            return out
        off = (out[0] & 0x0F) * 4 + 8            # IP 헤더(IHL*4) + UDP 헤더
        if len(out) - off < _st.STAMP_LEN or out[off:off + 4] != _st.MAGIC:
            return out

        buf = bytearray(out)
        old = bytes(buf[off:off + _st.STAMP_LEN])
        now = time.monotonic_ns()
        # 스텁은 즉시 되돌리므로 t2 와 t3 는 사실상 같다. 그래도 둘 다 남겨
        # rtt_net = (t4−t1) − (t3−t2) 식이 실 reflector 와 동일하게 성립하게 한다.
        _st.fill_t2t3(buf, now, time.monotonic_ns(),
                      clock_domain=_st.CLOCK_SHARED, off=off)
        # 페이로드를 바꿨으니 UDP 체크섬을 증분 갱신한다(48 B = 24 워드).
        # IP 주소 교환은 의사헤더 합의 순서만 바꾸므로 체크섬에 영향이 없다.
        ck_off = (out[0] & 0x0F) * 4 + 6
        old_ck = (buf[ck_off] << 8) | buf[ck_off + 1]
        if old_ck:
            new = bytes(buf[off:off + _st.STAMP_LEN])
            ow = [(old[i] << 8) | old[i + 1] for i in range(0, len(old), 2)]
            nw = [(new[i] << 8) | new[i + 1] for i in range(0, len(new), 2)]
            ck = _st._ones_complement_fixup(old_ck, ow, nw) or 0xFFFF
            buf[ck_off] = (ck >> 8) & 0xFF
            buf[ck_off + 1] = ck & 0xFF
        return bytes(buf)

    @staticmethod
    def _swap_ip(ip_packet: bytes) -> bytes:
        """출발지/목적지 IP 를 바꿔 되돌려 보낸다(헤더 체크섬 재계산)."""
        if len(ip_packet) < 20 or (ip_packet[0] >> 4) != 4:
            return ip_packet
        b = bytearray(ip_packet)
        b[12:16], b[16:20] = ip_packet[16:20], ip_packet[12:16]
        b[10:12] = b"\x00\x00"
        from ..transport.gtpu import _checksum16
        ihl = (b[0] & 0x0F) * 4
        ck = _checksum16(bytes(b[:ihl]))
        b[10:12] = struct.pack(">H", ck)
        return bytes(b)

    def summary(self) -> Dict[str, Any]:
        return {
            "stats": dict(self.stats),
            "errors": list(self.errors),
            "subscribers": [
                {"imsi": s.imsi, "ue_ip": s.ue_ip, "registered": s.registered,
                 "session_up": s.session_up, "ul_teid": s.ul_teid,
                 "gnb_teid": s.gnb_teid, "gnb_addr": s.gnb_addr}
                for s in self.subs.values()
            ],
        }


def selftest(verbose: bool = False) -> bool:
    """스텁 코어의 주소 할당 — 500대 시나리오에서 조용히 깨졌던 자리."""
    ok = True
    base = _ip_to_int("10.45.0.0")
    seen = set()
    for n in range(10, 10 + 1000):        # 1,000 세션: 옥텟 경계를 네 번 넘는다
        a = _int_to_ip(base + n)
        octs = [int(x) for x in a.split(".")]
        if len(octs) != 4 or any(not 0 <= o <= 255 for o in octs):
            ok = False
            print(f"  [STUB] 유효하지 않은 UE IP: {a} (n={n})")
            break
        try:
            bytes(octs)                   # NAS 인코딩이 하는 그대로
        except ValueError:
            ok = False
            print(f"  [STUB] NAS 로 인코딩 불가한 UE IP: {a}")
            break
        seen.add(a)
    if ok and len(seen) != 1000:
        ok = False
        print(f"  [STUB] UE IP 중복 — 고유 {len(seen)}/1000")
    for bad in ("10.45.0", "10.45.0.256", "300.1.1.1"):
        try:
            _ip_to_int(bad)
        except ValueError:
            continue
        ok = False
        print(f"  [STUB] 잘못된 주소를 통과시킴: {bad}")
    if ok and verbose:
        print("  [STUB] UE IP 1,000개 할당 — 옥텟 경계 통과, 중복 없음")
    return ok
