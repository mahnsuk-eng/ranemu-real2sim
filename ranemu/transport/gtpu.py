#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.transport.gtpu — N3(GTP-U, TS 29.281) 사용자평면.

역할
====
gNB 에뮬레이터의 **N3 종단**이다. 단말이 만든 IP 패킷을 GTP-U 로 감싸 UPF 로 보내고,
UPF 가 보낸 GTP-U 를 벗겨 단말에게 돌려준다. 코어 미러(SPAN)에는 이 트래픽이 그대로
보이므로, 기존 dpi_engine 의 처리량/손실 측정이 아무 변경 없이 동작한다.

GTP-U 헤더 (TS 29.281 §5.1)
    비트   8   7   6   5   4   3   2   1
    옥텟1  Version(3) | PT | * | E | S | PN
    옥텟2  Message Type
    옥텟3-4 Length (TEID 이후 바이트 수)
    옥텟5-8 TEID
    [E/S/PN 중 하나라도 1이면] 옥텟9-10 Sequence, 옥텟11 N-PDU, 옥텟12 다음확장헤더타입

메시지 타입: 1=Echo Request, 2=Echo Response, 26=Error Indication,
            254=End Marker, 255=G-PDU(사용자 데이터)

확장헤더 0x85 = PDU Session Container (TS 38.415) — 5G 에서 QFI 를 실어 나른다.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..util import get_logger

log = get_logger("ranemu.gtpu")

GTPU_PORT = 2152

MSG_ECHO_REQUEST = 1
MSG_ECHO_RESPONSE = 2
MSG_ERROR_INDICATION = 26
MSG_SUPPORTED_EXT_HEADERS = 31
MSG_END_MARKER = 254
MSG_GPDU = 255

EXT_NO_MORE = 0x00
EXT_PDU_SESSION_CONTAINER = 0x85

#: PDU Session Container 타입
PSC_TYPE_DL = 0
PSC_TYPE_UL = 1


class GtpuError(ValueError):
    """GTP-U 인코딩/디코딩 오류."""


@dataclass
class GtpuPacket:
    """디코딩된 GTP-U 패킷."""
    message_type: int
    teid: int
    payload: bytes
    sequence: Optional[int] = None
    qfi: Optional[int] = None
    psc_type: Optional[int] = None
    #: 인식하지 못한 확장헤더 (타입, 내용)
    extensions: Tuple[Tuple[int, bytes], ...] = ()

    @property
    def is_gpdu(self) -> bool:
        return self.message_type == MSG_GPDU


def encode(message_type: int, teid: int, payload: bytes = b"",
           sequence: Optional[int] = None, qfi: Optional[int] = None,
           psc_type: int = PSC_TYPE_UL) -> bytes:
    """GTP-U 패킷 인코딩.

    qfi 를 주면 PDU Session Container 확장헤더(0x85)를 붙인다 — 5G 표준 경로.
    """
    ext = b""
    next_ext = EXT_NO_MORE
    if qfi is not None:
        # PDU Session Container: [길이(4옥텟 단위)][내용][다음확장헤더]
        # 내용: 옥텟1 = PDU Type(4비트)|spare(4비트), 옥텟2 = spare(2)|QFI(6)
        body = bytes([((psc_type & 0x0F) << 4), qfi & 0x3F])
        # 전체 확장헤더 길이는 4의 배수여야 한다: [len][body...][next] = 1+2+1 = 4
        ext = bytes([1]) + body + bytes([EXT_NO_MORE])
        next_ext = EXT_PDU_SESSION_CONTAINER

    has_opt = (sequence is not None) or bool(ext)
    flags = 0x30                       # version=1, PT=1(GTP)
    if ext:
        flags |= 0x04                  # E
    if sequence is not None:
        flags |= 0x02                  # S
    opt = b""
    if has_opt:
        opt = struct.pack(">HBB", (sequence or 0) & 0xFFFF, 0, next_ext)
    length = len(opt) + len(ext) + len(payload)
    return struct.pack(">BBHI", flags, message_type & 0xFF, length, teid & 0xFFFFFFFF) \
        + opt + ext + payload


def decode(data: bytes) -> GtpuPacket:
    """GTP-U 패킷 디코딩(확장헤더 체인 포함)."""
    if len(data) < 8:
        raise GtpuError(f"GTP-U 헤더가 너무 짧음: {len(data)}바이트")
    flags, msg_type, length, teid = struct.unpack(">BBHI", data[:8])
    version = (flags >> 5) & 0x07
    if version != 1:
        raise GtpuError(f"지원하지 않는 GTP 버전: {version}")
    off = 8
    seq: Optional[int] = None
    qfi: Optional[int] = None
    psc_type: Optional[int] = None
    exts: list[Tuple[int, bytes]] = []

    if flags & 0x07:                                  # E/S/PN 중 하나라도 설정
        if len(data) < off + 4:
            raise GtpuError("선택 헤더가 잘림")
        seq_val, _npdu, next_ext = struct.unpack(">HBB", data[off:off + 4])
        if flags & 0x02:
            seq = seq_val
        off += 4
        # 확장헤더 체인
        guard = 0
        while next_ext != EXT_NO_MORE and off < len(data):
            guard += 1
            if guard > 16:
                raise GtpuError("확장헤더 체인이 비정상적으로 김")
            ext_len = data[off] * 4                   # 길이는 4옥텟 단위
            if ext_len < 4 or off + ext_len > len(data):
                raise GtpuError(f"확장헤더 길이 이상: {ext_len}")
            body = data[off + 1:off + ext_len - 1]
            this_type, next_ext = next_ext, data[off + ext_len - 1]
            if this_type == EXT_PDU_SESSION_CONTAINER and len(body) >= 2:
                psc_type = (body[0] >> 4) & 0x0F
                qfi = body[1] & 0x3F
            else:
                exts.append((this_type, body))
            off += ext_len

    payload = data[off:8 + 4 + length] if (flags & 0x07) else data[off:8 + length]
    # length 가 실제보다 크면(잘린 캡처) 남은 만큼만
    if not payload:
        payload = data[off:]
    return GtpuPacket(message_type=msg_type, teid=teid, payload=payload,
                      sequence=seq, qfi=qfi, psc_type=psc_type,
                      extensions=tuple(exts))


def echo_request(sequence: int = 0) -> bytes:
    return encode(MSG_ECHO_REQUEST, 0, sequence=sequence)


def echo_response(sequence: int = 0) -> bytes:
    """Echo Response 는 Recovery IE(타입 14, 재시작 카운터)를 포함한다."""
    return encode(MSG_ECHO_RESPONSE, 0, payload=bytes([14, 0]), sequence=sequence)


class GtpuSocket:
    """N3 UDP 소켓 래퍼 — 다중 단말의 TEID 를 하나의 소켓으로 다중화한다."""

    def __init__(self, local_addr: str = "0.0.0.0", local_port: int = GTPU_PORT,
                 rcvbuf: int = 8 << 20, sndbuf: int = 8 << 20):
        self.local_addr = local_addr
        self.local_port = local_port
        self.sock: Optional[socket.socket] = None
        self._rcvbuf = rcvbuf
        self._sndbuf = sndbuf
        self.tx_packets = 0
        self.tx_bytes = 0
        self.rx_packets = 0
        self.rx_bytes = 0

    def open(self) -> Tuple[str, int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        for opt, val in ((socket.SO_RCVBUF, self._rcvbuf), (socket.SO_SNDBUF, self._sndbuf)):
            try:
                s.setsockopt(socket.SOL_SOCKET, opt, val)
            except OSError:
                pass
        try:
            s.bind((self.local_addr, self.local_port))
        except PermissionError as e:
            s.close()
            raise GtpuError(
                f"GTP-U 포트 {self.local_port} 바인드 권한 없음 — 1024 미만 포트는 root 필요. "
                f"gnb.n3_local_port 를 높은 포트로 바꾸거나 권한을 주십시오") from e
        except OSError as e:
            s.close()
            raise GtpuError(f"GTP-U 바인드 실패 {self.local_addr}:{self.local_port} — {e}") from e
        self.sock = s
        self.local_addr, self.local_port = s.getsockname()
        log.info("N3 GTP-U 소켓 열림: %s:%d", self.local_addr, self.local_port)
        return self.local_addr, self.local_port

    def sendto(self, data: bytes, addr: str, port: int = GTPU_PORT) -> int:
        if self.sock is None:
            raise GtpuError("소켓이 열려 있지 않음")
        n = self.sock.sendto(data, (addr, port))
        self.tx_packets += 1
        self.tx_bytes += n
        return n

    def send_gpdu(self, teid: int, payload: bytes, addr: str, port: int = GTPU_PORT,
                  qfi: Optional[int] = None, sequence: Optional[int] = None) -> int:
        return self.sendto(encode(MSG_GPDU, teid, payload, sequence=sequence, qfi=qfi),
                           addr, port)

    def recvfrom(self, timeout: Optional[float] = 0.0, bufsize: int = 65536
                 ) -> Optional[Tuple[GtpuPacket, Tuple[str, int]]]:
        """한 개 수신. timeout=0 이면 논블로킹 폴링."""
        if self.sock is None:
            raise GtpuError("소켓이 열려 있지 않음")
        self.sock.settimeout(timeout)
        try:
            data, peer = self.sock.recvfrom(bufsize)
        except (socket.timeout, BlockingIOError):
            return None
        except OSError as e:
            log.debug("GTP-U 수신 오류(무시): %s", e)
            return None
        self.rx_packets += 1
        self.rx_bytes += len(data)
        try:
            return decode(data), peer
        except GtpuError as e:
            log.debug("GTP-U 디코딩 실패(무시): %s", e)
            return None

    def fileno(self) -> int:
        return self.sock.fileno() if self.sock else -1

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def stats(self) -> Dict[str, Any]:
        return {"tx_packets": self.tx_packets, "tx_bytes": self.tx_bytes,
                "rx_packets": self.rx_packets, "rx_bytes": self.rx_bytes}

    def __enter__(self) -> "GtpuSocket":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ═════════════════════════════════════════════════════════════════════════════
# 단말이 보낼 IP 패킷 생성 (GTP-U 내부 페이로드)
# ═════════════════════════════════════════════════════════════════════════════
def _checksum16(data: bytes) -> int:
    """인터넷 체크섬 (RFC 1071).

    대용량 페이로드에 대해 이 함수를 매 패킷 호출하면 파이썬 루프가 병목이 된다
    (실측: 패킷 생성 시간의 88%). 반복 전송 경로에서는 `Ipv4UdpTemplate` 을 써서
    20바이트 헤더에 대해서만 호출하도록 한다.
    """
    n = len(data)
    if n % 2:
        data = bytes(data) + b"\x00"
        n += 1
    total = 0
    for i in range(0, n, 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4_udp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                   payload: bytes, ttl: int = 64, ident: int = 0) -> bytes:
    """단말 IP 스택 대신 IPv4/UDP 패킷을 직접 만든다(체크섬 포함)."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    udp_len = 8 + len(payload)
    # UDP 체크섬(의사헤더 포함)
    pseudo = src + dst + bytes([0, 17]) + struct.pack(">H", udp_len)
    udp_no_ck = struct.pack(">HHHH", src_port, dst_port, udp_len, 0) + payload
    ck = _checksum16(pseudo + udp_no_ck) or 0xFFFF
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, ck) + payload

    total_len = 20 + udp_len
    ip_no_ck = struct.pack(">BBHHHBBH", 0x45, 0, total_len, ident & 0xFFFF, 0,
                           ttl, 17, 0) + src + dst
    ip_ck = _checksum16(ip_no_ck)
    return struct.pack(">BBHHHBBH", 0x45, 0, total_len, ident & 0xFFFF, 0,
                       ttl, 17, ip_ck) + src + dst + udp


class Ipv4UdpTemplate:
    """동일한 5-튜플/크기의 IPv4-UDP 패킷을 반복 생성하기 위한 캐시.

    왜 필요한가(실측 근거)
    ----------------------
    프로파일링 결과 패킷 생성 시간의 **88%** 가 `_checksum16` 이었다. 1400바이트
    페이로드를 파이썬 루프로 두 번(IP·UDP) 훑기 때문이다. 그런데 한 단말의 연속
    전송에서는 **UDP 체크섬이 전혀 변하지 않는다** — 의사헤더(출발/목적 IP, 프로토콜,
    UDP 길이)와 UDP 헤더·페이로드가 모두 고정이기 때문이다. 매 패킷 바뀌는 것은
    IP identification 뿐이고, 그것은 20바이트 IP 헤더 체크섬에만 영향을 준다.

    따라서 전체 패킷을 한 번 만들어 두고, 전송 시에는 ident 2바이트를 갈아끼운 뒤
    IP 헤더 20바이트에 대해서만 체크섬을 다시 계산한다(1400회 → 10회 루프).
    """

    __slots__ = ("_buf", "_view")

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 payload_len: int, ttl: int = 64):
        self._buf = bytearray(build_ipv4_udp(src_ip, dst_ip, src_port, dst_port,
                                             bytes(max(0, payload_len)), ttl=ttl, ident=0))
        self._view = memoryview(self._buf)

    def __len__(self) -> int:
        return len(self._buf)

    def build(self, ident: int) -> bytes:
        """identification 만 바꾼 완성 패킷(IP 헤더 체크섬 재계산 포함)."""
        b = self._buf
        b[4] = (ident >> 8) & 0xFF
        b[5] = ident & 0xFF
        b[10] = 0
        b[11] = 0
        ck = _checksum16(self._view[:20])
        b[10] = (ck >> 8) & 0xFF
        b[11] = ck & 0xFF
        return bytes(b)

    # ── 페이로드 부분 갱신 ────────────────────────────────────────────────
    def patch_payload(self, offset: int, data: bytes) -> None:
        """페이로드 일부만 바꾸고 UDP 체크섬을 **증분** 갱신한다(RFC 1624).

        왜 증분인가
        -----------
        위 캐시는 "페이로드가 안 변한다" 는 전제로 UDP 체크섬을 고정해 4.1배를 얻는다.
        계측용 스탬프를 넣으면 그 전제가 깨진다. 전체를 다시 계산하면 계측을 넣는 대가로
        처리량이 원래대로 떨어지는데, **계측이 관측 대상을 바꾸면 안 된다.**

        1의 보수 합은 결합적이라 바뀐 16비트 워드만 빼고 더하면 된다:
            HC' = ~(~HC + ~m + m')
        48바이트 스탬프면 24워드만 손보면 되므로 1400바이트를 다시 훑을 이유가 없다.

        길이는 바뀌지 않으므로 IP 헤더(길이·체크섬)는 건드리지 않는다.
        """
        b = self._buf
        start = 20 + 8 + offset                  # IP(20) + UDP(8) + off
        end = start + len(data)
        if offset < 0 or end > len(b):
            raise ValueError(
                f"페이로드 범위를 벗어남: off={offset} len={len(data)} "
                f"payload={len(b) - 28}B")
        if len(data) % 2:
            # 홀수 길이는 워드 경계가 어긋나 증분 갱신이 복잡해진다.
            # 스탬프는 짝수로 설계하면 되는 문제이므로 여기서 막는다.
            raise ValueError("patch_payload 는 짝수 길이만 지원한다")

        ck_off = 20 + 6
        old_ck = (b[ck_off] << 8) | b[ck_off + 1]
        if old_ck == 0:
            # 체크섬 0 = '검사 안 함'(RFC 768). 그대로 두는 것이 규약에 맞다.
            b[start:end] = data
            return

        acc = (~old_ck) & 0xFFFF
        for i in range(0, len(data), 2):
            old_w = (b[start + i] << 8) | b[start + i + 1]
            new_w = (data[i] << 8) | data[i + 1]
            acc += ((~old_w) & 0xFFFF) + new_w
        while acc >> 16:
            acc = (acc & 0xFFFF) + (acc >> 16)
        new_ck = (~acc) & 0xFFFF or 0xFFFF      # 0 은 '검사 안 함' 이므로 피한다

        b[start:end] = data
        b[ck_off] = (new_ck >> 8) & 0xFF
        b[ck_off + 1] = new_ck & 0xFF


def build_ipv4_icmp_echo(src_ip: str, dst_ip: str, ident: int, seq: int,
                         payload: bytes = b"") -> bytes:
    """ICMP Echo Request — RTT 측정용."""
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    icmp_no_ck = struct.pack(">BBHHH", 8, 0, 0, ident & 0xFFFF, seq & 0xFFFF) + payload
    ck = _checksum16(icmp_no_ck)
    icmp = struct.pack(">BBHHH", 8, 0, ck, ident & 0xFFFF, seq & 0xFFFF) + payload
    total_len = 20 + len(icmp)
    ip_no_ck = struct.pack(">BBHHHBBH", 0x45, 0, total_len, seq & 0xFFFF, 0,
                           64, 1, 0) + src + dst
    ip_ck = _checksum16(ip_no_ck)
    return struct.pack(">BBHHHBBH", 0x45, 0, total_len, seq & 0xFFFF, 0,
                       64, 1, ip_ck) + src + dst + icmp


def parse_ipv4(data: bytes) -> Dict[str, Any]:
    """수신 IP 패킷에서 진단에 필요한 최소 정보만 추출."""
    if len(data) < 20 or (data[0] >> 4) != 4:
        return {}
    ihl = (data[0] & 0x0F) * 4
    proto = data[9]
    out: Dict[str, Any] = {
        "src": socket.inet_ntoa(data[12:16]),
        "dst": socket.inet_ntoa(data[16:20]),
        "proto": proto,
        "total_length": struct.unpack(">H", data[2:4])[0],
        "payload_offset": ihl,
    }
    if proto == 17 and len(data) >= ihl + 8:
        sp, dp, ln, _ck = struct.unpack(">HHHH", data[ihl:ihl + 8])
        out.update({"src_port": sp, "dst_port": dp, "udp_length": ln,
                    "payload": data[ihl + 8:ihl + ln]})
    elif proto == 1 and len(data) >= ihl + 8:
        t, c, _ck, ident, seq = struct.unpack(">BBHHH", data[ihl:ihl + 8])
        out.update({"icmp_type": t, "icmp_code": c, "icmp_id": ident, "icmp_seq": seq,
                    "payload": data[ihl + 8:]})
    return out


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    ok = True

    # (1) G-PDU 기본 왕복
    payload = bytes(range(100))
    pkt = encode(MSG_GPDU, 0x11223344, payload)
    d = decode(pkt)
    if not (d.is_gpdu and d.teid == 0x11223344 and d.payload == payload):
        ok = False
        print(f"  [GTPU] G-PDU 왕복 실패: {d}")
    elif verbose:
        print("  [GTPU] G-PDU 왕복 OK")
    # 헤더 8바이트 + 페이로드
    if len(pkt) != 8 + len(payload):
        ok = False
        print(f"  [GTPU] 기본 헤더 길이 이상: {len(pkt)}")

    # (2) 길이 필드 정확성
    flags, mt, ln, teid = struct.unpack(">BBHI", pkt[:8])
    if ln != len(payload) or flags != 0x30 or mt != MSG_GPDU:
        ok = False
        print(f"  [GTPU] 헤더 필드 이상: flags={flags:02x} len={ln}")

    # (3) QFI 확장헤더(PDU Session Container)
    pkt2 = encode(MSG_GPDU, 7, payload, qfi=5, psc_type=PSC_TYPE_UL)
    d2 = decode(pkt2)
    if not (d2.qfi == 5 and d2.psc_type == PSC_TYPE_UL and d2.payload == payload):
        ok = False
        print(f"  [GTPU] QFI 확장헤더 왕복 실패: qfi={d2.qfi} psc={d2.psc_type}")
    elif verbose:
        print("  [GTPU] PDU Session Container(QFI=5) 왕복 OK")
    if not (struct.unpack(">BBHI", pkt2[:8])[0] & 0x04):
        ok = False
        print("  [GTPU] E 플래그가 설정되지 않음")

    # (4) 시퀀스 번호
    pkt3 = encode(MSG_GPDU, 7, payload, sequence=0xBEEF)
    d3 = decode(pkt3)
    if d3.sequence != 0xBEEF or d3.payload != payload:
        ok = False
        print(f"  [GTPU] 시퀀스 왕복 실패: {d3.sequence}")

    # (5) 시퀀스 + QFI 동시
    pkt4 = encode(MSG_GPDU, 9, payload, sequence=1, qfi=1)
    d4 = decode(pkt4)
    if not (d4.sequence == 1 and d4.qfi == 1 and d4.payload == payload):
        ok = False
        print(f"  [GTPU] 시퀀스+QFI 동시 왕복 실패: {d4}")
    elif verbose:
        print("  [GTPU] 시퀀스+QFI 동시 왕복 OK")

    # (6) Echo
    er = decode(echo_request(3))
    if er.message_type != MSG_ECHO_REQUEST or er.sequence != 3:
        ok = False
        print("  [GTPU] Echo Request 왕복 실패")
    ep = decode(echo_response(3))
    if ep.message_type != MSG_ECHO_RESPONSE or ep.payload[:1] != bytes([14]):
        ok = False
        print("  [GTPU] Echo Response(Recovery IE) 실패")
    elif verbose:
        print("  [GTPU] Echo Request/Response OK")

    # (7) 잘못된 버전 거부
    bad = bytearray(pkt); bad[0] = 0x00
    try:
        decode(bytes(bad))
        ok = False
        print("  [GTPU] 잘못된 GTP 버전을 통과시킴")
    except GtpuError:
        pass

    # (8) IPv4/UDP 생성 → 파싱 왕복 + 체크섬 검증
    ip = build_ipv4_udp("10.45.0.7", "8.8.8.8", 12345, 33434, b"HELLO")
    info = parse_ipv4(ip)
    if not (info.get("src") == "10.45.0.7" and info.get("dst") == "8.8.8.8"
            and info.get("src_port") == 12345 and info.get("payload") == b"HELLO"):
        ok = False
        print(f"  [GTPU] IPv4/UDP 왕복 실패: {info}")
    elif verbose:
        print("  [GTPU] IPv4/UDP 생성→파싱 OK")
    if _checksum16(ip[:20]) != 0:
        ok = False
        print("  [GTPU] IPv4 헤더 체크섬 오류")
    # UDP 체크섬 검증(의사헤더 포함 합이 0 이어야)
    pseudo = ip[12:20] + bytes([0, 17]) + ip[24:26]
    if _checksum16(pseudo + ip[20:]) != 0:
        ok = False
        print("  [GTPU] UDP 체크섬 오류")
    elif verbose:
        print("  [GTPU] IPv4/UDP 체크섬 검증 OK")

    # (9) ICMP Echo
    icmp = build_ipv4_icmp_echo("10.45.0.7", "8.8.8.8", 0x1234, 1, b"x" * 32)
    ii = parse_ipv4(icmp)
    if not (ii.get("proto") == 1 and ii.get("icmp_type") == 8 and ii.get("icmp_id") == 0x1234):
        ok = False
        print(f"  [GTPU] ICMP 생성/파싱 실패: {ii}")

    # (9b) 템플릿 캐시가 기준 구현과 **바이트 단위로 동일**해야 한다.
    #      (성능 최적화가 패킷을 조용히 망가뜨리면 코어측 측정이 통째로 무의미해진다)
    tmpl = Ipv4UdpTemplate("10.45.0.7", "8.8.8.8", 40000, 33434, payload_len=1372)
    for ident in (0, 1, 255, 256, 0xFFFF, 12345):
        got = tmpl.build(ident)
        ref = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434, bytes(1372),
                             ident=ident)
        if got != ref:
            ok = False
            print(f"  [GTPU] 템플릿(ident={ident})이 기준 구현과 불일치")
            break
        if _checksum16(got[:20]) != 0:
            ok = False
            print(f"  [GTPU] 템플릿(ident={ident}) IP 체크섬 무효")
            break
        pseudo = got[12:20] + bytes([0, 17]) + got[24:26]
        if _checksum16(pseudo + got[20:]) != 0:
            ok = False
            print(f"  [GTPU] 템플릿(ident={ident}) UDP 체크섬 무효")
            break
    else:
        # (부가) patch_payload 의 증분 체크섬이 전체 재계산과 같은가.
        # 계측 스탬프가 이 경로로 들어가므로 한 비트라도 틀리면 코어가 패킷을 버린다.
        for off, blob in ((0, bytes(range(48))), (16, b"\xde\xad\xbe\xef"),
                          (1372 - 8, b"\x01\x02\x03\x04\x05\x06\x07\x08")):
            t2 = Ipv4UdpTemplate("10.45.0.7", "8.8.8.8", 40000, 33434,
                                 payload_len=1372)
            t2.patch_payload(off, blob)
            patched = t2.build(7)
            pay = bytearray(bytes(1372))
            pay[off:off + len(blob)] = blob
            ref2 = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434,
                                  bytes(pay), ident=7)
            if patched != ref2:
                ok = False
                print(f"  [GTPU] patch_payload(off={off}) 가 기준 구현과 불일치")
                break
            pseudo2 = patched[12:20] + bytes([0, 17]) + patched[24:26]
            if _checksum16(pseudo2 + patched[20:]) != 0:
                ok = False
                print(f"  [GTPU] patch_payload(off={off}) UDP 체크섬 무효")
                break
        else:
            if verbose:
                print("  [GTPU] patch_payload 증분 체크섬 = 전체 재계산 OK")
        if verbose:
            print("  [GTPU] 패킷 템플릿 = 기준 구현(6개 ident) + 체크섬 유효 OK")

    # (10) 실제 UDP 소켓 왕복
    a = GtpuSocket(local_addr="127.0.0.1", local_port=0)
    b = GtpuSocket(local_addr="127.0.0.1", local_port=0)
    try:
        a.open(); b.open()
        a.send_gpdu(0xCAFE, b"PAYLOAD", "127.0.0.1", b.local_port, qfi=1)
        got = b.recvfrom(timeout=2.0)
        if not got or got[0].teid != 0xCAFE or got[0].payload != b"PAYLOAD" or got[0].qfi != 1:
            ok = False
            print(f"  [GTPU] 소켓 왕복 실패: {got}")
        elif verbose:
            print("  [GTPU] UDP 소켓 왕복(TEID/QFI 보존) OK")
        if a.tx_packets != 1 or b.rx_packets != 1:
            ok = False
            print("  [GTPU] 통계 카운터 오류")
    except GtpuError as e:
        ok = False
        print(f"  [GTPU] 소켓 시험 실패: {e}")
    finally:
        a.close(); b.close()

    # (11) tshark 가 있으면 GTP-U 인코딩을 독립 검증
    import shutil
    if shutil.which("tshark"):
        ok = _verify_with_tshark(verbose) and ok
    return ok


def _verify_with_tshark(verbose: bool) -> bool:
    """생성한 GTP-U 패킷을 tshark 로 파싱해 TEID/QFI 를 대조."""
    import subprocess
    import tempfile
    import warnings
    warnings.filterwarnings("ignore")
    try:
        from scapy.all import Ether, IP, UDP, Raw, wrpcap   # type: ignore
    except ImportError:
        return True

    inner = build_ipv4_udp("10.45.0.7", "8.8.8.8", 4000, 33434, b"A" * 64)
    gtp = encode(MSG_GPDU, 0x00A1B2C3, inner, qfi=9)
    with tempfile.TemporaryDirectory(prefix="ranemu-gtpu-") as td:
        path = os.path.join(td, "g.pcap")
        wrpcap(path, [Ether() / IP(src="10.1.16.52", dst="10.1.16.60") /
                      UDP(sport=GTPU_PORT, dport=GTPU_PORT) / Raw(load=gtp)])
        out = subprocess.run(
            ["tshark", "-r", path, "-T", "fields", "-E", "separator=|",
             "-E", "occurrence=a", "-E", "aggregator=,",
             "-e", "gtp.teid", "-e", "gtp.ext_hdr.pdu_ses_con.qos_flow_id",
             "-e", "ip.src", "-e", "ip.dst"],
            capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            print(f"  [GTPU] tshark 실행 실패: {out.stderr.strip()[:200]}")
            return False
    line = out.stdout.strip()
    parts = line.split("|") if line else []
    ok = True
    if len(parts) < 2:
        print(f"  [GTPU] tshark 파싱 결과 없음: {line!r}")
        return False
    if parts[0] not in ("0xa1b2c3", "0x00a1b2c3", "10597059"):
        ok = False
        print(f"  [GTPU] tshark TEID 불일치: {parts[0]!r}")
    if parts[1] not in ("9",):
        ok = False
        print(f"  [GTPU] tshark QFI 불일치: {parts[1]!r}")
    # 내부 IP 까지 벗겨서 보이는지(= 캡슐화가 올바름)
    if len(parts) >= 4 and "10.45.0.7" not in parts[2]:
        ok = False
        print(f"  [GTPU] tshark 가 내부 IP 를 복원하지 못함: {parts[2:]}")
    elif verbose and ok:
        print(f"  [GTPU] tshark 대조 OK (TEID={parts[0]}, QFI={parts[1]}, "
              f"inner={parts[2] if len(parts) > 2 else '?'})")
    return ok


if __name__ == "__main__":
    print("GTPU selftest:", "PASS" if selftest(verbose=True) else "FAIL")
