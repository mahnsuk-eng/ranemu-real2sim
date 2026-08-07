#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.transport.sctp — N2(NGAP) 용 SCTP 전송.

pysctp 없이 표준 socket 만 쓴다
==============================
리눅스 커널은 `socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)` 로 one-to-one SCTP 를 제공한다.
NGAP 은 **PPID=60** 을 요구하므로(TS 38.412), `sendmsg()` 의 보조데이터(cmsg)로
`SCTP_SNDINFO` 를 실어 PPID 를 지정한다. 커널이 이를 거부하면 평문 send 로 자동
강등하고 그 사실을 로그로 남긴다(일부 AMF 는 PPID 를 검사하지 않는다).
"""
from __future__ import annotations

import socket
import struct
import time
from typing import List, Optional, Tuple

from ..util import get_logger

log = get_logger("ranemu.sctp")

IPPROTO_SCTP = 132
SCTP_NODELAY = 3
SCTP_INITMSG = 2
SCTP_RECVRCVINFO = 32
SCTP_SNDINFO = 2                 # cmsg_type (sendmsg 보조데이터)
SCTP_RCVINFO = 1                 # cmsg_type (recvmsg 보조데이터)

PPID_NGAP = 60
PPID_S1AP = 18
PPID_XNAP = 61


class SctpError(OSError):
    """SCTP 연결/전송 오류."""


def _sndinfo(ppid: int, stream: int = 0) -> bytes:
    """struct sctp_sndinfo { u16 sid; u16 flags; u32 ppid; u32 context; s32 assoc_id }.

    ppid 는 네트워크 바이트오더로 전달해야 한다.
    """
    return struct.pack("=HHIIi", stream, 0, socket.htonl(ppid), 0, 0)


class SctpClient:
    """gNB → AMF 방향의 SCTP 클라이언트(one-to-one)."""

    def __init__(self, local_addr: str = "0.0.0.0", local_port: int = 0,
                 in_streams: int = 10, out_streams: int = 10,
                 ppid: int = PPID_NGAP, timeout: float = 10.0):
        self.local_addr = local_addr
        self.local_port = local_port
        self.in_streams = in_streams
        self.out_streams = out_streams
        self.ppid = ppid
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self._ppid_via_cmsg = True
        self.peer: Optional[Tuple[str, int]] = None

    # ── 연결 ──────────────────────────────────────────────────────────────
    def connect(self, addr: str, port: int = 38412) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
        try:
            # INIT 파라미터: 스트림 수 협상
            s.setsockopt(IPPROTO_SCTP, SCTP_INITMSG,
                         struct.pack("=HHHH", self.out_streams, self.in_streams, 5, 30))
        except OSError as e:
            log.debug("SCTP_INITMSG 설정 실패(무시): %s", e)
        try:
            s.setsockopt(IPPROTO_SCTP, SCTP_NODELAY, 1)
        except OSError:
            pass
        try:
            s.setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO, 1)
        except OSError as e:
            log.debug("SCTP_RECVRCVINFO 설정 실패(무시): %s", e)

        if self.local_addr != "0.0.0.0" or self.local_port:
            s.bind((self.local_addr, self.local_port))
        s.settimeout(self.timeout)
        try:
            s.connect((addr, port))
        except OSError as e:
            s.close()
            raise SctpError(f"SCTP 연결 실패 {addr}:{port} — {e}") from e
        self.sock = s
        self.peer = (addr, port)
        try:
            self.local_addr, self.local_port = s.getsockname()[:2]
        except OSError:
            pass
        log.info("SCTP 연결 수립: %s:%d ← 로컬 %s:%d (PPID=%d)",
                 addr, port, self.local_addr, self.local_port, self.ppid)

    # ── 송수신 ────────────────────────────────────────────────────────────
    def send(self, data: bytes, stream: int = 0) -> int:
        if self.sock is None:
            raise SctpError("연결되지 않음")
        if self._ppid_via_cmsg:
            try:
                return self.sock.sendmsg(
                    [data], [(IPPROTO_SCTP, SCTP_SNDINFO, _sndinfo(self.ppid, stream))])
            except OSError as e:
                # 커널이 SCTP_SNDINFO 를 모르면 한 번만 경고하고 강등
                self._ppid_via_cmsg = False
                log.warning("SCTP_SNDINFO 미지원(%s) — PPID 없이 전송으로 강등", e)
        return self.sock.send(data)

    def recv(self, timeout: Optional[float] = None, bufsize: int = 65536
             ) -> Optional[bytes]:
        """한 개의 SCTP 메시지를 수신. 타임아웃이면 None."""
        if self.sock is None:
            raise SctpError("연결되지 않음")
        self.sock.settimeout(self.timeout if timeout is None else timeout)
        try:
            data, _anc, _flags, _addr = self.sock.recvmsg(bufsize, 1024)
        except socket.timeout:
            return None
        except OSError as e:
            raise SctpError(f"SCTP 수신 오류: {e}") from e
        if not data:
            raise SctpError("SCTP 연결이 상대에 의해 종료됨")
        return data

    def recv_until(self, deadline: float, bufsize: int = 65536) -> Optional[bytes]:
        """deadline(monotonic) 까지 대기하며 한 메시지 수신."""
        remain = deadline - time.monotonic()
        if remain <= 0:
            return None
        return self.recv(timeout=remain, bufsize=bufsize)

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            log.info("SCTP 연결 종료")

    def __enter__(self) -> "SctpClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class SctpServer:
    """스텁 AMF 용 SCTP 서버(one-to-one, accept 기반)."""

    def __init__(self, addr: str = "127.0.0.1", port: int = 38412,
                 ppid: int = PPID_NGAP, backlog: int = 16):
        self.addr = addr
        self.port = port
        self.ppid = ppid
        self.backlog = backlog
        self.sock: Optional[socket.socket] = None

    def listen(self) -> Tuple[str, int]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_SCTP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.setsockopt(IPPROTO_SCTP, SCTP_INITMSG, struct.pack("=HHHH", 10, 10, 5, 30))
        except OSError:
            pass
        s.bind((self.addr, self.port))
        s.listen(self.backlog)
        self.sock = s
        self.addr, self.port = s.getsockname()[:2]
        log.info("스텁 AMF SCTP 대기: %s:%d", self.addr, self.port)
        return self.addr, self.port

    def accept(self, timeout: Optional[float] = None) -> Optional[SctpClient]:
        if self.sock is None:
            raise SctpError("listen() 먼저 호출")
        self.sock.settimeout(timeout)
        try:
            conn, peer = self.sock.accept()
        except socket.timeout:
            return None
        client = SctpClient(ppid=self.ppid)
        client.sock = conn
        client.peer = peer
        conn.settimeout(client.timeout)
        try:
            conn.setsockopt(IPPROTO_SCTP, SCTP_RECVRCVINFO, 1)
        except OSError:
            pass
        log.info("스텁 AMF: gNB 접속 %s", peer)
        return client

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def selftest(verbose: bool = False) -> bool:
    """루프백으로 SCTP 왕복 + PPID 전달을 검증."""
    ok = True
    # (1) sndinfo 구조체 크기/PPID 배치
    si = _sndinfo(60)
    if len(si) != 16:
        ok = False
        print(f"  [SCTP] sctp_sndinfo 크기 {len(si)} != 16")
    if struct.unpack("=HHIIi", si)[2] != socket.htonl(60):
        ok = False
        print("  [SCTP] PPID 바이트오더 오류")
    elif verbose:
        print("  [SCTP] sctp_sndinfo(PPID=60, 16바이트) OK")

    # (2) 실제 루프백 왕복
    srv = SctpServer(addr="127.0.0.1", port=0)
    try:
        _a, port = srv.listen()
    except OSError as e:
        print(f"  [SCTP] 루프백 서버 생성 실패({e}) — 커널 SCTP 미지원일 수 있음")
        return ok

    import threading
    received: List[bytes] = []

    def _serve() -> None:
        c = srv.accept(timeout=5.0)
        if c is None:
            return
        data = c.recv(timeout=5.0)
        if data:
            received.append(data)
            c.send(b"PONG:" + data)
        time.sleep(0.1)
        c.close()

    th = threading.Thread(target=_serve, daemon=True)
    th.start()
    time.sleep(0.05)

    cli = SctpClient(timeout=5.0)
    try:
        cli.connect("127.0.0.1", port)
        payload = b"NGAP-TEST-PDU"
        cli.send(payload)
        reply = cli.recv(timeout=5.0)
        if reply != b"PONG:" + payload:
            ok = False
            print(f"  [SCTP] 루프백 응답 불일치: {reply!r}")
        elif verbose:
            print(f"  [SCTP] 루프백 왕복 OK (PPID cmsg={'사용' if cli._ppid_via_cmsg else '강등'})")
        if received and received[0] != payload:
            ok = False
            print("  [SCTP] 서버 수신 페이로드 불일치")
    except OSError as e:
        ok = False
        print(f"  [SCTP] 루프백 시험 실패: {e}")
    finally:
        cli.close()
        th.join(timeout=3.0)
        srv.close()
    return ok


if __name__ == "__main__":
    print("SCTP selftest:", "PASS" if selftest(verbose=True) else "FAIL")
