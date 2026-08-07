#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.reflector — T2 reflector (설계 §3.3): N6 너머에 우리가 띄우는 UDP 상대.

왜 reflector 가 필요한가
========================
N6 너머 peer 는 5GS 밖의 application server 다 — peer 를 두는 것은 SUT(코어 배치)를
건드리는 것이 아니다. dumb echo(T1)로는 rtt_wire 밖에 못 얻는다:
- **t2/t3 기입** → 회신자 처리시간을 뺀 rtt_net (RFC 8762 STAMP 와 같은 트릭 —
  t3−t2 는 회신자 단일 클럭 차라서 동기화가 필요 없다).
- **stream 프로파일** → DL-heavy 트래픽(XR 영상, 모델 다운로드)을 N6 에서 합법적으로
  생성. echo 는 DL 크기=UL 크기라 DL 처리량/지연의 대표성이 없다(§3.3). DL 은 자체
  seq 공간(DL_SEQ_BIT)이라 DL 손실이 실측되고, DL 패킷이 트리거의 t1 을 그대로
  운반하므로 frame_delay = t4(마지막) − t1(트리거)가 gNB 단일 클럭 실측이 된다.

일반 UDP 소켓(SOCK_DGRAM)을 쓰므로 체크섬은 커널이 다시 계산한다 — 증분 체크섬은
GTP-U 안에서 직접 패치하는 쪽(gnb/stub)의 일이다.
"""
from __future__ import annotations

import argparse
import math
import socket
import struct
import threading
import time
from typing import Dict, Optional, Tuple

from .stamp import (CLOCK_PTP, CLOCK_SHARED, CLOCK_UNSYNC, DL_SEQ_BIT,
                    FLAG_BURST_END, FLAG_FRAME_TRIGGER, FLAG_REPLY_REQ,
                    STAMP_LEN, Stamp, fill_t2t3, pack_stamp, unpack_stamp)

PROFILES = ("echo", "ack", "stream")
_CLOCK_BY_NAME = {"unsync": CLOCK_UNSYNC, "shared": CLOCK_SHARED, "ptp": CLOCK_PTP}


class Reflector:
    """flow 별 response profile 을 수행하는 스레드형 UDP reflector.

    profile:
      - echo   : 동일 크기 반사 (대칭 트래픽)
      - ack    : 요청 크기와 무관하게 48 B 응답 (UL-heavy 서비스의 현실적 DL)
      - stream : 트리거 패킷 1개당 frame_bytes 를 frame_pkts 개로 쪼갠 DL 버스트
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0, *,
                 profile: str = "echo", frame_bytes: int = 62500,
                 frame_pkts: Optional[int] = None, mtu_payload: int = 1400,
                 clock_domain: str = "shared"):
        if profile not in PROFILES:
            raise ValueError(f"profile 은 {PROFILES} 중 하나: {profile!r}")
        self.profile = profile
        self.frame_bytes = frame_bytes
        self.mtu_payload = max(STAMP_LEN, mtu_payload)
        self.frame_pkts = frame_pkts or max(1, math.ceil(frame_bytes
                                                         / self.mtu_payload))
        #: 회신자가 스탬프에 기입하는 자기 클럭 도메인 **주장** — 검증은 runner 몫.
        self.clock_domain = _CLOCK_BY_NAME[clock_domain]
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, port))
        self._sock.settimeout(0.2)
        self.addr: Tuple[str, int] = self._sock.getsockname()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._dl_seq: Dict[int, int] = {}       # flow_id → DL seq 카운터
        # 통계 (selftest/운영 진단)
        self.received = 0
        self.replied = 0
        self.unstamped = 0
        self.silent = 0                          # reply-req 미설정 → 무회신
        self.bursts_sent = 0
        self.dl_packets_sent = 0

    # ── 수명주기 ─────────────────────────────────────────────────────────
    def start(self) -> "Reflector":
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name=f"reflector-{self.addr[1]}")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2.0)
        self._sock.close()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            # t2 는 수신 직후 — 처리시간이 t3−t2 에 들어가야 rtt_net 이 정직하다.
            t2 = time.monotonic_ns()
            self._handle(data, addr, t2)

    # ── 처리 ─────────────────────────────────────────────────────────────
    def _handle(self, data: bytes, addr: Tuple[str, int], t2: int) -> None:
        self.received += 1
        st = unpack_stamp(data)
        if st is None:
            self.unstamped += 1
            if self.profile == "echo":
                # 무스탬프도 에코는 해 준다(T1 하위호환) — 계측은 안 되지만
                # 트래픽 경로 자체를 죽이지는 않는다.
                self._sock.sendto(data, addr)
                self.replied += 1
            return
        if not (st.flags & FLAG_REPLY_REQ):
            self.silent += 1                     # 회신 요청 없음 = T0 흉내
            return

        if self.profile == "stream" and (st.flags & FLAG_FRAME_TRIGGER):
            self._send_burst(st, addr, t2)
            return

        if self.profile == "ack" or self.profile == "stream":
            buf = bytearray(data[:STAMP_LEN])    # 48 B 응답
        else:                                    # echo: 동일 크기
            buf = bytearray(data)
        fill_t2t3(buf, t2, time.monotonic_ns(), self.clock_domain)
        self._sock.sendto(bytes(buf), addr)
        self.replied += 1

    def _send_burst(self, trig: Stamp, addr: Tuple[str, int], t2: int) -> None:
        """트리거 1개 → DL 버스트. 각 DL 패킷은 트리거의 t1/phase 를 승계한다.

        t1 승계가 핵심이다: gNB 는 DL 패킷의 t4 와 스탬프 안의 t1 을 **자기 클럭**
        으로 비교하므로 frame_delay 가 동기화 없이 실측된다(§3.1 표의 frame_delay).
        """
        per_pkt = max(STAMP_LEN,
                      math.ceil(self.frame_bytes / self.frame_pkts))
        burst_id = trig.burst_id if trig.burst_id else (trig.seq & 0xFFFFFFFF)
        base_seq = self._dl_seq.get(trig.flow_id, 0)
        for i in range(self.frame_pkts):
            flags = 0                        # T2T3_VALID 은 fill_t2t3 가 세팅
            if i == self.frame_pkts - 1:
                flags |= FLAG_BURST_END
            payload = bytearray(pack_stamp(
                trig.flow_id, DL_SEQ_BIT | ((base_seq + i) & 0x7FFFFFFF),
                trig.t1_ns, phase_id=trig.phase_id, flags=flags,
                gen_delta_us=trig.gen_delta_us, burst_id=burst_id,
                burst_index=i))
            if per_pkt > STAMP_LEN:
                payload += bytes(per_pkt - STAMP_LEN)
            fill_t2t3(payload, t2, time.monotonic_ns(), self.clock_domain)
            self._sock.sendto(bytes(payload), addr)
            self.dl_packets_sent += 1
        self._dl_seq[trig.flow_id] = base_seq + self.frame_pkts
        self.bursts_sent += 1

    def stats(self) -> Dict[str, int]:
        return {"received": self.received, "replied": self.replied,
                "unstamped": self.unstamped, "silent": self.silent,
                "bursts_sent": self.bursts_sent,
                "dl_packets_sent": self.dl_packets_sent}


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    from .stamp import BurstLedger

    ok = True

    def client() -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        return s

    # 1) echo: 동일 크기 + t2/t3 유효 + 단일 호스트 OWD/rtt_net 정합성
    r_echo = Reflector(profile="echo", clock_domain="shared").start()
    try:
        c = client()
        t1 = time.monotonic_ns()
        req = pack_stamp(1, 100, t1, flags=FLAG_REPLY_REQ) + bytes(152)
        c.sendto(req, r_echo.addr)
        data, _ = c.recvfrom(65535)
        t4 = time.monotonic_ns()
        st = unpack_stamp(data)
        if len(data) != len(req):
            ok = False
            print(f"  [RF] echo 크기 불일치: {len(data)} vs {len(req)}")
        if st is None or not st.t2t3_valid or st.reflector_clock != CLOCK_SHARED:
            ok = False
            print(f"  [RF] echo t2/t3 미기입: {st}")
        else:
            rtt_wire = t4 - t1
            turn = st.turn_ns()
            rtt_net = rtt_wire - turn
            # 같은 호스트 = 같은 부트의 monotonic → t2−t1(OWD)도 참 실측이어야 한다
            if not (st.t2_ns >= t1 and st.t3_ns >= st.t2_ns and t4 >= st.t3_ns):
                ok = False
                print(f"  [RF] 단일클럭 순서 위반: t1={t1} t2={st.t2_ns} "
                      f"t3={st.t3_ns} t4={t4}")
            if not (0 <= turn <= rtt_wire and 0 <= rtt_net <= rtt_wire):
                ok = False
                print(f"  [RF] rtt_net 분해 오류: wire={rtt_wire} turn={turn}")
            elif verbose:
                print(f"  [RF] echo: rtt_wire={rtt_wire/1e3:.1f}us "
                      f"turn={turn/1e3:.1f}us rtt_net={rtt_net/1e3:.1f}us OK")
        # 무스탬프 → 에코되고 unstamped 로 계수
        c.sendto(b"not-a-stamp-payload", r_echo.addr)
        data2, _ = c.recvfrom(65535)
        if data2 != b"not-a-stamp-payload" or r_echo.unstamped != 1:
            ok = False
            print("  [RF] 무스탬프 에코 처리 오류")
        # reply-req 미설정 → 침묵
        c.sendto(pack_stamp(1, 101, time.monotonic_ns(), flags=0), r_echo.addr)
        try:
            c.settimeout(0.4)
            c.recvfrom(65535)
            ok = False
            print("  [RF] reply-req 없는 패킷에 회신함")
        except socket.timeout:
            pass
        if r_echo.silent != 1:
            ok = False
            print(f"  [RF] silent 계수 오류: {r_echo.silent}")
        c.close()
    finally:
        r_echo.stop()

    # 2) ack: 500 B 요청 → 48 B 응답 (UL-heavy 서비스의 현실적 DL)
    r_ack = Reflector(profile="ack", clock_domain="shared").start()
    try:
        c = client()
        c.sendto(pack_stamp(2, 7, time.monotonic_ns(), flags=FLAG_REPLY_REQ)
                 + bytes(452), r_ack.addr)
        data, _ = c.recvfrom(65535)
        st = unpack_stamp(data)
        if len(data) != STAMP_LEN or st is None or not st.t2t3_valid \
                or st.seq != 7:
            ok = False
            print(f"  [RF] ack 응답 오류: len={len(data)} {st}")
        elif verbose:
            print("  [RF] ack: 500 B 요청 → 48 B 응답 OK")
        c.close()
    finally:
        r_ack.stop()

    # 3) stream: 트리거 1개 → 3-패킷 버스트, t1 승계, BurstLedger 로 프레임 판정
    r_str = Reflector(profile="stream", frame_bytes=3000,
                      mtu_payload=1400, clock_domain="shared").start()
    try:
        if r_str.frame_pkts != 3:
            ok = False
            print(f"  [RF] frame_pkts 계산 오류: {r_str.frame_pkts}")
        c = client()
        trig_t1 = time.monotonic_ns()
        c.sendto(pack_stamp(3, 55, trig_t1,
                            flags=FLAG_REPLY_REQ | FLAG_FRAME_TRIGGER,
                            burst_id=9), r_str.addr)
        bl = BurstLedger(pdb_ms=100.0)
        got, total_bytes = [], 0
        for _ in range(3):
            data, _ = c.recvfrom(65535)
            t4 = time.monotonic_ns()
            st = unpack_stamp(data)
            got.append(st)
            total_bytes += len(data)
            bl.on_dl_packet(st, t4, len(data))
        idxs = sorted(s.burst_index for s in got)
        if idxs != [0, 1, 2]:
            ok = False
            print(f"  [RF] burst_index 오류: {idxs}")
        for s in got:
            if not s.is_dl or s.burst_id != 9 or s.t1_ns != trig_t1 \
                    or not s.t2t3_valid:
                ok = False
                print(f"  [RF] DL 스탬프 필드 오류: {s}")
        ends = [s for s in got if s.flags & FLAG_BURST_END]
        if len(ends) != 1 or ends[0].burst_index != 2:
            ok = False
            print(f"  [RF] BURST_END 오류: {[(s.burst_index, s.flags) for s in got]}")
        if total_bytes < 3000:
            ok = False
            print(f"  [RF] 버스트 총량 미달: {total_bytes} < 3000")
        if bl.n_frames != 1 or bl.k_frames_ok != 1:
            ok = False
            print(f"  [RF] BurstLedger 프레임 판정 실패: {bl.as_dict()}")
        elif verbose:
            fd = bl.delay_hist.vmax
            print(f"  [RF] stream: 3000 B → 3 pkt 버스트, frame_delay="
                  f"{fd:.3f}ms (t1 승계 단일클럭 실측) OK")
        # 비트리거 패킷은 48 B ack — UL 전달률 계측 유지
        c.sendto(pack_stamp(3, 56, time.monotonic_ns(), flags=FLAG_REPLY_REQ),
                 r_str.addr)
        data, _ = c.recvfrom(65535)
        if len(data) != STAMP_LEN:
            ok = False
            print(f"  [RF] stream 비트리거 ack 오류: {len(data)}")
        # DL seq 는 흐름별 단조 증가 (다음 버스트는 3부터)
        c.sendto(pack_stamp(3, 57, time.monotonic_ns(),
                            flags=FLAG_REPLY_REQ | FLAG_FRAME_TRIGGER,
                            burst_id=10), r_str.addr)
        seqs = []
        for _ in range(3):
            data, _ = c.recvfrom(65535)
            seqs.append(unpack_stamp(data).seq & 0x7FFFFFFF)
        if sorted(seqs) != [3, 4, 5]:
            ok = False
            print(f"  [RF] DL seq 연속성 오류: {seqs}")
        # 카운터는 send 후에 증가한다 — 클라이언트가 마지막 패킷을 받은 시점에
        # 핸들러 스레드가 아직 += 를 실행 전일 수 있으므로(GIL 스케줄링) 잠깐 대기.
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            stats = r_str.stats()
            if stats["bursts_sent"] == 2 and stats["dl_packets_sent"] == 6:
                break
            time.sleep(0.01)
        if stats["bursts_sent"] != 2 or stats["dl_packets_sent"] != 6:
            ok = False
            print(f"  [RF] 통계 오류: {stats}")
        c.close()
    finally:
        r_str.stop()

    return ok


def main() -> int:
    ap = argparse.ArgumentParser(
        description="ranemu T2 reflector — N6 도달 가능한 호스트에서 실행")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=9462)
    ap.add_argument("--profile", choices=PROFILES, default="echo")
    ap.add_argument("--frame-bytes", type=int, default=62500,
                    help="stream: 버스트 총 바이트 (기본 62.5 kB = 30 Mbps@60fps)")
    ap.add_argument("--frame-pkts", type=int, default=None)
    ap.add_argument("--clock", choices=sorted(_CLOCK_BY_NAME), default="unsync",
                    help="이 호스트가 주장하는 클럭 도메인 — gNB 와 같은 호스트일 "
                         "때만 shared 를 선언할 것")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    if args.selftest:
        okr = selftest(verbose=True)
        print("REFLECTOR selftest:", "PASS" if okr else "FAIL")
        return 0 if okr else 1
    r = Reflector(args.host, args.port, profile=args.profile,
                  frame_bytes=args.frame_bytes, frame_pkts=args.frame_pkts,
                  clock_domain=args.clock).start()
    print(f"reflector: {r.addr[0]}:{r.addr[1]} profile={args.profile} "
          f"clock={args.clock} — Ctrl-C 로 종료")
    try:
        while True:
            time.sleep(5)
            print(f"  {r.stats()}")
    except KeyboardInterrupt:
        r.stop()
        print(f"최종: {r.stats()}")
    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        sys.exit(main())
    print("REFLECTOR selftest:", "PASS" if selftest(verbose=True) else "FAIL")
