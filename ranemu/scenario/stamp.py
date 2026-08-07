#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.stamp — 48 B in-band STAMP 코덱 + 흐름 원장(ledger) + 검열 규칙.

probe.py(20 B 시제품)의 후속이자 유일한 스탬프 포맷이다. 20 B 판에서 검증된 두 축 —
RFC 1624 증분 UDP 체크섬(전체 재계산과 바이트 동일, 10.3배 빠름)과 미회신 추적 원장 —
을 유지하면서, 설계 §3.6 의 t1/t2/t3/burst/phase 필드를 싣는다.

왜 48 B 인가
============
RFC 8762(STAMP)와 같은 트릭을 쓰려면 회신자가 자기 클럭으로 t2(수신)/t3(송신)를
패킷 안에 기입해야 한다. t3−t2 는 **회신자 단일 클럭의 차**이므로 클럭 동기 없이도
유효하고, 이를 빼면 rtt_net = (t4−t1) − (t3−t2) 를 얻는다. 여기에 phase 귀속
(phase_id), XR 프레임 판정(burst_id/burst_index), access_hold(gen_delta_us)까지
실으면 8바이트 정렬로 정확히 48 B 다. `Ipv4UdpTemplate.patch_payload` 가 짝수 길이를
요구하므로 48(짝수)은 그 제약도 만족한다.

원장이 지키는 두 가지 정직성 규칙 (§3.7)
========================================
1. **PDB 성공 판정은 히스토그램 bin 이 아니라 해소 시점의 원값 비교**로 한다.
   히스토그램(log-등간 600 bins)은 분위수 추정용이고 상대 분해능이 ~2.33% 라서,
   bin 상단값으로 성공/실패를 정하면 신뢰도에 계통 오차가 생긴다. 원값 비교는
   binning 오차가 0 이다.
2. **우측 검열**: phase 말미 T_resolve 이내에 송신된 패킷은 성공/실패 어느 쪽으로도
   세지 않는다(censored). 회신될 기회가 공평하지 않았던 표본을 분모에 넣으면
   신뢰도가 체계적으로 낮게(또는 미회신을 빼면 높게) 왜곡된다.
"""
from __future__ import annotations

import math
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# 48 B 스탬프 레이아웃 (설계 §3.6 그대로)
#
#   off len  field
#   0   4    magic  "RSTP"
#   4   2    flow_id
#   6   1    phase_id
#   7   1    flags
#   8   4    seq            (DL stream 은 상위비트 DL_SEQ_BIT 로 별도 공간)
#   12  8    t1_ns
#   20  4    gen_delta_us   (t1 − t_gen; access_hold 산출용, modelled 표기 대상)
#   24  8    t2_ns          (reflector ingress; 요청 시 0)
#   32  8    t3_ns          (reflector egress; 요청 시 0)
#   40  4    burst_id
#   44  1    burst_index
#   45  3    reserved
# ─────────────────────────────────────────────────────────────────────────────
MAGIC = b"RSTP"
STAMP_FMT = ">4sHBBIQIQQIB3s"
STAMP_LEN = struct.calcsize(STAMP_FMT)
assert STAMP_LEN == 48 and STAMP_LEN % 2 == 0   # patch_payload 는 짝수 길이 요구

FLAG_REPLY_REQ = 0x01       # 회신 요청 (없으면 reflector 는 침묵 — T0 흉내)
FLAG_FRAME_TRIGGER = 0x02   # stream 프로파일의 DL 버스트 트리거
FLAG_T2T3_VALID = 0x04      # t2/t3 가 회신자에 의해 기입됨
FLAG_BURST_END = 0x08       # DL 버스트의 마지막 패킷 (burst_index+1 = 버스트 크기)

# flags bit4-6: 회신자가 기입하는 자기 클럭 도메인 주장
CLOCK_UNSYNC, CLOCK_SHARED, CLOCK_PTP = 0, 1, 2

#: DL stream 시퀀스 공간 구분 비트 — UL seq 와 충돌하지 않게 상위비트를 쓴다.
DL_SEQ_BIT = 0x80000000

_OFF_FLAGS = 7
_OFF_T2 = 24
_OFF_T3 = 32

IP_HDR = 20
UDP_HDR = 8
MIN_PAYLOAD = STAMP_LEN
#: 스탬프를 담을 수 있는 최소 **IP 패킷** 크기(IP+UDP+스탬프).
#: 이보다 작은 서비스 메시지는 계측할 수 없으므로 팽창하거나 포기해야 한다.
MIN_PACKET = IP_HDR + UDP_HDR + STAMP_LEN


@dataclass
class Stamp:
    """디코딩된 48 B 스탬프."""
    flow_id: int
    phase_id: int
    flags: int
    seq: int
    t1_ns: int
    gen_delta_us: int
    t2_ns: int
    t3_ns: int
    burst_id: int
    burst_index: int

    @property
    def t2t3_valid(self) -> bool:
        return bool(self.flags & FLAG_T2T3_VALID)

    @property
    def reflector_clock(self) -> int:
        return (self.flags >> 4) & 0x7

    @property
    def is_dl(self) -> bool:
        return bool(self.seq & DL_SEQ_BIT)

    def turn_ns(self) -> int:
        """회신자 처리시간 t3−t2 — 단일 클럭 차이므로 동기화 없이 유효."""
        return self.t3_ns - self.t2_ns if self.t2t3_valid else 0


def pack_stamp(flow_id: int, seq: int, t1_ns: int, *, phase_id: int = 0,
               flags: int = FLAG_REPLY_REQ, gen_delta_us: int = 0,
               t2_ns: int = 0, t3_ns: int = 0, burst_id: int = 0,
               burst_index: int = 0) -> bytes:
    return struct.pack(STAMP_FMT, MAGIC, flow_id & 0xFFFF, phase_id & 0xFF,
                       flags & 0xFF, seq & 0xFFFFFFFF, t1_ns & ((1 << 64) - 1),
                       gen_delta_us & 0xFFFFFFFF, t2_ns & ((1 << 64) - 1),
                       t3_ns & ((1 << 64) - 1), burst_id & 0xFFFFFFFF,
                       burst_index & 0xFF, b"\x00\x00\x00")


def unpack_stamp(payload: bytes) -> Optional[Stamp]:
    """UDP 페이로드 선두에서 스탬프를 읽는다. 스탬프가 아니면 None."""
    if len(payload) < STAMP_LEN:
        return None
    (magic, flow, phase, flags, seq, t1, gen_d,
     t2, t3, burst, bidx, _rsv) = struct.unpack(STAMP_FMT, payload[:STAMP_LEN])
    if magic != MAGIC:
        return None
    return Stamp(flow, phase, flags, seq, t1, gen_d, t2, t3, burst, bidx)


def decode_from_inner_ip(inner: bytes) -> Optional[Stamp]:
    """**inner IPv4 datagram 전체**에서 스탬프를 디코딩한다.

    gnb._pump_downlink 의 훅은 GTP-U 를 벗긴 inner IP 패킷 전체를 넘긴다.
    오프셋 0 에서 읽으면 IP 헤더를 읽게 되어 magic 이 절대 맞지 않고, 모든
    패킷이 '무스탬프' 로 침묵 소실된다(실측으로 확인된 함정). IHL 은 옵션이
    붙으면 20 이 아니므로 하드코딩 28 이 아니라 실제 IHL 로 건너뛴다.
    """
    if len(inner) < IP_HDR + UDP_HDR or (inner[0] >> 4) != 4:
        return None
    if inner[9] != 17:                       # UDP 가 아니면 스탬프일 수 없다
        return None
    off = (inner[0] & 0x0F) * 4 + UDP_HDR
    return unpack_stamp(inner[off:])


def fill_t2t3(buf: bytearray, t2_ns: int, t3_ns: int,
              clock_domain: int = CLOCK_UNSYNC, off: int = 0) -> None:
    """회신자가 자기 클럭으로 t2/t3 를 기입하고 유효 플래그·클럭 도메인을 남긴다.

    reflector 는 일반 UDP 소켓(SOCK_DGRAM)이라 커널이 체크섬을 다시 계산하므로
    여기서는 증분 갱신이 필요 없다. GTP-U 안에서 직접 고치는 쪽(stub 코어)은
    `stamp_packet` 을 쓴다.
    """
    struct.pack_into(">Q", buf, off + _OFF_T2, t2_ns & ((1 << 64) - 1))
    struct.pack_into(">Q", buf, off + _OFF_T3, t3_ns & ((1 << 64) - 1))
    buf[off + _OFF_FLAGS] = ((buf[off + _OFF_FLAGS] & 0x0F) | FLAG_T2T3_VALID
                             | ((clock_domain & 0x7) << 4))


# ─────────────────────────────────────────────────────────────────────────────
# 증분 체크섬 (RFC 1624) — probe.py 에서 검증된 기계 그대로, 48 B 로 확장
# ─────────────────────────────────────────────────────────────────────────────
def _ones_complement_fixup(old_ck: int, old_words: Iterable[int],
                           new_words: Iterable[int]) -> int:
    """HC' = ~(~HC + ~m + m') — 바뀐 워드만 반영해 체크섬을 갱신한다."""
    acc = (~old_ck) & 0xFFFF
    for m in old_words:
        acc += (~m) & 0xFFFF
    for m in new_words:
        acc += m & 0xFFFF
    while acc >> 16:
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def stamp_packet(pkt: bytearray, stamp: bytes, *,
                 payload_off: int = IP_HDR + UDP_HDR) -> None:
    """완성된 IPv4/UDP 패킷의 페이로드에 스탬프를 새기고 UDP 체크섬을 증분 갱신.

    페이로드 변경은 IP 헤더 체크섬에 영향이 없으므로 UDP 체크섬만 고친다.
    전체 재계산(1372 B 재순회) 대신 48 B(24워드)만 재합산 — 계측이 관측 대상의
    처리량을 바꾸면 안 된다는 원칙의 실현이다.
    """
    end = payload_off + len(stamp)
    if len(pkt) < end:
        raise ValueError(f"패킷이 스탬프({len(stamp)}B)를 담기에 짧다: {len(pkt)}B")

    ck_off = IP_HDR + 6
    old_ck = (pkt[ck_off] << 8) | pkt[ck_off + 1]
    if old_ck == 0:
        # 체크섬 0 은 IPv4 UDP 에서 '검사 안 함'(RFC 768) — 갱신할 것이 없다.
        pkt[payload_off:end] = stamp
        return

    old_words = [(pkt[i] << 8) | pkt[i + 1] for i in range(payload_off, end, 2)]
    new_words = [(stamp[i] << 8) | stamp[i + 1] for i in range(0, len(stamp), 2)]
    pkt[payload_off:end] = stamp
    new_ck = _ones_complement_fixup(old_ck, old_words, new_words) or 0xFFFF
    pkt[ck_off] = (new_ck >> 8) & 0xFF
    pkt[ck_off + 1] = new_ck & 0xFF


# ─────────────────────────────────────────────────────────────────────────────
# Log-등간 히스토그램 — 메모리 상수 지연 분포
# ─────────────────────────────────────────────────────────────────────────────
class LogHistogram:
    """10 µs–10 s, decade 당 100 bins(총 600) — 상대 분해능 ≈ 10^(1/100)−1 = 2.33%.

    10⁷ 패킷을 흘려도 메모리는 600 정수로 고정된다. 분위수는 bin **상단값**을
    돌려준다(참값보다 절대 작지 않음 → 지연 상한 판정에 보수적). 성공/실패
    계상에는 절대 쓰지 않는다 — 그것은 원값 비교의 몫이다(모듈 docstring 참조).
    """
    LO_MS = 0.01
    HI_MS = 10000.0
    BPD = 100                                   # bins per decade
    NBINS = 600

    __slots__ = ("bins", "count", "total", "vmin", "vmax")

    def __init__(self) -> None:
        self.bins = [0] * self.NBINS
        self.count = 0
        self.total = 0.0
        self.vmin = math.inf
        self.vmax = -math.inf

    def _index(self, v_ms: float) -> int:
        if v_ms <= self.LO_MS:
            return 0
        i = int(self.BPD * math.log10(v_ms / self.LO_MS))
        return min(self.NBINS - 1, i)

    def add(self, v_ms: float) -> None:
        self.bins[self._index(v_ms)] += 1
        self.count += 1
        self.total += v_ms
        if v_ms < self.vmin:
            self.vmin = v_ms
        if v_ms > self.vmax:
            self.vmax = v_ms

    def merge(self, other: "LogHistogram") -> None:
        """다른 히스토그램을 흡수한다(같은 bin 격자이므로 무손실).

        한 모집단의 여러 단말을 하나의 분위수로 볼 때 쓴다. 서비스 요구는
        "이 서비스의 패킷" 에 대한 것이지 단말별 분위수의 평균이 아니므로,
        단말별 분위수를 평균내지 않고 표본을 합쳐서 분위수를 낸다.
        """
        if other.count == 0:
            return
        for i, c in enumerate(other.bins):
            if c:
                self.bins[i] += c
        self.count += other.count
        self.total += other.total
        self.vmin = min(self.vmin, other.vmin)
        self.vmax = max(self.vmax, other.vmax)

    def _upper_edge(self, i: int) -> float:
        return self.LO_MS * 10.0 ** ((i + 1) / self.BPD)

    def value_at_rank(self, rank: int) -> float:
        """1-기반 rank 번째 순서통계량의 보수적(상단) 값."""
        if self.count == 0 or rank <= 0:
            return float("nan")
        rank = min(rank, self.count)
        cum = 0
        for i, c in enumerate(self.bins):
            cum += c
            if cum >= rank:
                if i == self.NBINS - 1:
                    # 범위 초과분이 clamp 된 bin — 상단 edge 가 실측 최대보다 작을
                    # 수 있으므로 실측 최대를 쓴다(그래야 상계로 남는다).
                    return max(self._upper_edge(i), self.vmax)
                return self._upper_edge(i)
        return max(self._upper_edge(self.NBINS - 1), self.vmax)

    def quantile(self, p: float) -> float:
        if self.count == 0:
            return float("nan")
        return self.value_at_rank(max(1, math.ceil(p * self.count)))

    def mean(self) -> float:
        return self.total / self.count if self.count else float("nan")

    def as_dict(self) -> Dict[str, float]:
        if self.count == 0:
            return {"count": 0}
        return {"count": self.count, "min": round(self.vmin, 4),
                "p50": round(self.quantile(0.50), 4),
                "p95": round(self.quantile(0.95), 4),
                "p99": round(self.quantile(0.99), 4),
                "p999": round(self.quantile(0.999), 4),
                "max": round(self.vmax, 4), "mean": round(self.mean(), 4)}


# ─────────────────────────────────────────────────────────────────────────────
# Phase 별 적산과 흐름 원장
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class PhaseStats:
    """한 흐름 × 한 phase 의 평가 모집단 적산."""
    hist: LogHistogram = field(default_factory=LogHistogram)
    sent: int = 0
    n_eval: int = 0            # 검열 규칙 통과 후의 분모
    k_within: int = 0          # delivered AND rtt ≤ PDB (원값 비교)
    received: int = 0
    lost: int = 0              # T_resolve 만료
    late: int = 0              # 도착했으나 PDB 초과 — 3GPP 정의상 실패
    censored: int = 0          # 창 밖 송신 — 분모 제외
    duplicates: int = 0
    reordered: int = 0
    clamped_negative: int = 0  # rtt_net<0 방어 (관측되면 계측 자체의 이상 신호)
    #: 실패(late/lost)의 송신시각 — survival 스캔과 run-length 병기용.
    #: 실패는 희소하다는 가정 하에 목록으로 둔다(무실패면 메모리 0).
    failure_send_ns: List[int] = field(default_factory=list)
    max_failure_run: int = 0
    _run: int = field(default=0, repr=False)
    bytes_acked: int = 0

    def _fail(self, t1_ns: int) -> None:
        self.failure_send_ns.append(t1_ns)
        self._run += 1
        if self._run > self.max_failure_run:
            self.max_failure_run = self._run

    def as_dict(self) -> Dict[str, object]:
        return {"sent": self.sent, "n_eval": self.n_eval,
                "k_within": self.k_within, "received": self.received,
                "lost": self.lost, "late": self.late, "censored": self.censored,
                "duplicates": self.duplicates, "reordered": self.reordered,
                "max_failure_run": self.max_failure_run,
                "bytes_acked": self.bytes_acked, "rtt_ms": self.hist.as_dict()}


class FlowLedger:
    """흐름 하나의 outstanding 추적 + phase 별 적산 + 검열.

    설계 결정
    ---------
    - phase 귀속은 **송신 시각/송신 시점의 phase_id** 기준(§3.7). 회신 스탬프에
      phase_id 가 실려 오므로 회신 시점의 phase 와 무관하게 정확히 복원된다.
    - T_resolve = max(4×PDB, 8×p95_running, 250 ms). p95 는 흐름 전체 히스토그램의
      보수(상단) 분위수 — T_resolve 가 너무 짧아 재정렬/지연 회신을 손실로
      오판하는 쪽이 가장 위험하므로 전 항이 위쪽으로 치우치게 설계했다.
    - 평가창 [start+warmup, end−T_resolve] 판정에는 **만료 확정 시점의 T_resolve**
      를 쓴다. 설계가 어느 시점의 T_resolve 인지 명시하지 않아, 값이 커질수록
      창이 좁아져 표본을 잃을지언정 오염되지는 않는 보수적 해석을 택했다.
    """

    def __init__(self, flow_id: int, *, pdb_ms: Optional[float] = None,
                 label: str = "", t_resolve_floor_ms: float = 250.0):
        self.flow_id = flow_id
        self.label = label
        self.pdb_ms = pdb_ms
        self.t_resolve_floor_ms = t_resolve_floor_ms
        self.outstanding: Dict[int, Tuple[int, int, int]] = {}  # seq → (t1, phase, burst)
        self.phases: Dict[int, PhaseStats] = {}
        self.windows: Dict[int, Tuple[int, int, int]] = {}      # phase → (start, end, warmup_ns)
        self._hist_all = LogHistogram()
        self._highest_seq = -1

    # ── 설정 ────────────────────────────────────────────────────────────
    def set_phase_window(self, phase_id: int, start_ns: int, end_ns: int,
                         warmup_s: float = 0.0) -> None:
        self.windows[phase_id] = (start_ns, end_ns, int(warmup_s * 1e9))

    def phase(self, phase_id: int) -> PhaseStats:
        ps = self.phases.get(phase_id)
        if ps is None:
            ps = self.phases[phase_id] = PhaseStats()
        return ps

    # ── T_resolve ───────────────────────────────────────────────────────
    def t_resolve_ns(self) -> int:
        cand = self.t_resolve_floor_ms
        if self.pdb_ms:
            cand = max(cand, 4.0 * self.pdb_ms)
        if self._hist_all.count >= 20:      # 표본이 적을 때의 p95 는 잡음이다
            cand = max(cand, 8.0 * self._hist_all.quantile(0.95))
        return int(cand * 1e6)

    def _in_window(self, phase_id: int, t1_ns: int, resolve_ns: int) -> bool:
        w = self.windows.get(phase_id)
        if w is None:
            return True                      # 창 미설정 = 검열 없음(오프라인 분석)
        start, end, warm = w
        return (start + warm) <= t1_ns <= (end - resolve_ns)

    # ── 기록 ────────────────────────────────────────────────────────────
    def on_send(self, seq: int, t1_ns: int, phase_id: int = 0,
                burst_id: int = 0) -> None:
        self.outstanding[seq] = (t1_ns, phase_id, burst_id)
        self.phase(phase_id).sent += 1

    def on_reply(self, st: Stamp, t4_ns: int) -> Optional[float]:
        """회신 해소. 기록된 지연(ms)을 돌려준다(중복/미지 seq 는 None).

        지연은 t2/t3 가 유효하면 rtt_net, 아니면 rtt_wire — 어느 쪽이든
        owd_ul ≤ rtt_net ≤ rtt_wire 이므로 PDB 판정은 참 신뢰도의 하한이다(§3.5).
        """
        rec = self.outstanding.pop(st.seq, None)
        phase_hint = st.phase_id
        if rec is None:
            self.phase(phase_hint).duplicates += 1
            return None
        t1_ns, phase_id, _burst = rec
        ps = self.phase(phase_id)

        seq_lin = st.seq & 0x7FFFFFFF        # DL 공간 비트 제거 후 선형 비교
        if self._highest_seq >= 0 and seq_lin < (self._highest_seq & 0x7FFFFFFF):
            ps.reordered += 1
        else:
            self._highest_seq = st.seq

        rtt_ms = (t4_ns - t1_ns) / 1e6
        if st.t2t3_valid:
            net = rtt_ms - st.turn_ns() / 1e6
            if net < 0.0:
                # t3−t2 > rtt_wire 는 물리적으로 불가능 — 회신자 클럭 이상의 증거.
                # 0 으로 자르되 세어 둔다(많으면 verdict 신뢰 불가).
                ps.clamped_negative += 1
                net = 0.0
            rtt_ms = net
        self._hist_all.add(rtt_ms)

        resolve_ns = self.t_resolve_ns()
        if not self._in_window(phase_id, t1_ns, resolve_ns):
            ps.censored += 1
            return rtt_ms
        ps.received += 1
        ps.n_eval += 1
        ps.hist.add(rtt_ms)
        if self.pdb_ms is None or rtt_ms <= self.pdb_ms:   # **원값 비교** — bin 아님
            ps.k_within += 1
            ps._run = 0
        else:
            ps.late += 1
            ps._fail(t1_ns)
        return rtt_ms

    def on_reply_payload(self, payload: bytes, t4_ns: int) -> Optional[float]:
        st = unpack_stamp(payload)
        if st is None:
            return None
        return self.on_reply(st, t4_ns)

    # ── 손실 확정 ────────────────────────────────────────────────────────
    def expire(self, now_ns: int) -> int:
        """T_resolve 경과 미회신을 lost 로 확정. 확정 건수를 돌려준다."""
        if not self.outstanding:
            return 0
        resolve_ns = self.t_resolve_ns()
        dead = [(s, r) for s, r in self.outstanding.items()
                if now_ns - r[0] > resolve_ns]
        for seq, (t1_ns, phase_id, _burst) in dead:
            del self.outstanding[seq]
            ps = self.phase(phase_id)
            if not self._in_window(phase_id, t1_ns, resolve_ns):
                ps.censored += 1
                continue
            ps.n_eval += 1
            ps.lost += 1
            ps._fail(t1_ns)
        return len(dead)

    def finalize(self, now_ns: Optional[int] = None) -> None:
        """런 종료: 만료분은 lost, 아직 기회가 안 지난 것은 censored.

        미해소 표본을 실패로 몰면(단순 finalize=전부 손실) 런 말미가 항상 나쁘게
        보인다 — 그것이 §3.7 검열 규칙의 존재 이유다.
        """
        n = now_ns if now_ns is not None else time.monotonic_ns()
        self.expire(n)
        for seq, (t1_ns, phase_id, _b) in list(self.outstanding.items()):
            del self.outstanding[seq]
            self.phase(phase_id).censored += 1

    def as_dict(self) -> Dict[str, object]:
        return {"flow_id": self.flow_id, "label": self.label,
                "pdb_ms": self.pdb_ms,
                "t_resolve_ms": round(self.t_resolve_ns() / 1e6, 3),
                "phases": {pid: ps.as_dict() for pid, ps in self.phases.items()}}


# ─────────────────────────────────────────────────────────────────────────────
# 버스트(프레임) 원장 — XR frame_delay / frame reliability
# ─────────────────────────────────────────────────────────────────────────────
class BurstLedger:
    """DL stream 버스트를 프레임 단위로 판정한다 (TR 38.838 satisfied-UE 정합).

    프레임 성공 = 그 버스트의 **모든** 패킷이 PDB 내 도착. 버스트 크기는 사전에
    모른다 — FLAG_BURST_END 패킷의 burst_index+1 이 곧 크기다(스트림 회신자가
    기입). frame_delay = 마지막 패킷 t4 − 트리거 t1: 양끝이 같은 gNB 프로세스
    클럭이므로 **동기화 없는 참 실측**이다(§3.1).
    """

    def __init__(self, *, pdb_ms: Optional[float] = None,
                 t_resolve_ms: float = 1000.0):
        self.pdb_ms = pdb_ms
        self.t_resolve_ns = int(t_resolve_ms * 1e6)
        self._open: Dict[Tuple[int, int], Dict[str, object]] = {}
        self.n_frames = 0
        self.k_frames_ok = 0
        self.delay_hist = LogHistogram()
        self.dl_packets = 0
        self.dl_bytes = 0

    def on_dl_packet(self, st: Stamp, t4_ns: int, nbytes: int = 0) -> None:
        key = (st.phase_id, st.burst_id)
        b = self._open.get(key)
        if b is None:
            b = self._open[key] = {"got": 0, "expected": None, "all_within": True,
                                   "t1_ns": st.t1_ns, "last_t4": t4_ns,
                                   "first_seen_ns": t4_ns}
        b["got"] = int(b["got"]) + 1
        if t4_ns > int(b["last_t4"]):
            b["last_t4"] = t4_ns
        self.dl_packets += 1
        self.dl_bytes += nbytes
        # 패킷 단위 PDB 는 트리거 t1 기준 — 프레임 예산은 pose→패킷 도착까지다.
        if self.pdb_ms is not None and (t4_ns - st.t1_ns) / 1e6 > self.pdb_ms:
            b["all_within"] = False
        if st.flags & FLAG_BURST_END:
            b["expected"] = st.burst_index + 1
        exp = b["expected"]
        if exp is not None and int(b["got"]) >= int(exp):
            self._close(key, complete=True)

    def _close(self, key: Tuple[int, int], complete: bool) -> None:
        b = self._open.pop(key)
        self.n_frames += 1
        ok = complete and bool(b["all_within"])
        if ok:
            self.k_frames_ok += 1
        self.delay_hist.add((int(b["last_t4"]) - int(b["t1_ns"])) / 1e6)

    def expire(self, now_ns: int) -> None:
        """T_resolve 넘게 완결되지 않은 버스트는 미완 프레임 = 실패로 확정."""
        for key in [k for k, b in self._open.items()
                    if now_ns - int(b["first_seen_ns"]) > self.t_resolve_ns]:
            self._close(key, complete=False)

    def finalize(self, now_ns: Optional[int] = None) -> None:
        n = now_ns if now_ns is not None else time.monotonic_ns()
        self.expire(n)
        for key in list(self._open):
            self._close(key, complete=False)

    def as_dict(self) -> Dict[str, object]:
        return {"n_frames": self.n_frames, "k_frames_ok": self.k_frames_ok,
                "dl_packets": self.dl_packets, "dl_bytes": self.dl_bytes,
                "frame_delay_ms": self.delay_hist.as_dict()}


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    from ..transport.gtpu import Ipv4UdpTemplate, build_ipv4_udp, _checksum16

    ok = True

    # 1) 48 B 코덱 왕복 — 전 필드
    s = pack_stamp(7, 123456, 987654321012345, phase_id=3,
                   flags=FLAG_REPLY_REQ | FLAG_FRAME_TRIGGER,
                   gen_delta_us=250, burst_id=42, burst_index=5)
    st = unpack_stamp(s + b"\x00" * 64)
    if (st is None or st.flow_id != 7 or st.seq != 123456
            or st.t1_ns != 987654321012345 or st.phase_id != 3
            or st.gen_delta_us != 250 or st.burst_id != 42
            or st.burst_index != 5 or st.t2t3_valid):
        ok = False
        print(f"  [SP] 코덱 왕복 실패: {st}")
    if unpack_stamp(b"\x00" * 64) is not None or unpack_stamp(b"RS") is not None:
        ok = False
        print("  [SP] 스탬프 아닌 것을 스탬프로 읽음")

    # 2) inner IP datagram 경로 — _pump_downlink 훅이 넘기는 것은 UDP 페이로드가
    #    아니라 inner IPv4 전체다. 이 경로가 안 되면 계측이 조용히 0 이 된다.
    inner = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434,
                           s + b"\x00" * 16, ident=9)
    st2 = decode_from_inner_ip(inner)
    if st2 is None or st2.seq != 123456 or st2.flow_id != 7:
        ok = False
        print("  [SP] inner IP 경로 디코딩 실패 — 침묵 0-계측 함정")
    if decode_from_inner_ip(s) is not None:      # 생 페이로드는 IP 가 아니다
        ok = False
        print("  [SP] IP 아닌 버퍼를 inner IP 로 오인")
    elif verbose:
        print("  [SP] inner IPv4(IHL 스킵) 디코딩 OK")

    # 3) fill_t2t3: 플래그/클럭 도메인/값
    buf = bytearray(s + b"\x00" * 16)
    fill_t2t3(buf, 111, 222, CLOCK_SHARED)
    st3 = unpack_stamp(bytes(buf))
    if (st3 is None or not st3.t2t3_valid or st3.t2_ns != 111 or st3.t3_ns != 222
            or st3.reflector_clock != CLOCK_SHARED or st3.turn_ns() != 111):
        ok = False
        print(f"  [SP] fill_t2t3 실패: {st3}")

    # 4) 증분 체크섬 == 전체 재계산 (4개 크기, 바이트 단위 동일)
    for plen in (48, 200, 600, 1372):
        base = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434,
                              bytes(plen), ident=1)
        pkt = bytearray(base)
        stamp = pack_stamp(3, 42, 1_700_000_000_000_000_000, phase_id=2,
                           burst_id=9)
        stamp_packet(pkt, stamp)
        payload = bytearray(bytes(plen))
        payload[:STAMP_LEN] = stamp
        ref = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434,
                             bytes(payload), ident=1)
        if bytes(pkt) != ref:
            ok = False
            print(f"  [SP] 증분 체크섬 불일치 plen={plen}")
        udp_len = 8 + plen
        pseudo = pkt[12:20] + bytes([0, 17]) + struct.pack(">H", udp_len)
        if _checksum16(bytes(pseudo) + bytes(pkt[20:])) != 0:
            ok = False
            print(f"  [SP] 스탬프 후 UDP 체크섬 무효 plen={plen}")
    if verbose and ok:
        print("  [SP] 증분 체크섬 = 전체 재계산 (48/200/600/1372 B) OK")

    # 5) 속도: 증분이 전체 재계산보다 빨라야 계측이 처리량을 깎지 않는다
    tmpl = Ipv4UdpTemplate("10.45.0.7", "8.8.8.8", 40000, 33434, payload_len=1372)
    t0 = time.perf_counter()
    for i in range(3000):
        p = bytearray(tmpl.build(i & 0xFFFF))
        stamp_packet(p, pack_stamp(1, i, i))
    t_inc = time.perf_counter() - t0
    t0 = time.perf_counter()
    pay = bytearray(bytes(1372))
    for i in range(3000):
        pay[:STAMP_LEN] = pack_stamp(1, i, i)
        build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434, bytes(pay), ident=i)
    t_full = time.perf_counter() - t0
    if t_inc >= t_full:
        ok = False
        print(f"  [SP] 증분이 전체보다 느림: {t_inc:.3f}s vs {t_full:.3f}s")
    elif verbose:
        print(f"  [SP] 48B 스탬프 비용: 증분 {t_inc*1e6/3000:.1f} us/pkt vs "
              f"전체재계산 {t_full*1e6/3000:.1f} us/pkt ({t_full/t_inc:.1f}배) OK")

    # 6) 히스토그램: 보수성(상단값)과 상대 분해능 ≤ 2.33%, 메모리 상수
    h = LogHistogram()
    import random
    rng = random.Random(42)
    vals = sorted(rng.uniform(0.1, 50.0) for _ in range(100000))
    for v in vals:
        h.add(v)
    for p in (0.5, 0.95, 0.99):
        exact = vals[max(0, math.ceil(p * len(vals)) - 1)]
        est = h.quantile(p)
        if not (exact <= est <= exact * 1.0235):
            ok = False
            print(f"  [SP] 히스토그램 p{p}: {est} vs 정확 {exact} — 보수성/분해능 위반")
    if len(h.bins) != 600 or h.count != 100000:
        ok = False
        print("  [SP] 히스토그램 메모리/계수 이상")
    # 범위 초과 clamp: 상단값이 실측 최대 아래로 내려가면 안 된다
    h2 = LogHistogram()
    h2.add(50000.0)
    if h2.quantile(0.99) < 50000.0:
        ok = False
        print("  [SP] 범위초과 값의 분위수가 실측 최대보다 작다")

    # 7) 원장: PDB 성공은 **원값** 비교 — bin 상단값이면 실패로 오판될 경계 사례.
    #    rtt=1.001 ms 는 bin 200(상단 1.0233 ms)에 들어간다. pdb=1.01 ms 에서
    #    원값 비교는 성공, bin 상단 비교라면 실패였을 것이다.
    led = FlowLedger(1, pdb_ms=1.01)
    led.on_send(0, 1_000_000_000, phase_id=0)
    led.on_reply(Stamp(1, 0, FLAG_REPLY_REQ, 0, 1_000_000_000, 0, 0, 0, 0, 0),
                 1_000_000_000 + 1_001_000)
    ps = led.phase(0)
    if ps.k_within != 1 or ps.late != 0:
        ok = False
        print(f"  [SP] PDB 원값 판정 실패: within={ps.k_within} late={ps.late}")
    elif verbose:
        print("  [SP] PDB 판정이 bin 아닌 원값 (경계 1.001 ms ≤ 1.01 ms) OK")

    # 8) late 는 실패, rtt_net = rtt_wire − turn
    led2 = FlowLedger(2, pdb_ms=1.0)
    base = 10_000_000_000
    for i in range(10):
        led2.on_send(i, base + i * 1_000_000)
    for i in range(10):
        # 5 ms 왕복이지만 회신자 처리 4.5 ms → rtt_net 0.5 ms (성공)
        t2, t3 = base + i * 1_000_000 + 200_000, base + i * 1_000_000 + 4_700_000
        fl = FLAG_REPLY_REQ | FLAG_T2T3_VALID
        s_i = Stamp(2, 0, fl, i, base + i * 1_000_000, 0, t2, t3, 0, 0)
        if i < 8:
            led2.on_reply(s_i, base + i * 1_000_000 + 5_000_000)
        else:
            # 처리시간 없이 5 ms → rtt_net 5 ms (late)
            s_i.flags = FLAG_REPLY_REQ
            led2.on_reply(s_i, base + i * 1_000_000 + 5_000_000)
    ps2 = led2.phase(0)
    if ps2.k_within != 8 or ps2.late != 2 or ps2.max_failure_run != 2:
        ok = False
        print(f"  [SP] late/rtt_net 계상 오류: {ps2.as_dict()}")

    # 9) T_resolve 공식: floor 250 ms / 4×PDB / 8×p95 중 최대
    l3 = FlowLedger(3, pdb_ms=100.0)
    if abs(l3.t_resolve_ns() / 1e6 - 400.0) > 1e-6:   # 4×100 > 250
        ok = False
        print(f"  [SP] T_resolve(4×PDB) 오류: {l3.t_resolve_ns()/1e6}")
    l4 = FlowLedger(4)                                 # 표본 없음 → floor
    if abs(l4.t_resolve_ns() / 1e6 - 250.0) > 1e-6:
        ok = False
        print(f"  [SP] T_resolve(floor) 오류: {l4.t_resolve_ns()/1e6}")
    for i in range(30):
        l4.on_send(i, base + i)
        l4.on_reply(Stamp(4, 0, 0, i, base + i, 0, 0, 0, 0, 0),
                    base + i + 60_000_000)             # 60 ms → 8×p95 ≈ 480 ms
    if l4.t_resolve_ns() / 1e6 < 400.0:
        ok = False
        print(f"  [SP] T_resolve(8×p95) 오류: {l4.t_resolve_ns()/1e6}")

    # 10) 검열: 평가창 [start+warmup, end−T_resolve] 밖 송신은 분모 제외
    l5 = FlowLedger(5, pdb_ms=10.0)                    # T_resolve = 250 ms(floor)
    t0n, t1n = 1_000_000_000, 11_000_000_000
    l5.set_phase_window(0, t0n, t1n, warmup_s=1.0)     # 평가창 [2.0 s, 10.75 s]
    cases = [(0, int(1.5e9), "warmup"), (1, int(5.0e9), "in"),
             (2, int(10.9e9), "tail")]
    for seq, ts, _w in cases:
        l5.on_send(seq, ts)
        l5.on_reply(Stamp(5, 0, 0, seq, ts, 0, 0, 0, 0, 0), ts + 1_000_000)
    ps5 = l5.phase(0)
    if ps5.n_eval != 1 or ps5.censored != 2 or ps5.k_within != 1:
        ok = False
        print(f"  [SP] 검열 경계 오류: {ps5.as_dict()}")
    elif verbose:
        print("  [SP] 검열: warmup/tail 송신 분모 제외, 창 내만 계상 OK")

    # 11) 손실 확정(expire)과 finalize 의 검열 — 기회가 안 지난 표본은 censored
    l6 = FlowLedger(6, pdb_ms=10.0)
    l6.on_send(0, base)                                # 오래된 미회신 → lost
    l6.on_send(1, base + 200_000_000)                  # 250 ms 안 지남 → censored
    l6.finalize(now_ns=base + 300_000_000)
    ps6 = l6.phase(0)
    if ps6.lost != 1 or ps6.censored != 1 or ps6.n_eval != 1:
        ok = False
        print(f"  [SP] finalize 검열 오류: {ps6.as_dict()}")

    # 12) 중복/재정렬
    l7 = FlowLedger(7, pdb_ms=10.0)
    for i in range(3):
        l7.on_send(i, base + i * 1_000_000)
    r = Stamp(7, 0, 0, 2, base + 2_000_000, 0, 0, 0, 0, 0)
    l7.on_reply(r, base + 3_000_000)
    l7.on_reply(Stamp(7, 0, 0, 0, base, 0, 0, 0, 0, 0), base + 4_000_000)  # 재정렬
    l7.on_reply(r, base + 5_000_000)                                       # 중복
    ps7 = l7.phase(0)
    if ps7.duplicates != 1 or ps7.reordered != 1 or ps7.received != 2:
        ok = False
        print(f"  [SP] 중복/재정렬 오류: {ps7.as_dict()}")

    # 13) 버스트 원장: 완결/지연/미완 프레임과 frame_delay
    bl = BurstLedger(pdb_ms=10.0)
    trig_t1 = base
    for idx in range(3):                               # 3-패킷 프레임, 전부 제때
        fl = FLAG_T2T3_VALID | (FLAG_BURST_END if idx == 2 else 0)
        bl.on_dl_packet(Stamp(1, 0, fl, DL_SEQ_BIT | idx, trig_t1, 0, 0, 0,
                              100, idx), trig_t1 + (idx + 1) * 2_000_000, 1400)
    if bl.n_frames != 1 or bl.k_frames_ok != 1:
        ok = False
        print(f"  [SP] 버스트 완결 오류: {bl.as_dict()}")
    fd = bl.delay_hist.vmax
    if not (5.9 < fd < 6.2):                           # 마지막 패킷 t4−t1 = 6 ms
        ok = False
        print(f"  [SP] frame_delay 오류: {fd}")
    # 프레임 내 1 패킷이 PDB 초과 → 프레임 실패
    for idx in range(3):
        fl = FLAG_BURST_END if idx == 2 else 0
        late = 12_000_000 if idx == 1 else 2_000_000
        bl.on_dl_packet(Stamp(1, 0, fl, DL_SEQ_BIT | (16 + idx), trig_t1, 0, 0, 0,
                              101, idx), trig_t1 + late, 1400)
    # 패킷 유실로 미완 → expire 로 실패 확정
    bl.on_dl_packet(Stamp(1, 0, 0, DL_SEQ_BIT | 32, trig_t1, 0, 0, 0, 102, 0),
                    trig_t1 + 2_000_000, 1400)
    bl.finalize(now_ns=trig_t1 + int(2e9))
    if bl.n_frames != 3 or bl.k_frames_ok != 1:
        ok = False
        print(f"  [SP] 프레임 실패 계상 오류: {bl.as_dict()}")
    elif verbose:
        print(f"  [SP] 프레임 판정: 완결 1 / 지연 1 / 미완 1 → ok 1/3 OK")

    # 14) 해소 성능 — 원장이 pps 상한을 깎지 않는지 (메모리도 상수 유지)
    l8 = FlowLedger(8, pdb_ms=10.0)
    n_perf = 200_000
    t0 = time.perf_counter()
    for i in range(n_perf):
        t1_ns = base + i * 10_000
        l8.on_send(i, t1_ns)
        l8.on_reply(Stamp(8, 0, 0, i, t1_ns, 0, 0, 0, 0, 0), t1_ns + 500_000)
    dt = time.perf_counter() - t0
    rate = n_perf / dt
    if l8.outstanding or l8.phase(0).n_eval != n_perf:
        ok = False
        print("  [SP] 성능 시험 중 원장 상태 오류")
    if rate < 30_000:
        ok = False
        print(f"  [SP] 해소 성능 미달: {rate:,.0f}/s")
    elif verbose:
        print(f"  [SP] 해소 성능 {rate:,.0f} 쌍/s (2×10⁵ 합성, bins 600 고정) OK")

    return ok


if __name__ == "__main__":
    print("STAMP selftest:", "PASS" if selftest(verbose=True) else "FAIL")
