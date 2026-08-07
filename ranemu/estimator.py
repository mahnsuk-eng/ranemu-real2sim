#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.estimator — 캡처 손실을 보정하는 처리량 추정기.

문제
====
수동 프로브는 **캡처된 바이트**를 세어 처리량을 보고한다. 캡처 경로가 패킷을 잃으면
(1 GbE 미러 포화 등) 보고값은 조용히 낮아진다. 프로브는 자기가 무엇을 놓쳤는지 모른다 —
놓친 패킷은 정의상 보이지 않기 때문이다.

착상
====
그러나 **놓친 패킷의 흔적은 남는다.** 스트림이 단조 증가하는 인밴드 카운터를 실어
나른다면, 캡처된 값들 사이의 빈틈이 곧 손실량이다:

    관측된 카운터:  ... 41, 42, 45, 46, 47, 51 ...
                            ↑빈틈 2개    ↑빈틈 3개
    → 손실 5, 관측 6 → 손실률 5/11 = 45.5%
    → 보정 처리량 = 관측 처리량 / (1 − 0.455)

카운터 원천(우선순위)
  1. **GTP-U 시퀀스 번호** (TS 29.281 §5.1) — RAN 이 설정하면 가장 직접적
  2. **내부 IPv4 identification** — 송신 스택이 순차 증가시키면 사용 가능
  3. (참고) 내부 TCP 시퀀스 — dpi_engine 이 이미 ACK 기반으로 활용

가정과 한계는 `LossEstimate.assumptions` 에 명시된다. 특히 손실 패킷의 평균 크기가
관측 패킷과 같다고 가정하므로, 크기가 강하게 편향된 트래픽에서는 보정이 부정확하다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .pcapio import PcapReader
from .util import get_logger

log = get_logger("ranemu.estimator")

#: 16비트 카운터의 모듈러
_MOD16 = 1 << 16

#: 이보다 큰 전진은 손실이 아니라 재정렬/카운터 리셋/다른 흐름으로 간주(보수적)
DEFAULT_MAX_GAP = 4096


class SequenceTracker:
    """모듈러 단조 카운터에서 손실·중복·재정렬을 분리해 센다.

    16비트 카운터는 자주 순환하므로 부호 있는 모듈러 델타로 전진/후진을 판정한다.
    후진(재정렬 또는 중복)은 손실로 세지 않는다 — 그렇게 하면 손실을 과대평가한다.

    바이트 추정
    -----------
    손실 패킷의 크기는 알 수 없다. 두 가지 추정을 함께 낸다:
      · 전역 평균 기반  — 손실이 패킷 크기와 **독립**일 때 불편(unbiased)
      · 갭 국소 평균 기반 — 갭을 감싼 두 패킷의 평균 크기를 쓴다. tail-drop 처럼
        손실이 크기와 상관될 때, 큰 패킷 구간에서 큰 손실을 가정하게 되어 편향이 준다.
    """

    __slots__ = ("last", "last_size", "observed", "lost", "duplicates", "reordered",
                 "resets", "max_gap", "modulus", "lost_bytes_local")

    def __init__(self, modulus: int = _MOD16, max_gap: int = DEFAULT_MAX_GAP):
        self.modulus = modulus
        self.max_gap = max_gap
        self.last: Optional[int] = None
        self.last_size: int = 0
        self.observed = 0
        self.lost = 0
        self.duplicates = 0
        self.reordered = 0
        self.resets = 0
        self.lost_bytes_local = 0.0

    def feed(self, counter: int, size: int = 0) -> None:
        counter %= self.modulus
        self.observed += 1
        if self.last is None:
            self.last = counter
            self.last_size = size
            return
        # 부호 있는 모듈러 델타: (-modulus/2, +modulus/2]
        delta = (counter - self.last) % self.modulus
        if delta > self.modulus // 2:
            delta -= self.modulus
        if delta == 1:
            pass                                   # 정상 연속
        elif delta == 0:
            self.duplicates += 1
            return                                 # last 갱신 안 함
        elif delta < 0:
            self.reordered += 1
            return                                 # 뒤늦게 도착 — last 유지
        elif delta <= self.max_gap:
            n_lost = delta - 1
            self.lost += n_lost
            # 갭을 감싼 두 패킷의 평균 크기로 손실 바이트를 추정
            if size or self.last_size:
                local = (self.last_size + size) / 2.0 if (self.last_size and size) \
                    else float(self.last_size or size)
                self.lost_bytes_local += n_lost * local
        else:
            self.resets += 1                       # 비정상 점프: 손실로 세지 않음
        self.last = counter
        self.last_size = size

    @property
    def total_sent_estimate(self) -> int:
        """이 흐름에서 실제로 송신되었을 패킷 수 추정."""
        return self.observed - self.duplicates + self.lost

    @property
    def loss_rate(self) -> float:
        total = self.total_sent_estimate
        return (self.lost / total) if total > 0 else 0.0


@dataclass
class FlowEstimate:
    """한 흐름(TEID 또는 단말 IP)의 추정 결과."""
    key: str
    source: str = "none"                 # gtpu_seq | ip_id | none
    observed_packets: int = 0
    observed_bytes: int = 0              # 내부 IP 패킷 바이트(디캡 후)
    duplicates: int = 0
    reordered: int = 0
    estimated_lost: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    teid: Optional[int] = None
    ue_ip: Optional[str] = None
    #: 갭 국소 평균으로 추정한 손실 바이트(크기상관 손실에서 편향이 작다)
    lost_bytes_local: float = 0.0
    #: 관측 패킷 크기의 변동계수 — 클수록 크기상관 손실의 위험이 크다
    size_cv: float = 0.0
    _size_sum: float = 0.0
    _size_sq: float = 0.0

    @property
    def span_s(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def unique_packets(self) -> int:
        return self.observed_packets - self.duplicates

    @property
    def unique_bytes(self) -> int:
        """중복 제거 후 바이트(평균 크기로 환산)."""
        if self.observed_packets <= 0:
            return 0
        mean = self.observed_bytes / self.observed_packets
        return int(round(mean * self.unique_packets))

    @property
    def loss_rate(self) -> float:
        total = self.unique_packets + self.estimated_lost
        return (self.estimated_lost / total) if total > 0 else 0.0

    @property
    def measured_bps(self) -> float:
        """프로브가 보고하는 값에 해당(중복 제거만 적용, 손실 보정 없음)."""
        s = self.span_s
        return (self.unique_bytes * 8.0 / s) if s > 0 else 0.0

    @property
    def corrected_bps(self) -> float:
        """손실 보정 처리량(전역 평균 가정). 손실이 패킷 크기와 독립일 때 불편."""
        lr = self.loss_rate
        if lr >= 0.999:
            return 0.0
        return self.measured_bps / (1.0 - lr)

    @property
    def corrected_local_bps(self) -> float:
        """갭 국소 평균 크기로 손실 바이트를 추정한 보정 처리량.

        tail-drop 처럼 큰 패킷이 우선 버려지는 경우, 전역 평균을 쓰면 손실 바이트를
        과소평가한다. 갭 주변 패킷이 크면 그 갭의 손실도 컸다고 보는 편이 낫다.
        """
        s = self.span_s
        if s <= 0:
            return 0.0
        return (self.unique_bytes + self.lost_bytes_local) * 8.0 / s

    @property
    def size_bias_risk(self) -> bool:
        """크기상관 손실로 보정이 편향될 위험이 있는가.

        패킷 크기가 균일하면(변동계수가 작으면) 어떤 손실 패턴이든 보정은 불편하다.
        이질적이면서 손실이 있으면 편향 가능 — 값을 조용히 믿게 두지 않고 표시한다.
        """
        return self.size_cv > 0.25 and self.loss_rate > 0.01

    @property
    def reliable(self) -> bool:
        return not self.size_bias_risk

    def as_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key, "source": self.source, "teid": self.teid,
            "ue_ip": self.ue_ip,
            "observed_packets": self.observed_packets,
            "unique_packets": self.unique_packets,
            "duplicates": self.duplicates, "reordered": self.reordered,
            "estimated_lost": self.estimated_lost,
            "loss_rate": round(self.loss_rate, 6),
            "span_s": round(self.span_s, 6),
            "measured_mbps": round(self.measured_bps / 1e6, 4),
            "corrected_mbps": round(self.corrected_bps / 1e6, 4),
            "corrected_local_mbps": round(self.corrected_local_bps / 1e6, 4),
            "size_cv": round(self.size_cv, 4),
            "size_bias_risk": self.size_bias_risk,
            "reliable": self.reliable,
        }


@dataclass
class LossEstimate:
    """pcap 전체에 대한 추정 결과."""
    flows: List[FlowEstimate] = field(default_factory=list)
    packets_read: int = 0
    gtpu_packets: int = 0
    counter_source: str = "none"
    assumptions: List[str] = field(default_factory=lambda: [
        "손실 패킷의 평균 크기가 관측 패킷과 같다",
        "인밴드 카운터가 흐름 내에서 단조 증가한다",
        f"연속 {DEFAULT_MAX_GAP}개를 넘는 빈틈은 손실이 아니라 재정렬/리셋으로 본다",
    ])

    @property
    def aggregate_loss_rate(self) -> float:
        lost = sum(f.estimated_lost for f in self.flows)
        uniq = sum(f.unique_packets for f in self.flows)
        total = lost + uniq
        return (lost / total) if total > 0 else 0.0

    def by_ue_ip(self) -> Dict[str, FlowEstimate]:
        return {f.ue_ip: f for f in self.flows if f.ue_ip}

    def as_dict(self) -> Dict[str, Any]:
        return {"packets_read": self.packets_read, "gtpu_packets": self.gtpu_packets,
                "counter_source": self.counter_source,
                "aggregate_loss_rate": round(self.aggregate_loss_rate, 6),
                "assumptions": self.assumptions,
                "flows": [f.as_dict() for f in self.flows]}


# ─────────────────────────────────────────────────────────────────────────────
def _parse_frame(data: bytes) -> Optional[Tuple[int, bytes, Optional[int]]]:
    """Ethernet/IPv4/UDP(2152) 프레임에서 (TEID, 내부 IP 패킷, GTP-U seq) 추출.

    dpkt 없이 직접 파싱한다(핫 경로이고 필요한 필드가 적다). VLAN 태그를 벗긴다.
    """
    n = len(data)
    if n < 14:
        return None
    off = 12
    etype = (data[off] << 8) | data[off + 1]
    off += 2
    # VLAN(0x8100) / QinQ(0x88a8, 0x9100) 언랩
    guard = 0
    while etype in (0x8100, 0x88A8, 0x9100) and off + 4 <= n and guard < 3:
        etype = (data[off + 2] << 8) | data[off + 3]
        off += 4
        guard += 1
    if etype != 0x0800 or off + 20 > n:
        return None
    ip_start = off
    if (data[ip_start] >> 4) != 4:
        return None
    ihl = (data[ip_start] & 0x0F) * 4
    if data[ip_start + 9] != 17:                   # UDP 아님
        return None
    udp = ip_start + ihl
    if udp + 8 > n:
        return None
    sport = (data[udp] << 8) | data[udp + 1]
    dport = (data[udp + 2] << 8) | data[udp + 3]
    if 2152 not in (sport, dport):
        return None
    g = udp + 8
    if g + 8 > n:
        return None
    flags = data[g]
    if (flags >> 5) & 0x07 != 1:                   # GTP 버전 1
        return None
    if data[g + 1] != 0xFF:                        # G-PDU 만
        return None
    teid = int.from_bytes(data[g + 4:g + 8], "big")
    pos = g + 8
    seq: Optional[int] = None
    if flags & 0x07:
        if pos + 4 > n:
            return None
        if flags & 0x02:                           # S 비트
            seq = (data[pos] << 8) | data[pos + 1]
        next_ext = data[pos + 3]
        pos += 4
        guard = 0
        while next_ext != 0x00 and pos < n and guard < 8:
            ext_len = data[pos] * 4
            if ext_len < 4 or pos + ext_len > n:
                return None
            next_ext = data[pos + ext_len - 1]
            pos += ext_len
            guard += 1
    return teid, data[pos:], seq


def _inner_ip_info(inner: bytes) -> Optional[Tuple[str, int, int]]:
    """내부 IPv4 패킷 → (출발지 IP, identification, 전체 길이)."""
    if len(inner) < 20 or (inner[0] >> 4) != 4:
        return None
    ident = (inner[4] << 8) | inner[5]
    total = (inner[2] << 8) | inner[3]
    src = f"{inner[12]}.{inner[13]}.{inner[14]}.{inner[15]}"
    return src, ident, total


def estimate_from_pcap(path: str, *, prefer: str = "auto",
                       max_gap: int = DEFAULT_MAX_GAP,
                       max_packets: int = 0) -> LossEstimate:
    """캡처 pcap 에서 흐름별 손실률과 보정 처리량을 추정한다.

    prefer: "auto" | "gtpu_seq" | "ip_id"
    """
    est = LossEstimate()
    trackers: Dict[str, SequenceTracker] = {}
    flows: Dict[str, FlowEstimate] = {}
    seq_available = 0
    ipid_available = 0

    reader = PcapReader(path)
    try:
        for ts, data, _orig in reader:
            est.packets_read += 1
            if max_packets and est.packets_read > max_packets:
                break
            parsed = _parse_frame(data)
            if parsed is None:
                continue
            teid, inner, gseq = parsed
            info = _inner_ip_info(inner)
            if info is None:
                continue
            src_ip, ident, total_len = info
            est.gtpu_packets += 1
            if gseq is not None:
                seq_available += 1
            ipid_available += 1

            key = f"{teid}"
            fl = flows.get(key)
            if fl is None:
                fl = FlowEstimate(key=key, teid=teid, ue_ip=src_ip)
                flows[key] = fl
                trackers[key] = SequenceTracker(max_gap=max_gap)
            fl.observed_packets += 1
            fl.observed_bytes += total_len
            fl._size_sum += total_len
            fl._size_sq += total_len * total_len
            if fl.first_ts is None:
                fl.first_ts = ts
            fl.last_ts = ts

            # 카운터 선택: GTP-U 시퀀스가 있으면 우선, 없으면 내부 IP-ID
            use_seq = (prefer == "gtpu_seq") or (prefer == "auto" and gseq is not None)
            counter = gseq if (use_seq and gseq is not None) else ident
            trackers[key].feed(counter, total_len)
    finally:
        reader.close()

    if est.gtpu_packets:
        if seq_available >= est.gtpu_packets * 0.99 and prefer in ("auto", "gtpu_seq"):
            est.counter_source = "gtpu_seq"
        elif ipid_available:
            est.counter_source = "ip_id"
    for key, fl in flows.items():
        t = trackers[key]
        fl.estimated_lost = t.lost
        fl.duplicates = t.duplicates
        fl.reordered = t.reordered
        fl.lost_bytes_local = t.lost_bytes_local
        fl.source = est.counter_source
        n = fl.observed_packets
        if n > 1:
            mean = fl._size_sum / n
            var = max(0.0, fl._size_sq / n - mean * mean)
            fl.size_cv = (var ** 0.5 / mean) if mean > 0 else 0.0
        est.flows.append(fl)
    est.flows.sort(key=lambda f: -f.observed_packets)
    return est


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    import os
    import random
    import tempfile
    from .impair import ImpairmentConfig, apply_to_pcap
    from .pcapio import GtpuFramer, PcapWriter
    from .transport.gtpu import Ipv4UdpTemplate, build_ipv4_udp, encode, MSG_GPDU

    ok = True

    # ── 카운터 추적기 단위검증 ────────────────────────────────────────────
    t = SequenceTracker()
    for c in (10, 11, 12, 15, 16):                 # 13,14 손실
        t.feed(c)
    if t.lost != 2 or t.observed != 5:
        ok = False
        print(f"  [EST] 기본 갭 계산 오류: lost={t.lost}")
    elif verbose:
        print("  [EST] 갭 → 손실 2개 계산 OK")

    t = SequenceTracker()                          # 랩어라운드
    for c in (65534, 65535, 0, 1):
        t.feed(c)
    if t.lost != 0:
        ok = False
        print(f"  [EST] 16비트 랩어라운드에서 허위 손실 {t.lost}")
    elif verbose:
        print("  [EST] 랩어라운드 허위손실 없음 OK")

    t = SequenceTracker()                          # 중복
    for c in (5, 6, 6, 7):
        t.feed(c)
    if t.duplicates != 1 or t.lost != 0:
        ok = False
        print(f"  [EST] 중복 처리 오류: dup={t.duplicates} lost={t.lost}")

    t = SequenceTracker()                          # 재정렬
    for c in (5, 7, 6, 8):
        t.feed(c)
    if t.reordered != 1 or t.lost != 1:
        ok = False
        print(f"  [EST] 재정렬 처리 오류: reord={t.reordered} lost={t.lost}")
    elif verbose:
        print("  [EST] 중복/재정렬을 손실과 분리 OK")

    # 비정상 전방 점프(max_gap 초과)는 손실이 아니라 리셋으로 본다.
    # 주의: 16비트 모듈러에서 +49999 는 실제로 −15537(역방향=재정렬)이므로
    # 전방 점프를 시험하려면 modulus/2 미만이면서 max_gap 을 넘는 값을 써야 한다.
    t = SequenceTracker(max_gap=100)
    t.feed(1); t.feed(5000)
    if t.lost != 0 or t.resets != 1:
        ok = False
        print(f"  [EST] 비정상 전방점프 처리 오류: lost={t.lost} resets={t.resets}")
    t = SequenceTracker(max_gap=100)               # 큰 후진 = 재정렬
    t.feed(1); t.feed(50000)
    if t.lost != 0 or t.reordered != 1:
        ok = False
        print(f"  [EST] 큰 후진을 재정렬로 보지 않음: lost={t.lost} "
              f"reord={t.reordered}")
    elif verbose:
        print("  [EST] 비정상 전방점프=리셋, 큰 후진=재정렬 구분 OK")

    # ── pcap 통합: 알려진 손실률을 복원하는가 ─────────────────────────────
    with tempfile.TemporaryDirectory(prefix="ranemu-est-") as td:
        src = os.path.join(td, "truth.pcap")
        fr = GtpuFramer("10.1.16.52", "10.1.16.60")
        tmpl = Ipv4UdpTemplate("10.45.0.7", "8.8.8.8", 40000, 33434, payload_len=1372)
        n, gap = 6000, 1e-4
        with PcapWriter(src) as w:
            for i in range(n):
                gtp = encode(MSG_GPDU, 0x1001, tmpl.build(i & 0xFFFF),
                             sequence=i & 0xFFFF, qfi=1)
                w.write(1700000000.0 + i * gap, fr.frame(gtp))

        # 무손상: 손실 0, 측정=보정
        e0 = estimate_from_pcap(src)
        if e0.gtpu_packets != n:
            ok = False
            print(f"  [EST] GTP-U 파싱 수 {e0.gtpu_packets} != {n}")
        if e0.aggregate_loss_rate > 1e-9:
            ok = False
            print(f"  [EST] 무손상인데 손실 추정 {e0.aggregate_loss_rate}")
        elif verbose:
            print(f"  [EST] 무손상 pcap: {e0.gtpu_packets}패킷, 손실추정 0, "
                  f"source={e0.counter_source} OK")
        f0 = e0.flows[0]
        truth_bps = f0.measured_bps

        # 손실 주입 → 추정 손실률과 보정 처리량 확인
        for target in (0.05, 0.10, 0.25, 0.40, 0.60):
            d = os.path.join(td, f"l{int(target*100)}.pcap")
            st = apply_to_pcap(src, d, ImpairmentConfig(loss_rate=target, seed=11))
            e = estimate_from_pcap(d)
            f = e.flows[0]
            actual = st.loss_rate_actual
            err_loss = abs(f.loss_rate - actual)
            # 보정 전/후 처리량 오차
            err_raw = abs(f.measured_bps - truth_bps) / truth_bps * 100
            err_cor = abs(f.corrected_bps - truth_bps) / truth_bps * 100
            if err_loss > 0.02:
                ok = False
                print(f"  [EST] 손실률 추정 오차 큼: 실제 {actual:.3f} 추정 {f.loss_rate:.3f}")
            if err_cor > err_raw:
                ok = False
                print(f"  [EST] 보정이 오히려 나빠짐: raw {err_raw:.1f}% → cor {err_cor:.1f}%")
            elif verbose:
                print(f"  [EST] 손실 {actual*100:>4.1f}% → 추정 {f.loss_rate*100:>4.1f}%, "
                      f"처리량 오차 {err_raw:>5.1f}% → 보정후 {err_cor:>4.1f}%")

        # IP-ID 만 있는 경우(GTP-U 시퀀스 없음)도 동작해야 한다
        src2 = os.path.join(td, "noseq.pcap")
        with PcapWriter(src2) as w:
            for i in range(n):
                gtp = encode(MSG_GPDU, 0x1002, tmpl.build(i & 0xFFFF), qfi=1)
                w.write(1700000000.0 + i * gap, fr.frame(gtp))
        d2 = os.path.join(td, "noseq_l.pcap")
        st2 = apply_to_pcap(src2, d2, ImpairmentConfig(loss_rate=0.2, seed=13))
        e2 = estimate_from_pcap(d2)
        if e2.counter_source != "ip_id":
            ok = False
            print(f"  [EST] 카운터 원천 선택 오류: {e2.counter_source}")
        f2 = e2.flows[0]
        if abs(f2.loss_rate - st2.loss_rate_actual) > 0.02:
            ok = False
            print(f"  [EST] IP-ID 기반 손실 추정 오차: 실제 {st2.loss_rate_actual:.3f} "
                  f"추정 {f2.loss_rate:.3f}")
        elif verbose:
            print(f"  [EST] IP-ID 기반(시퀀스 없음) 손실 {st2.loss_rate_actual*100:.1f}% "
                  f"→ 추정 {f2.loss_rate*100:.1f}% OK")

        # 중복(다중 탭)이 손실 추정을 오염시키지 않아야 한다
        d3 = os.path.join(td, "dup.pcap")
        apply_to_pcap(src, d3, ImpairmentConfig(duplicate_rate=0.3, seed=17))
        e3 = estimate_from_pcap(d3)
        f3 = e3.flows[0]
        if f3.loss_rate > 0.02:
            ok = False
            print(f"  [EST] 중복 때문에 허위 손실 {f3.loss_rate:.3f}")
        if abs(f3.corrected_bps - truth_bps) / truth_bps > 0.05:
            ok = False
            print(f"  [EST] 중복 환경 보정 오차 "
                  f"{abs(f3.corrected_bps-truth_bps)/truth_bps*100:.1f}%")
        elif verbose:
            print(f"  [EST] 다중탭 중복 30%: 허위손실 {f3.loss_rate*100:.2f}%, "
                  f"보정 처리량 오차 {abs(f3.corrected_bps-truth_bps)/truth_bps*100:.2f}% OK")

        # ── 보정 가정이 깨지는 조건: 크기상관 손실 ────────────────────────
        # 균일 크기면 어떤 손실 패턴이든 보정이 정확해야 하고,
        # 이질적 크기 + tail-drop 이면 편향이 생기되 **반드시 플래그가 서야 한다**.
        rng = random.Random(21)
        mixed = os.path.join(td, "mixed.pcap")
        fr2 = GtpuFramer("10.1.16.52", "10.1.16.60")
        with PcapWriter(mixed) as w:
            for i in range(8000):
                sz = 64 if rng.random() < 0.5 else 1400
                ip = build_ipv4_udp("10.45.0.9", "8.8.8.8", 40001, 33434,
                                    bytes(max(0, sz - 28)), ident=i & 0xFFFF)
                w.write(1700000000.0 + i * 1e-4,
                        fr2.frame(encode(MSG_GPDU, 0x3002, ip,
                                         sequence=i & 0xFFFF, qfi=1)))
        base = estimate_from_pcap(mixed).flows[0]
        truth_mixed = base.measured_bps
        if base.size_cv < 0.5:
            ok = False
            print(f"  [EST] 혼합 크기인데 size_cv 가 낮음: {base.size_cv:.3f}")

        # 균등(크기 독립) 손실 → 이질적이어도 보정이 정확해야 한다
        du = os.path.join(td, "mixed_uni.pcap")
        apply_to_pcap(mixed, du, ImpairmentConfig(loss_rate=0.30, seed=23))
        fu = estimate_from_pcap(du).flows[0]
        eu = abs(fu.corrected_bps - truth_mixed) / truth_mixed * 100
        if eu > 3.0:
            ok = False
            print(f"  [EST] 크기독립 손실인데 보정 오차 {eu:.1f}%")
        elif verbose:
            print(f"  [EST] 혼합크기(cv={base.size_cv:.2f})+크기독립 손실30% → "
                  f"보정 오차 {eu:.2f}% OK")

        # tail-drop(크기 상관) → 편향이 생기지만 플래그가 서야 한다
        ds = os.path.join(td, "mixed_sat.pcap")
        apply_to_pcap(mixed, ds, ImpairmentConfig(
            capacity_mbps=truth_mixed / 1e6 * 0.55, buffer_kb=32.0, seed=23))
        fs = estimate_from_pcap(ds).flows[0]
        if not fs.size_bias_risk:
            ok = False
            print("  [EST] 크기상관 손실 위험을 표시하지 않음(조용히 틀린 값을 냄)")
        elif verbose:
            es = abs(fs.corrected_bps - truth_mixed) / truth_mixed * 100
            el = abs(fs.corrected_local_bps - truth_mixed) / truth_mixed * 100
            print(f"  [EST] tail-drop+혼합크기: 보정 오차 전역 {es:.1f}% / "
                  f"국소 {el:.1f}% — size_bias_risk 플래그 ON OK")
        # 균일 크기에서는 플래그가 서면 안 된다(거짓 경보)
        du2 = os.path.join(td, "uni_sat.pcap")
        apply_to_pcap(src, du2, ImpairmentConfig(loss_rate=0.3, seed=23))
        if estimate_from_pcap(du2).flows[0].size_bias_risk:
            ok = False
            print("  [EST] 균일 크기인데 편향 위험을 표시(거짓 경보)")

        # 손실 + 중복 동시
        d4 = os.path.join(td, "both.pcap")
        st4 = apply_to_pcap(src, d4, ImpairmentConfig(loss_rate=0.3, duplicate_rate=0.2,
                                                     seed=19))
        e4 = estimate_from_pcap(d4)
        f4 = e4.flows[0]
        err = abs(f4.corrected_bps - truth_bps) / truth_bps * 100
        if err > 8.0:
            ok = False
            print(f"  [EST] 손실+중복 동시 보정 오차 {err:.1f}%")
        elif verbose:
            print(f"  [EST] 손실30%+중복20% 동시 → 보정 오차 {err:.2f}% OK")
    return ok


if __name__ == "__main__":
    print("ESTIMATOR selftest:", "PASS" if selftest(verbose=True) else "FAIL")
