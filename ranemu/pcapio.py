#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.pcapio — 경량 pcap 읽기/쓰기 (libpcap 클래식 포맷).

왜 직접 쓰는가
==============
정답 캡처(ground-truth capture)를 만들려면 **에뮬레이터가 실제로 송신한 바로 그 패킷을,
실제 송신 시각과 함께** 기록해야 한다. 커널 캡처(tcpdump)는 그 자체가 손실·타임스탬프
합침을 겪는 대상이므로 정답이 될 수 없다. 여기서 기록한 pcap 이 실험의 기준선이다.

scapy 로도 쓸 수 있지만 패킷당 수십 μs 가 들어 1 Gb/s 송신 경로를 그대로 망가뜨린다.
이 모듈은 struct 만으로 패킷당 ~1 μs 에 기록한다.

포맷 (libpcap):
    글로벌 헤더 24B: magic(4) ver_major(2) ver_minor(2) thiszone(4) sigfigs(4)
                     snaplen(4) network(4)
    레코드 헤더 16B: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
"""
from __future__ import annotations

import os
import struct
from typing import Iterator, Optional, Tuple

PCAP_MAGIC = 0xA1B2C3D4          # 마이크로초 해상도, 네이티브 엔디안
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101

_GLOBAL = struct.Struct("<IHHiIII")
_REC = struct.Struct("<IIII")

#: dpi_engine 은 외부 UDP 2152 로 GTP-U 를 식별한다(dpi_engine.GTP_U_PORT).
GTPU_PORT = 2152


class PcapWriter:
    """클래식 pcap 기록기."""

    __slots__ = ("_fh", "snaplen", "linktype", "count", "bytes")

    def __init__(self, path: str, linktype: int = LINKTYPE_ETHERNET,
                 snaplen: int = 262144, buffering: int = 1 << 20):
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._fh = open(path, "wb", buffering=buffering)
        self.snaplen = snaplen
        self.linktype = linktype
        self.count = 0
        self.bytes = 0
        self._fh.write(_GLOBAL.pack(PCAP_MAGIC, 2, 4, 0, 0, snaplen, linktype))

    def write(self, ts: float, data: bytes, orig_len: Optional[int] = None) -> None:
        """패킷 하나 기록. orig_len 을 주면 절단(snaplen) 캡처를 재현할 수 있다."""
        sec = int(ts)
        usec = int(round((ts - sec) * 1_000_000))
        if usec >= 1_000_000:                      # 반올림으로 1초를 넘긴 경우
            sec += 1
            usec -= 1_000_000
        n = len(data)
        self._fh.write(_REC.pack(sec, usec, n, orig_len if orig_len is not None else n))
        self._fh.write(data)
        self.count += 1
        self.bytes += n

    def close(self) -> None:
        if self._fh and not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class PcapReader:
    """클래식 pcap 판독기. (ts, data, orig_len) 을 순회한다."""

    __slots__ = ("_fh", "linktype", "snaplen", "_swap", "_rec")

    def __init__(self, path: str):
        self._fh = open(path, "rb")
        head = self._fh.read(24)
        if len(head) < 24:
            raise ValueError(f"pcap 헤더가 짧음: {path}")
        magic = struct.unpack("<I", head[:4])[0]
        if magic == PCAP_MAGIC:
            self._swap = False
            fmt = "<IHHiIII"
        elif magic == 0xD4C3B2A1:
            self._swap = True
            fmt = ">IHHiIII"
        else:
            raise ValueError(f"지원하지 않는 pcap magic 0x{magic:08x} "
                             f"(pcapng 는 미지원)")
        _m, _vj, _vn, _tz, _sf, self.snaplen, self.linktype = struct.unpack(fmt, head)
        self._rec = struct.Struct(">IIII" if self._swap else "<IIII")

    def __iter__(self) -> Iterator[Tuple[float, bytes, int]]:
        read = self._fh.read
        unpack = self._rec.unpack
        while True:
            hdr = read(16)
            if len(hdr) < 16:
                return
            sec, usec, incl, orig = unpack(hdr)
            data = read(incl)
            if len(data) < incl:
                return                              # 잘린 파일: 읽은 데까지
            yield sec + usec / 1_000_000.0, data, orig

    def close(self) -> None:
        if self._fh and not self._fh.closed:
            self._fh.close()

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


# ─────────────────────────────────────────────────────────────────────────────
# 프레이밍 — GTP-U 페이로드를 Ethernet/IP/UDP 로 감싼다
# ─────────────────────────────────────────────────────────────────────────────
_ETH_HDR = struct.Struct(">6s6sH")


def _checksum16(data: bytes) -> int:
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


class GtpuFramer:
    """GTP-U 페이로드를 Ethernet/IPv4/UDP(2152) 프레임으로 감싼다.

    외부 IP 헤더는 고정이므로 템플릿을 캐시하고 길이/ID/체크섬만 갱신한다
    (전체 재계산은 1 Gb/s 경로에서 병목이 된다).
    """

    __slots__ = ("_eth", "_src", "_dst", "_sport", "_dport", "_ident")

    def __init__(self, src_ip: str, dst_ip: str,
                 src_mac: bytes = b"\x02\x00\x00\x00\x00\x01",
                 dst_mac: bytes = b"\x02\x00\x00\x00\x00\x02",
                 sport: int = GTPU_PORT, dport: int = GTPU_PORT):
        import socket
        self._eth = _ETH_HDR.pack(dst_mac, src_mac, 0x0800)
        self._src = socket.inet_aton(src_ip)
        self._dst = socket.inet_aton(dst_ip)
        self._sport = sport
        self._dport = dport
        self._ident = 0

    def frame(self, gtpu_payload: bytes) -> bytes:
        """GTP-U 바이트열 → 완성된 Ethernet 프레임."""
        self._ident = (self._ident + 1) & 0xFFFF
        udp_len = 8 + len(gtpu_payload)
        # UDP 체크섬 0 = '계산하지 않음'(IPv4 에서 합법). 캡처 분석기는 이를 허용한다.
        udp = struct.pack(">HHHH", self._sport, self._dport, udp_len, 0) + gtpu_payload
        total = 20 + udp_len
        ip_nock = struct.pack(">BBHHHBBH", 0x45, 0, total, self._ident, 0, 64, 17, 0) \
            + self._src + self._dst
        ck = _checksum16(ip_nock)
        ip = struct.pack(">BBHHHBBH", 0x45, 0, total, self._ident, 0, 64, 17, ck) \
            + self._src + self._dst
        return self._eth + ip + udp


def selftest(verbose: bool = False) -> bool:  # noqa: C901
    import tempfile
    ok = True

    with tempfile.TemporaryDirectory(prefix="ranemu-pcap-") as td:
        path = os.path.join(td, "t.pcap")

        # (1) 쓰기 → 읽기 왕복(타임스탬프 정밀도 포함)
        pkts = [(1700000000.000001, b"A" * 60),
                (1700000000.123456, b"B" * 100),
                (1700000001.999999, b"C" * 1400)]
        with PcapWriter(path) as w:
            for ts, d in pkts:
                w.write(ts, d)
            if w.count != 3:
                ok = False
                print("  [PCAPIO] 기록 수 불일치")
        got = list(PcapReader(path))
        if len(got) != 3:
            ok = False
            print(f"  [PCAPIO] 읽은 패킷 수 {len(got)} != 3")
        else:
            for (ets, ed), (gts, gd, golen) in zip(pkts, got):
                if abs(gts - ets) > 1.5e-6 or gd != ed or golen != len(ed):
                    ok = False
                    print(f"  [PCAPIO] 왕복 불일치: {gts} vs {ets}, len {len(gd)}")
                    break
            else:
                if verbose:
                    print("  [PCAPIO] 쓰기→읽기 왕복(μs 정밀도) OK")

        # (2) 링크타입 보존
        r = PcapReader(path)
        if r.linktype != LINKTYPE_ETHERNET:
            ok = False
            print(f"  [PCAPIO] linktype {r.linktype} != 1")
        r.close()

        # (3) 절단 캡처(snaplen) 표현: incl_len < orig_len
        path2 = os.path.join(td, "s.pcap")
        with PcapWriter(path2, snaplen=128) as w:
            w.write(1.0, b"X" * 128, orig_len=1500)
        (ts, data, orig), = list(PcapReader(path2))
        if len(data) != 128 or orig != 1500:
            ok = False
            print(f"  [PCAPIO] 절단 표현 실패: incl={len(data)} orig={orig}")
        elif verbose:
            print("  [PCAPIO] snaplen 절단(incl<orig) 표현 OK")

        # (4) GTP-U 프레이밍이 dpkt 로 파싱되고 외부 포트가 2152 인가
        from .transport.gtpu import build_ipv4_udp, encode, MSG_GPDU
        inner = build_ipv4_udp("10.45.0.7", "8.8.8.8", 40000, 33434, bytes(1372))
        gtp = encode(MSG_GPDU, 0x1234, inner, qfi=1)
        fr = GtpuFramer("10.1.16.52", "10.1.16.60")
        frame = fr.frame(gtp)
        path3 = os.path.join(td, "g.pcap")
        with PcapWriter(path3) as w:
            w.write(1700000000.0, frame)
        try:
            import dpkt
            with open(path3, "rb") as fh:
                rd = dpkt.pcap.Reader(fh)
                if rd.datalink() != 1:
                    ok = False
                    print("  [PCAPIO] dpkt 가 Ethernet 으로 인식하지 못함")
                for _ts, buf in rd:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    udp = ip.data
                    if udp.dport != GTPU_PORT or udp.sport != GTPU_PORT:
                        ok = False
                        print(f"  [PCAPIO] 외부 UDP 포트 {udp.sport}/{udp.dport} != 2152")
                    if bytes(udp.data) != gtp:
                        ok = False
                        print("  [PCAPIO] GTP-U 페이로드 손상")
                    if _checksum16(bytes(ip)[:20]) != 0:
                        ok = False
                        print("  [PCAPIO] 외부 IP 체크섬 무효")
                    break
            if verbose and ok:
                print("  [PCAPIO] GTP-U 프레이밍 dpkt 파싱 + 포트 2152 + 체크섬 OK")
        except ImportError:
            print("  [PCAPIO] dpkt 없음 — dpi_engine 연동 검증 생략")

        # (5) 대량 기록 성능(1 Gb/s 경로를 막지 않아야 한다)
        import time
        path4 = os.path.join(td, "perf.pcap")
        blob = frame
        t0 = time.perf_counter()
        with PcapWriter(path4) as w:
            for i in range(50000):
                w.write(1700000000.0 + i * 1e-5, blob)
        dt = time.perf_counter() - t0
        per_pkt_us = dt / 50000 * 1e6
        if per_pkt_us > 20.0:
            ok = False
            print(f"  [PCAPIO] 기록이 너무 느림: {per_pkt_us:.2f} μs/패킷")
        elif verbose:
            print(f"  [PCAPIO] 기록 성능 {per_pkt_us:.2f} μs/패킷 "
                  f"({50000/dt/1000:.0f} kpps 상당) OK")
    return ok


if __name__ == "__main__":
    print("PCAPIO selftest:", "PASS" if selftest(verbose=True) else "FAIL")
