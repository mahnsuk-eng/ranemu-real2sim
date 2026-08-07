#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.capture — 코어측 수집(SPAN 미러) 오케스트레이션.

기존 파이프라인을 그대로 쓴다
============================
`~/5ga_solution/network_agent.py` 는 이미 이 테스트베드에 맞춰진 캡처/분석 경로를 갖고
있다(VLAN 태그 GTP-U 필터, N2 풀 스냅렌, dpi_engine + ngap_agent 조인). 여기서 그것을
다시 구현하지 않고 **가져다 쓴다**. 그래야 ranemu 로 주입한 트래픽이 평소 측정과
'같은 자'로 재어진다 — 그것이 시험검증의 전제다.

network_agent 를 못 불러오면 tcpdump 를 직접 띄우는 축소 경로로 내려간다.

주의(메모리에 기록된 이 테스트베드의 함정)
    · N2(SCTP/38412)와 N3(GTP-U/2152)가 **같은 인터페이스 ens15f0** 로 들어온다.
    · GTP-U 는 802.1Q VLAN 태그가 붙어 있어 BPF 를 `vlan` 그룹까지 써야 한다.
    · N2 캡처는 **풀 스냅렌(-s0)** 이어야 NGAP IE 파싱이 된다.
    · ens15f2 는 링크다운이므로 옛 'N3 전용 탭' 전제는 성립하지 않는다.
  이 모든 처리는 network_agent 쪽에 이미 반영되어 있다.
"""
from __future__ import annotations

import importlib
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from .util import get_logger

log = get_logger("ranemu.capture")

#: network_agent / dpi_engine / ngap_agent 가 있는 디렉터리
SOLUTION_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_network_agent():
    """network_agent 모듈을 로드(실패하면 None)."""
    if SOLUTION_DIR not in sys.path:
        sys.path.insert(0, SOLUTION_DIR)
    try:
        return importlib.import_module("network_agent")
    except Exception as e:  # noqa: BLE001
        log.warning("network_agent 로드 실패(%s) — 축소 캡처 경로 사용", e)
        return None


@dataclass
class CaptureSession:
    """진행 중인 코어측 캡처."""
    out_base: str
    n3_pcap: str
    n2_pcap: str
    handles: Any = None                  # network_agent captures 또는 Popen 목록
    mode: str = "network_agent"          # network_agent | tcpdump | none
    started_at: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.mode != "none"


def start(out_dir: str, name: str, *, n3_interface: Optional[str] = None,
          n2_interface: Optional[str] = None, snaplen: int = 256,
          tcpdump_bin: str = "/usr/bin/tcpdump") -> CaptureSession:
    """코어 미러에서 N3(GTP-U) + N2(NGAP) 캡처를 시작."""
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, name)
    sess = CaptureSession(out_base=base, n3_pcap=f"{base}.n3.pcap",
                          n2_pcap=f"{base}.n2.pcap", started_at=time.time())

    na = _load_network_agent()
    if na is not None and hasattr(na, "start_measurement_capture"):
        try:
            captures, err = na.start_measurement_capture(
                base, n3_interface=n3_interface, n2_interface=n2_interface,
                snaplen=snaplen, tcpdump_bin=tcpdump_bin)
        except Exception as e:  # noqa: BLE001
            captures, err = None, str(e)
        if captures:
            sess.handles = captures
            sess.mode = "network_agent"
            log.info("코어측 캡처 시작(network_agent): N3=%s N2=%s",
                     sess.n3_pcap, sess.n2_pcap)
            return sess
        sess.error = err or "start_measurement_capture 실패"
        log.warning("network_agent 캡처 실패(%s) — tcpdump 직접 실행 시도", sess.error)

    # 축소 경로: tcpdump 직접
    if not shutil.which(tcpdump_bin) and not os.path.exists(tcpdump_bin):
        sess.mode = "none"
        sess.error = f"tcpdump 없음({tcpdump_bin})"
        return sess
    iface3 = n3_interface or os.environ.get("RANEMU_N3_IFACE", "any")
    iface2 = n2_interface or os.environ.get("RANEMU_N2_IFACE", iface3)
    # VLAN 태그를 고려한 BPF (bare 항을 먼저, 그다음 vlan 그룹 — `not vlan` 은 절대 금지)
    f3 = "udp port 2152 or (vlan and udp port 2152)"
    f2 = "sctp port 38412 or (vlan and sctp port 38412)"
    procs = []
    try:
        for iface, path, bpf, snap in ((iface3, sess.n3_pcap, f3, snaplen),
                                       (iface2, sess.n2_pcap, f2, 0)):
            cmd = ["sudo", "-n", tcpdump_bin, "-i", iface, "-w", path,
                   "-s", str(snap), "-B", "65536", "-U", bpf]
            procs.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.PIPE,
                                          start_new_session=True))
        sess.handles = procs
        sess.mode = "tcpdump"
        sess.error = None
        log.info("코어측 캡처 시작(tcpdump): %s / %s", iface3, iface2)
    except Exception as e:  # noqa: BLE001
        for p in procs:
            p.kill()
        sess.mode = "none"
        sess.error = f"tcpdump 기동 실패: {e}"
    return sess


def stop(sess: CaptureSession) -> Dict[str, Any]:
    """캡처를 멈추고 산출 파일 정보를 반환."""
    if sess.mode == "network_agent":
        na = _load_network_agent()
        if na is not None and hasattr(na, "stop_capture_procs"):
            try:
                na.stop_capture_procs(sess.handles, merged_path=None)
            except Exception as e:  # noqa: BLE001
                log.warning("캡처 종료 중 오류(무시): %s", e)
    elif sess.mode == "tcpdump":
        for p in (sess.handles or []):
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    p.kill()
                except Exception:  # noqa: BLE001
                    pass
    time.sleep(0.4)                       # 파일 flush 여유
    out = {"mode": sess.mode, "n3_pcap": sess.n3_pcap, "n2_pcap": sess.n2_pcap,
           "error": sess.error}
    for key, path in (("n3_bytes", sess.n3_pcap), ("n2_bytes", sess.n2_pcap)):
        out[key] = os.path.getsize(path) if os.path.exists(path) else 0
    log.info("코어측 캡처 종료: N3 %d바이트, N2 %d바이트", out["n3_bytes"], out["n2_bytes"])
    return out


def analyze(n3_pcap: str, n2_pcap: str, link_mbps: float = 1000.0) -> Dict[str, Any]:
    """dpi_engine(N3) + ngap_agent(N2) 로 단말별 측정 결과를 만든다."""
    na = _load_network_agent()
    if na is not None and hasattr(na, "analyze_measurement"):
        try:
            return na.analyze_measurement(n3_pcap, n2_pcap, link_mbps=link_mbps)
        except Exception as e:  # noqa: BLE001
            log.warning("analyze_measurement 실패(%s) — 직접 분석 시도", e)

    # 축소 경로: dpi_engine / ngap_agent 를 직접 호출
    if SOLUTION_DIR not in sys.path:
        sys.path.insert(0, SOLUTION_DIR)
    try:
        dpi = importlib.import_module("dpi_engine")
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"dpi_engine 없음: {e}", "ues": []}
    if not (n3_pcap and os.path.exists(n3_pcap)):
        return {"ok": False, "error": f"N3 pcap 없음: {n3_pcap}", "ues": []}
    res = dpi.analyze_pcap(n3_pcap, dedup=True, link_mbps=link_mbps)
    ues = (res.get("summary") or {}).get("by_ue") or []
    ngap_info: Dict[str, Any] = {}
    if n2_pcap and os.path.exists(n2_pcap):
        try:
            ng = importlib.import_module("ngap_agent")
            identities = ng.extract_identities(n2_pcap)
            matched = ng.enrich_by_ue(ues, identities)
            ngap_info = {"ue_count": len(identities.get("ues", [])), "matched": matched}
        except Exception as e:  # noqa: BLE001
            ngap_info = {"error": str(e)}
    return {"ok": True, "ues": ues, "meta": res.get("meta", {}), "ngap": ngap_info}


def selftest(verbose: bool = False) -> bool:
    """캡처 계층은 권한/하드웨어에 의존하므로 '연결성' 만 검증한다."""
    ok = True

    # (1) 기존 모듈을 실제로 불러올 수 있는가 (이 통합이 이 모듈의 존재 이유)
    na = _load_network_agent()
    if na is None:
        print("  [CAPTURE] network_agent 로드 실패 — 축소 경로만 사용 가능")
    else:
        missing = [f for f in ("start_measurement_capture", "stop_capture_procs",
                               "analyze_measurement", "build_capture_filter")
                   if not hasattr(na, f)]
        if missing:
            ok = False
            print(f"  [CAPTURE] network_agent 에 필요한 함수 없음: {missing}")
        elif verbose:
            print("  [CAPTURE] network_agent 연동 함수 4종 확인 OK")

    # (2) dpi_engine / ngap_agent 가용성
    if SOLUTION_DIR not in sys.path:
        sys.path.insert(0, SOLUTION_DIR)
    for mod, fn in (("dpi_engine", "analyze_pcap"), ("ngap_agent", "extract_identities")):
        try:
            m = importlib.import_module(mod)
            if not hasattr(m, fn):
                ok = False
                print(f"  [CAPTURE] {mod}.{fn} 없음")
            elif verbose:
                print(f"  [CAPTURE] {mod}.{fn} 확인 OK")
        except Exception as e:  # noqa: BLE001
            print(f"  [CAPTURE] {mod} 로드 실패({e}) — 코어측 분석 불가")

    # (3) 존재하지 않는 pcap 은 조용히 실패하지 말고 오류를 보고해야 한다
    res = analyze("/nonexistent/x.n3.pcap", "/nonexistent/x.n2.pcap")
    if res.get("ok"):
        ok = False
        print("  [CAPTURE] 없는 pcap 을 성공으로 보고함")
    elif verbose:
        print("  [CAPTURE] 없는 pcap → 오류 보고 OK")

    # (4) 캡처 세션 객체의 경로 규약(network_agent 와 동일해야 조인이 된다)
    sess = CaptureSession(out_base="/tmp/x", n3_pcap="/tmp/x.n3.pcap",
                          n2_pcap="/tmp/x.n2.pcap")
    if not (sess.n3_pcap.endswith(".n3.pcap") and sess.n2_pcap.endswith(".n2.pcap")):
        ok = False
        print("  [CAPTURE] pcap 경로 규약 불일치")
    return ok


if __name__ == "__main__":
    print("CAPTURE selftest:", "PASS" if selftest(verbose=True) else "FAIL")
