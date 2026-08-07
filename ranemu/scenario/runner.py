#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.scenario.runner — 시나리오를 실제 실행으로 바꾸는 계층.

역할은 셋이다.

  1. **컴파일** — `ServiceScenario` 를 기존 `RunConfig` 로 낮춘다. gnb 는 시나리오라는
     개념을 모른 채로 남는다(그래야 기존 경로가 안 바뀐다).
  2. **훅** — gnb 가 부르는 네 지점(`stamp_template`/`on_dl_payload`/`on_tick`/
     `result_fragment`)을 구현해 인밴드 계측을 얹는다.
  3. **phase 제어** — 시각이 되면 쉐이퍼·트래픽을 재조정하고, 흐름별 평가창을
     갱신한다.

설계상 중요한 점: 훅이 없으면(`Gnb.hooks is None`) gnb 는 예전과 **바이트 단위로
동일하게** 동작한다. 계측을 얹기 위해 관측 대상을 바꾸지 않는다는 원칙을 코드 구조로
강제한 것이다.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from ..config import RunConfig, loads as load_run_config
from ..util import get_logger
from . import stamp as st
from .model import Phase, ServiceScenario, UePopulation

log = get_logger("ranemu.scenario.runner")

#: 계측기 자신의 대기가 판정 임계에서 차지해도 되는 최대 비율.
#: 20% 는 임의 선택이 아니라, 이 값을 넘으면 남은 여유가 측정 불확도보다
#: 작아져 PASS/FAIL 어느 쪽도 임계 판별을 지지하지 못하기 때문이다.
INSTRUMENT_SHARE_MAX = 0.20

#: 왕복지연 히스토그램으로 판정할 수 있는 metric. 이 목록 밖의 metric 에
#: 지연 분포를 갖다 대면 서로 다른 양을 비교하게 되므로 판정하지 않는다.
_RTT_METRICS = {"rtt_ms", "rtt_net_ms", "rtt_wire_ms", "pdv_ms"}

#: 커널 UDP 루프백 왕복의 실측 바닥(EVIDENCE §1). 참조 코어 구성에서 이보다 큰
#: 상행 편도지연은 코어가 아니라 계측 설비의 지체로 본다.
SOCKET_FLOOR_MS = 0.004


# ─────────────────────────────────────────────────────────────────────────────
# 1. 컴파일
# ─────────────────────────────────────────────────────────────────────────────
def compile_run_config(sc: ServiceScenario, *, core: Dict[str, Any],
                       gnb: Dict[str, Any], security: Dict[str, Any],
                       out_dir: str = "/tmp/ranemu_scenarios",
                       downlink_mode: str = "loopback",
                       capture: Optional[Dict[str, Any]] = None) -> RunConfig:
    """시나리오 → 기존 RunConfig.

    population 이 `ue_groups` 로 낮춰지고, phase 총합이 트래픽 지속시간이 된다.
    population 이름을 그룹 이름으로 그대로 쓰므로, 실행 결과에서 `ue.group` 으로
    다시 population 을 복원할 수 있다.
    """
    groups: List[Dict[str, Any]] = []
    inflated: List[Dict[str, Any]] = []
    for i, p in enumerate(sc.populations):
        g: Dict[str, Any] = {
            "name": p.name,
            "count": p.count,
            "imsi_start": p.imsi_start or f"45005{i:04d}0000001"[:15],
            "features": list(p.features),
            "feature_params": dict(p.feature_params),
            "dnn": p.dnn,
            "sst": p.sst,
            "ramp_seconds": p.ramp_seconds,
        }
        if p.sd:
            g["sd"] = p.sd
        tr = dict(p.traffic or {})
        if "pattern" in tr:
            g["traffic"] = tr.pop("pattern")

        # 소형 메시지 팽창(§3.6 정책 a).
        # TS 22.104 계열 제어 메시지는 40–250 B 인데 48 B 스탬프는 IP+UDP 포함
        # 최소 76 B 를 요구한다. 64 B 메시지는 스탬프를 담을 수 없어 **한 패킷도
        # 계측되지 않는다** — 조용히 0 표본이 되는 대신, 최소 크기로 키우고
        # 키웠다는 사실을 기록한다. 부하가 그만큼 늘어나므로 숨기면 안 된다.
        size = tr.get("packet_size")
        if p.stamp and p.stamp_policy == "inflate" and size is not None:
            if int(size) < st.MIN_PACKET:
                inflated.append({"population": p.name,
                                 "configured_bytes": int(size),
                                 "used_bytes": st.MIN_PACKET,
                                 "load_increase_pct": round(
                                     (st.MIN_PACKET / int(size) - 1) * 100, 1)})
                tr["packet_size"] = st.MIN_PACKET
        if tr:
            g["traffic_params"] = tr
        groups.append(g)

    duration = sc.total_duration_s()
    cfg = load_run_config({
        "name": f"scenario-{sc.id}",
        "seed": sc.seed,
        "out_dir": out_dir,
        "core": core,
        "gnb": gnb,
        "security": security,
        "ue_groups": groups,
        "traffic": {
            "duration": duration,
            "downlink_mode": downlink_mode,
            "packet_size": 1400,
            # 스탬프가 손실 추정의 1차 기준이지만, 기존 GTP-U 시퀀스 카운터도 켜
            # 두면 캡처 기반 교차확인이 가능하다(추가 비용 거의 없음).
            "gtpu_sequence": True,
            "offered_ul_mbps": 500.0,
            "offered_dl_mbps": 1000.0,
        },
        "capture": capture or {"enabled": False},
    })
    # 팽창 사실을 설정에 붙여 둔다(훅이 verdict 메타데이터로 옮긴다).
    setattr(cfg, "_scn_inflated", inflated)
    if inflated:
        for it in inflated:
            log.warning("계측을 위해 %s 의 패킷을 %d→%d B 로 키움 (부하 +%.1f%%)",
                        it["population"], it["configured_bytes"],
                        it["used_bytes"], it["load_increase_pct"])
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
# 2. 훅
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class _FlowState:
    """단말 하나(=흐름 하나)의 송신 상태."""
    flow_id: int
    population: str
    ledger: st.FlowLedger
    seq: int = 0
    stamped: int = 0
    skipped: int = 0
    inflated: bool = False
    #: 에뮬레이터 자신이 붙인 대기(µs) — 계측기가 병목인지 판단하는 진단값
    hold_us_sum: int = 0
    hold_us_max: int = 0
    hold_n: int = 0
    #: 공유 클럭일 때만 유효한 편도 분해. owd_dl 이 크면 **수신 경로**(gnb 의
    #: _pump_downlink 적체)가 지연을 만든 것이므로, 그 판정은 코어가 아니라
    #: 계측기에 대한 것이 된다. 송신측 access_hold 만으로는 이걸 못 잡는다.
    owd_ul: st.LogHistogram = field(default_factory=st.LogHistogram)
    owd_dl: st.LogHistogram = field(default_factory=st.LogHistogram)
    turn: st.LogHistogram = field(default_factory=st.LogHistogram)


class ScenarioHooks:
    """gnb 에 꽂히는 계측·제어 훅.

    gnb 는 이 객체의 네 메서드만 안다. 시나리오·판정은 전혀 모른다.
    """

    def __init__(self, sc: ServiceScenario, *, clock_domain: str = "shared"):
        self.sc = sc
        self.clock_domain = clock_domain
        self.flows: Dict[int, _FlowState] = {}
        self.pop_of: Dict[str, UePopulation] = {p.name: p for p in sc.populations}
        # phase 진행
        self.phase_idx = -1
        self._phase_deadline = 0.0
        self._t0_mono = 0.0
        self._t0_ns = 0
        self.phase_marks: List[Dict[str, Any]] = []
        self._last_expire = 0.0
        self.unstamped_rx = 0
        self.late_stamp_rx = 0
        #: 계측을 위해 키운 패킷 기록(§3.6) — 판정 보고서에 그대로 실린다
        self.inflated: List[Dict[str, Any]] = []
        self._gnb: Any = None
        #: 판정 대상 모집단이 다 붙기 전에 평가창을 열면, 첫 phase 는 코어가 아니라
        #: **등록·세션수립 과도상태**를 재게 된다(실측: baseline p99 15.8 ms 가
        #: loaded 1.9 ms 보다 나쁘게 나왔다). 그래서 창을 여는 것을 미룬다.
        self._expected_sut_flows = sum(
            p.count for p in sc.populations if p.role == "sut" and p.stamp)
        self._setup_hold_s = 0.0      # 실제로 얼마나 미뤘는지 — 결과에 싣는다
        self._setup_capped = False    # 다 붙기 전에 상한으로 열었는가
        self._first_tick = 0.0

    # ── gnb 가 자신을 알려 준다(쉐이퍼 재조정에 필요) ─────────────────────
    def attach(self, gnb: Any) -> None:
        self._gnb = gnb
        self.inflated = list(getattr(getattr(gnb, "cfg", None),
                                     "_scn_inflated", []) or [])

    # ── 흐름 등록 ────────────────────────────────────────────────────────
    def _flow(self, ue: Any) -> _FlowState:
        fid = ue.ran_ue_ngap_id & 0xFFFF
        fs = self.flows.get(fid)
        if fs is None:
            pop = self.pop_of.get(ue.group)
            pdb = self._pdb_for(ue.group)
            fs = _FlowState(
                flow_id=fid, population=ue.group,
                ledger=st.FlowLedger(fid, pdb_ms=pdb,
                                     label=f"{ue.group}/{ue.imsi}"))
            # 이미 지나간 phase 들의 창도 등록해 둔다(늦게 활성화된 단말 대비)
            for pid, mark in enumerate(self.phase_marks):
                fs.ledger.set_phase_window(pid, mark["start_ns"], mark["end_ns"],
                                           mark["warmup_s"])
            self.flows[fid] = fs
        return fs

    def _pdb_for(self, population: str) -> Optional[float]:
        """이 모집단에 걸린 목표 중 가장 엄격한 PDB — 원장의 성공 판정 기준."""
        best: Optional[float] = None
        for t in self.sc.targets:
            if t.applies_to not in ("*", population):
                continue
            v = getattr(t, "pdb_ms", None)
            if v is None and getattr(t, "kind", "") == "quantile" \
                    and t.metric in _RTT_METRICS:
                if t.unit == "ms":
                    v = t.value
                elif t.unit == "s":
                    v = t.value * 1000.0
            if v is not None:
                best = v if best is None else min(best, float(v))
        return best

    # ── (1) 송신 직전: 스탬프 ────────────────────────────────────────────
    def stamp_template(self, ue: Any, tmpl: Any, now: float,
                       sched: Optional[float] = None) -> None:
        pop = self.pop_of.get(ue.group)
        if pop is not None and not pop.stamp:
            return
        fs = self._flow(ue)
        # 표본 스탬프 정책: 일부만 찍어 소형 메시지 팽창을 피한다
        if pop is not None and pop.stamp_policy == "sample" and pop.stamp_sample < 1.0:
            period = max(1, int(round(1.0 / pop.stamp_sample)))
            if (fs.seq % period) != 0:
                fs.seq += 1
                fs.skipped += 1
                return
        if len(tmpl) < 28 + st.STAMP_LEN:
            # 패킷이 스탬프보다 작다 — 조용히 건너뛰지 않고 한 번만 경고한다.
            if not fs.inflated:
                fs.inflated = True
                log.warning("%s: 패킷이 스탬프(%dB)보다 작아 계측 불가 — "
                            "packet_size 를 %dB 이상으로",
                            ue.group, st.STAMP_LEN, 28 + st.STAMP_LEN)
            return
        t1 = time.monotonic_ns()
        # access_hold = 실제 송신 − 생성 예정 시각. 쉐이퍼의 의도된 대기와
        # 이벤트 루프의 지체가 섞여 있으므로, 이것이 왕복지연에 비해 크면
        # '코어를 쟀다' 고 말할 수 없다(§ 타당성 진단).
        hold_us = 0
        if sched is not None and now > sched:
            hold_us = min(0xFFFFFFFF, int((now - sched) * 1e6))
            fs.hold_us_sum += hold_us
            fs.hold_us_max = max(fs.hold_us_max, hold_us)
            fs.hold_n += 1
        tmpl.patch_payload(0, st.pack_stamp(
            fs.flow_id, fs.seq, t1, phase_id=max(0, self.phase_idx),
            flags=st.FLAG_REPLY_REQ, gen_delta_us=hold_us))
        fs.ledger.on_send(fs.seq, t1, phase_id=max(0, self.phase_idx))
        fs.seq += 1
        fs.stamped += 1

    # ── (2) 수신: 해소 ───────────────────────────────────────────────────
    def on_dl_payload(self, ue: Any, payload: bytes, now: float) -> None:
        s = st.decode_from_inner_ip(payload)
        if s is None:
            self.unstamped_rx += 1
            return
        fs = self.flows.get(s.flow_id)
        if fs is None:
            self.late_stamp_rx += 1
            return
        t4 = time.monotonic_ns()
        # 편도 분해는 회신자와 시계를 공유할 때만 의미가 있다(§3.2).
        # unsync 에서 t2/t3 를 t1/t4 와 빼는 것은 서로 다른 epoch 을 빼는 것이라
        # 숫자는 나오지만 물리적 의미가 없다 — 그래서 조건을 건다.
        if s.t2t3_valid and self.clock_domain in ("shared", "ptp"):
            ul = (s.t2_ns - s.t1_ns) / 1e6
            dl = (t4 - s.t3_ns) / 1e6
            tn = (s.t3_ns - s.t2_ns) / 1e6
            if ul >= 0:
                fs.owd_ul.add(ul)
            if dl >= 0:
                fs.owd_dl.add(dl)
            if tn >= 0:
                fs.turn.add(tn)
        fs.ledger.on_reply(s, t4)

    # ── (3) 주기 처리: phase 전환 + 만료 ─────────────────────────────────
    #: 세션수립을 기다리는 상한. 일부 단말이 끝내 안 붙어도 실행은 진행되어야 하고,
    #: 상한으로 열었다는 사실은 결과에 남는다.
    SETUP_HOLD_MAX_S = 20.0

    def _sut_flows_up(self) -> int:
        return sum(1 for fs in self.flows.values()
                   if (self.pop_of.get(fs.population) or
                       UePopulation()).role == "sut")

    def on_tick(self, now: float) -> None:
        if self.phase_idx < 0:
            if not self._first_tick:
                self._first_tick = now
            waited = now - self._first_tick
            ready = (self._expected_sut_flows <= 0
                     or self._sut_flows_up() >= self._expected_sut_flows)
            if not ready and waited < self.SETUP_HOLD_MAX_S:
                return                      # 아직 평가창을 열지 않는다
            self._setup_hold_s = round(waited, 3)
            self._setup_capped = not ready
            if not ready:
                log.warning("세션수립 대기 상한(%.0fs) 도달 — 판정대상 %d/%d 만 활성",
                            self.SETUP_HOLD_MAX_S, self._sut_flows_up(),
                            self._expected_sut_flows)
            elif waited > 0:
                log.info("판정대상 %d 흐름 활성 — %.2fs 대기 후 평가창 개시",
                         self._sut_flows_up(), waited)
            self._begin(0, now)
        elif self.sc.phases and now >= self._phase_deadline \
                and self.phase_idx + 1 < len(self.sc.phases):
            self._close(now)
            self._begin(self.phase_idx + 1, now)
        # 만료 확정은 비싸지 않지만 매 틱 돌 필요는 없다
        if now - self._last_expire >= 0.25:
            self._last_expire = now
            n = time.monotonic_ns()
            for fs in self.flows.values():
                fs.ledger.expire(n)
            # phase 조건은 '살아 있는 단말'에만 적용되므로, phase 시작 뒤에 붙은
            # 단말은 아무 조건도 못 받고 기본 속도로 돈다 — baseline 이 배경을 끄기로
            # 했는데도 배경이 도는 식이다. 늦게 온 단말에 현재 phase 를 다시 건다.
            if 0 <= self.phase_idx < len(self.sc.phases):
                self._apply_phase(self.sc.phases[self.phase_idx], now)

    def _begin(self, idx: int, now: float) -> None:
        self.phase_idx = idx
        ph = self.sc.phases[idx] if idx < len(self.sc.phases) else None
        dur = ph.duration_s if ph else self.sc.total_duration_s()
        self._phase_deadline = now + dur
        if not self._t0_mono:
            self._t0_mono, self._t0_ns = now, time.monotonic_ns()
        start_ns = time.monotonic_ns()
        mark = {"phase": ph.name if ph else "run", "index": idx,
                "start_ns": start_ns, "end_ns": start_ns + int(dur * 1e9),
                "warmup_s": ph.warmup_s if ph else 0.0,
                "start_s": round(now - self._t0_mono, 3), "duration_s": dur}
        self.phase_marks.append(mark)
        for fs in self.flows.values():
            fs.ledger.set_phase_window(idx, mark["start_ns"], mark["end_ns"],
                                       mark["warmup_s"])
        if ph is not None:
            self._apply_phase(ph, now)
        log.info("phase[%d] %s 시작 (%.1fs)", idx, mark["phase"], dur)

    def _close(self, now: float) -> None:
        if 0 <= self.phase_idx < len(self.phase_marks):
            self.phase_marks[self.phase_idx]["end_ns"] = time.monotonic_ns()

    def _apply_phase(self, ph: Phase, now: float) -> None:
        """phase 가 지정한 부하·손상 조건을 살아 있는 단말에 반영한다.

        손상은 **누적**되는 양이므로 같은 단말에 두 번 걸면 안 된다. 단말마다
        어느 phase 를 이미 받았는지 표시해 두고, 늦게 붙은 단말에만 다시 건다.
        """
        gnb = self._gnb
        if gnb is None:
            return
        for ue in getattr(gnb, "ues", []):
            grp = getattr(ue, "group", None)
            if grp is None:
                continue
            if getattr(ue, "_scn_phase_applied", None) == self.phase_idx:
                continue                      # 이미 이 phase 를 받았다
            setattr(ue, "_scn_phase_applied", self.phase_idx)
            # 부하 배율: 목표 속도를 곱한다(쉐이퍼 상태는 보존)
            scale = ph.load_scale.get(grp, ph.load_scale.get("*"))
            if scale is not None and getattr(ue, "ul_shaper", None) is not None:
                base = getattr(ue, "_scn_base_ul_mbps", None)
                if base is None:
                    base = ue.ul_shaper.rate_mbps
                    setattr(ue, "_scn_base_ul_mbps", base)
                ue.ul_shaper.retune(rate_mbps=base * float(scale))
            # 활성 비율
            act = ph.active_scale.get(grp, ph.active_scale.get("*"))
            if act is not None and getattr(ue, "traffic_gen", None) is not None:
                try:
                    ue.traffic_gen.set_active_ratio(float(act))
                except Exception:      # noqa: BLE001 — 생성기 구현 차이에 관대
                    pass
            # 손상: 무선 조건 열화/중단.
            # ImpairmentSpec 은 '더하는' 양(owd_add_ms/loss_add)으로 표현되므로
            # 현재값에 누적한다. 절대값으로 덮어쓰면 phase 를 거칠수록 원래
            # 무선 조건(feature 가 정한 링크버짓)이 지워진다.
            for imp in ph.impair:
                if imp.target not in ("*", grp):
                    continue
                for sh in (getattr(ue, "ul_shaper", None),
                           getattr(ue, "dl_shaper", None)):
                    if sh is None:
                        continue
                    kw: Dict[str, Any] = {}
                    if imp.owd_add_ms is not None:
                        kw["owd_ms"] = sh.delay.base_ms + imp.owd_add_ms
                    if imp.loss_add is not None:
                        kw["loss_rate"] = min(1.0, sh.loss.rate + imp.loss_add)
                    if imp.interrupt_period_s is not None:
                        kw["interrupt_period_s"] = imp.interrupt_period_s
                    if imp.interrupt_ms is not None:
                        kw["interrupt_ms"] = imp.interrupt_ms
                    if kw:
                        sh.retune(**kw)
                # SINR 변화는 링크버짓을 다시 풀어야 하므로 v1 에서는 처리하지
                # 않는다. 조용히 무시하면 시나리오가 의도한 조건이 안 걸린 채
                # 판정이 나오므로, 한 번만 경고해 표면화한다.
                if imp.sinr_delta_db is not None and not getattr(
                        self, "_warned_sinr", False):
                    self._warned_sinr = True
                    log.warning("sinr_delta_db 는 아직 반영되지 않는다 — "
                                "해당 phase 의 무선조건은 명세와 다르다")

    # ── (4) 결과 ─────────────────────────────────────────────────────────
    def result_fragment(self) -> Dict[str, Any]:
        self._close(time.monotonic())
        n = time.monotonic_ns()
        for fs in self.flows.values():
            fs.ledger.finalize(n)
        flows = []
        for fs in self.flows.values():
            d = dict(fs.ledger.as_dict())
            d.update({"population": fs.population, "stamped": fs.stamped,
                      "skipped": fs.skipped,
                      "access_hold_us": {
                          "n": fs.hold_n,
                          "mean": round(fs.hold_us_sum / fs.hold_n, 1)
                                  if fs.hold_n else 0.0,
                          "max": fs.hold_us_max},
                      "owd_ul_ms": fs.owd_ul.as_dict(),
                      "owd_dl_ms": fs.owd_dl.as_dict(),
                      "turn_ms": fs.turn.as_dict()})
            flows.append(d)
        return {
            "scenario_id": self.sc.id,
            "clock_domain": self.clock_domain,
            "phases": self.phase_marks,
            "flows": flows,
            "unstamped_rx": self.unstamped_rx,
            "late_stamp_rx": self.late_stamp_rx,
            "setup_hold_s": self._setup_hold_s,
            "setup_hold_capped": self._setup_capped,
            "sut_flows_expected": self._expected_sut_flows,
            "sut_flows_up": self._sut_flows_up(),
            "payload_inflated": self.inflated,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 3. 실행
# ─────────────────────────────────────────────────────────────────────────────
_STUB_KEY = "465b5ce8b199b49faa5f0a2ee238a6bc"
_STUB_OPC = "cd63cb71954a9f4e48a5994e37a02baf"


def run_scenario(sc: ServiceScenario, *, core_cfg: Optional[Dict[str, Any]] = None,
                 gnb_cfg: Optional[Dict[str, Any]] = None,
                 security: Optional[Dict[str, Any]] = None,
                 out_dir: str = "/tmp/ranemu_scenarios",
                 clock_domain: str = "shared") -> Dict[str, Any]:
    """시나리오를 실행하고 측정이 붙은 결과 dict 를 돌려준다.

    `core_cfg` 를 주지 않으면 참조(스텁) 코어를 띄운다. 스텁은 gnb 와 같은
    프로세스라 클럭 도메인이 `shared` 이고, 그래서 오프라인에서도 편도지연 경로가
    성립한다 — 실 코어에서는 N6 너머 reflector 가 같은 역할을 한다.
    """
    from ..gnb import Gnb

    stub = None
    if core_cfg is None:
        from ..core import StubCore
        stub = StubCore(key=bytes.fromhex(_STUB_KEY), opc=bytes.fromhex(_STUB_OPC),
                        amf_addr="127.0.0.1", amf_port=0,
                        upf_addr="127.0.0.1", upf_port=0,
                        mcc="450", mnc="05", downlink_mode="loopback")
        a, p, ua, up = stub.start()
        core_cfg = {"kind": "stub", "amf_addr": a, "amf_port": p,
                    "upf_addr": ua, "upf_port": up}
        security = security or {"key": _STUB_KEY, "opc": _STUB_OPC, "amf": "8000"}
        downlink = "loopback"
    else:
        downlink = "echo"

    gnb_cfg = gnb_cfg or {
        "name": "ranemu-scenario-gnb", "mcc": "450", "mnc": "05", "gnb_id": 1,
        "tac": 1, "n2_local_addr": "127.0.0.1", "n3_local_addr": "127.0.0.1",
        "n3_local_port": 0, "n3_advertise_addr": "127.0.0.1"}
    security = security or {"key": _STUB_KEY, "opc": _STUB_OPC, "amf": "8000"}

    cfg = compile_run_config(sc, core=core_cfg, gnb=gnb_cfg, security=security,
                             out_dir=out_dir, downlink_mode=downlink)
    errs = [e for e in cfg.validate() if "downlink_mode" not in e]
    if errs:
        if stub:
            stub.stop()
        return {"failed": f"설정 검증 실패: {errs}"}

    hooks = ScenarioHooks(sc, clock_domain=clock_domain)
    gnb = Gnb(cfg)
    gnb.hooks = hooks
    hooks.attach(gnb)
    try:
        res = gnb.run()
    finally:
        gnb.close()
        if stub:
            res_stub = stub.summary()
            stub.stop()
            res = locals().get("res", {})
            if isinstance(res, dict):
                res["core_summary"] = res_stub
    return res


# ─────────────────────────────────────────────────────────────────────────────
# 4. 측정 → 판정
# ─────────────────────────────────────────────────────────────────────────────
def evaluate(sc: ServiceScenario, hooks: "ScenarioHooks", *,
             tier: int = 2, clock_domain: Optional[str] = None,
             peer_in_process: bool = False) -> Dict[str, Any]:
    """측정 원장을 목표별 판정으로 바꾼다.

    판정 단위는 (target × phase × population) 이다. 같은 목표라도 phase 마다
    조건이 다르므로 합쳐서 보면 어느 국면에서 깨졌는지 사라진다.

    직렬화된 결과 dict 가 아니라 **살아 있는 원장**을 받는다. 직렬화본의 지연
    분포는 요약(분위수 몇 개)이라 모집단 합산 분위수를 다시 낼 수 없기 때문이다.
    """
    from . import kpi as K
    from . import verdict as V

    cd = clock_domain or hooks.clock_domain
    phases = hooks.phase_marks or [{"phase": "run", "index": 0}]
    by_pop: Dict[str, List[Any]] = {}
    for fs in hooks.flows.values():
        by_pop.setdefault(fs.population, []).append(fs.ledger)

    # ── 타당성 게이트: 계측기가 선언된 트래픽을 실제로 냈는가 ──────────────
    # access_hold = 실제 송신 − 생성 예정 시각. 이것이 판정 임계에 비해 크면
    # 우리는 선언된 시나리오를 흘리지 못한 것이고, 그러면 그 결과는 코어에 대한
    # 판정이 아니다. '측정값이 나왔으니 판정한다' 가 이 도구가 없애려는 실패다.
    hold_by_pop: Dict[str, float] = {}
    for fs in hooks.flows.values():
        if fs.hold_n:
            cur = hold_by_pop.get(fs.population, 0.0)
            hold_by_pop[fs.population] = max(
                cur, fs.hold_us_sum / fs.hold_n / 1000.0)      # ms

    # 상행 편도(owd_ul)를 통째로 '계측 부담' 으로 세면 안 된다. 실 배치에서 그
    # 구간은 바로 **측정 대상**(코어+N6)이기 때문이다. 참조 코어에서는 그것이
    # 우리 프로세스이긴 하지만, 그렇다고 자동 강등의 근거로 쓰면 유효한 측정까지
    # 죽인다(배경 0 에서 owd_ul 0.15 ms, 임계 1 ms 인데도 강등되는 것을 확인).
    #
    # 그래서 owd_ul 은 **강등이 아니라 진단**으로 남긴다. 자동으로 판별할 수 없는
    # 것을 판별하는 척하는 대신, 지배 여부를 보고하고 유효 동작범위는 실험으로
    # 특성화해 명시한다(EVIDENCE §3-E).
    dominated: Dict[str, float] = {}
    for fs in hooks.flows.values():
        if fs.owd_ul.count:
            cur = dominated.get(fs.population, 0.0)
            dominated[fs.population] = max(cur, fs.owd_ul.quantile(0.50))

    # 계측을 위해 패킷을 키운 모집단 — 그 사실은 **그 모집단의 모든 판정에**
    # 실려야 한다. 컴파일 단계에서 기록해 두고 여기서 붙이지 않으면, 보고서는
    # 선언된 크기의 트래픽을 잰 것처럼 읽힌다.
    inflated_pops = {d.get("population") for d in (hooks.inflated or [])}

    records: List[Any] = []
    for t in sc.targets:
        pops = ([t.applies_to] if t.applies_to != "*" else sorted(by_pop))
        for pop in pops:
            flows = by_pop.get(pop, [])
            for ph in phases:
                pid, pname = ph.get("index", 0), ph.get("phase", "run")
                if t.phases and "*" not in t.phases and pname not in t.phases:
                    continue
                agg = _aggregate_phase(flows, pid)
                if agg is None or agg["n"] == 0:
                    # 표본이 없다고 목표를 결과에서 지우면 안 된다. 지우면 보고서가
                    # "판정하지 않았다" 가 아니라 "그런 요구는 없었다" 처럼 읽힌다.
                    why = ("이 phase 에서 이 모집단의 평가 표본이 0 이다"
                           if agg is not None else
                           "이 모집단이 이 phase 에서 트래픽을 내지 않았다")
                    records.append(V.not_measurable_record(
                        t, tier, cd, phase=pname, population=pop,
                        reason=(why + " — 실행시간이 서비스 자체의 주기보다 "
                                "짧거나 단말이 아직 활성화되지 않았을 수 있다")))
                    continue
                # 지연·신뢰도 목표는 시간 임계를 갖는다. 계측기 자신의 대기가
                # 그 임계의 INSTRUMENT_SHARE_MAX 를 넘으면 판정하지 않는다.
                thr_ms = getattr(t, "pdb_ms", None)
                if thr_ms is None and t.kind == "quantile":
                    if t.unit == "ms":
                        thr_ms = t.value
                    elif t.unit == "s":            # 초 목표를 ms 로 환산
                        thr_ms = t.value * 1000.0
                hold = hold_by_pop.get(pop, 0.0)
                if thr_ms and hold > INSTRUMENT_SHARE_MAX * float(thr_ms):
                    records.append(V.not_measurable_record(
                        t, tier, cd, phase=pname, population=pop,
                        reason=(f"계측기 자신의 송신 대기 {hold:.3f} ms 가 임계 "
                                f"{thr_ms:g} ms 의 "
                                f"{hold / float(thr_ms) * 100:.0f}% — 선언된 "
                                f"트래픽을 내지 못했으므로 코어에 대한 판정이 "
                                f"아니다. 부하를 낮추거나 프로세스를 나눌 것")))
                    continue
                rec = _decide(t, agg, K, V, phase=pname, tier=tier,
                              clock_domain=cd)
                if rec is not None:
                    # 판정 단위는 (목표 × phase × 모집단) 인데 _decide 는 모집단을
                    # 모른다 — 여기서 채우지 않으면 모든 측정 판정이 "*" 로 남아
                    # 어느 모집단에 대한 판정인지 사라진다.
                    rec.population = pop
                    records.append(rec)

    # 팽창 표시를 모든 관련 판정에 붙인다(NOT_MEASURABLE 도 포함 — 그 목표가
    # 어떤 트래픽 위에서 판정되지 않았는지도 같은 정보다).
    for r in records:
        if getattr(r, "population", None) in inflated_pops:
            r.payload_inflated = True

    return {
        "scenario_id": sc.id,
        "tier": tier,
        "clock_domain": cd,
        "instrument": {
            "access_hold_ms_by_population": {k: round(v, 4)
                                             for k, v in hold_by_pop.items()},
            "owd_ul_p50_ms_by_population": {k: round(v, 4)
                                            for k, v in dominated.items()},
            "peer_in_process": peer_in_process,
            "note": ("참조 코어에서는 owd_ul 이 우리 프로세스 안의 지체를 포함한다. "
                     "유효 동작범위 밖에서 얻은 판정은 코어에 대한 주장으로 쓰지 "
                     "말 것 — EVIDENCE §3-E 의 배경부하 곡선 참조."),
        },
        "verdict": V.aggregate(records),
        # 구조화된 레코드(집계·그림용)와 사람이 읽는 형태를 둘 다 남긴다.
        "records": [r.as_dict() for r in records],
        "json": V.render_json(records, fingerprint={
            "scenario": sc.id, "seed": sc.seed, "tier": tier,
            "clock_domain": cd}),
        "markdown": V.render_markdown(records, title=sc.title or sc.id),
    }


def _aggregate_phase(ledgers: List[Any], pid: int) -> Optional[Dict[str, Any]]:
    """한 phase 안에서 모집단의 흐름들을 합친다.

    신뢰도는 흐름별 분자·분모를 그대로 더한다(가중평균이 아니라 합산) — 서비스
    요구는 "이 서비스의 패킷이" 예산 안에 들어오는가이지, 단말별 비율의 평균이
    아니다. 지연 분위수도 같은 이유로 표본을 합쳐서 낸다.
    """
    n = k = late = lost = cens = 0
    max_run = 0
    hist = st.LogHistogram()
    found = False
    for led in ledgers:
        ps = led.phases.get(pid)
        if ps is None:
            continue
        found = True
        n += ps.n_eval
        k += ps.k_within
        late += ps.late
        lost += ps.lost
        cens += ps.censored
        max_run = max(max_run, ps.max_failure_run)
        hist.merge(ps.hist)
    if not found:
        return None
    return {"n": n, "k": k, "late": late, "lost": lost, "censored": cens,
            "max_failure_run": max_run, "hist": hist}


def _decide(t: Any, agg: Dict[str, Any], K: Any, V: Any, *, phase: str,
            tier: int, clock_domain: str) -> Optional[Any]:
    """목표 종류별로 알맞은 추정기와 판정 함수를 고른다."""
    kind = getattr(t, "kind", "")
    if kind == "ratio":
        rel = K.ReliabilityEstimate(n=agg["n"], k=agg["k"],
                                    confidence=getattr(t, "confidence", 0.95))
        return V.decide_ratio(t, rel, phase=phase, tier=tier,
                              clock_domain=clock_domain)
    if kind == "quantile":
        # **metric 을 반드시 확인한다.** 우리가 가진 히스토그램은 왕복지연 하나뿐인데
        # 이것을 세션 설정시간·측위오차 같은 다른 metric 의 목표에 갖다 대면
        # 숫자는 나오지만 완전히 다른 양을 비교하게 된다(실제로 setup 2.0 s 목표에
        # RTT p95 218 ms 를 대어 잘못된 FAIL 이 나왔다).
        if t.metric not in _RTT_METRICS:
            return V.not_measurable_record(
                t, tier, clock_domain, phase=phase,
                reason=(f"metric={t.metric} 는 이 실행 경로가 재지 않는다 — "
                        f"왕복지연 분포로 대신 판정하지 않는다"))
        hist = agg["hist"]
        if hist.count == 0:
            return None
        qe = K.QuantileEstimate.from_histogram(
            hist, getattr(t, "quantile", 0.99) or 0.99,
            getattr(t, "confidence", 0.95))
        return V.decide_quantile(t, qe, phase=phase, tier=tier,
                                 clock_domain=clock_domain)
    # survival / availability / rate / delta / population 은 추가 입력(주기·바이트·
    # 기준 phase·절차 카운터)이 필요하다. 지금 없는 입력을 있는 척 채워 판정하면
    # 그것이야말로 이 도구가 없애려는 실패다.
    #
    # 그렇다고 **조용히 빠뜨려서도 안 된다.** 목표가 결과에서 사라지면 보고서는
    # "판정하지 않았다" 가 아니라 "그런 요구는 없었다" 처럼 읽힌다. 그래서
    # NOT_MEASURABLE 레코드로 남겨 이유를 명시한다.
    return V.not_measurable_record(
        t, tier, clock_domain, phase=phase,
        reason=(f"'{kind}' 목표는 이 실행 경로가 제공하지 않는 입력이 필요하다 "
                f"(metric={t.metric}) — 판정하지 않고 남긴다"))


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:  # noqa: C901
    """컴파일과 훅의 기본 동작 — 네트워크 없이."""
    from .model import KpiProvenance, KpiTarget, MeasurementConfig

    ok = True
    sc = ServiceScenario(
        id="t", title="test", service_class="URLLC",
        populations=[UePopulation(name="p1", count=2, features=["urllc"],
                                  traffic={"pattern": "periodic",
                                           "period_ms": 2.0,
                                           "packet_size": 200})],
        phases=[Phase(name="a", duration_s=4.0, warmup_s=1.0),
                Phase(name="b", duration_s=4.0, warmup_s=1.0,
                      load_scale={"p1": 2.0})],
        targets=[KpiTarget(name="lat", kind="quantile", metric="rtt_ms",
                           basis="rtt-conservative", op="<=", value=2.0,
                           unit="ms", quantile=0.99,
                           provenance=KpiProvenance(spec="TS 22.104",
                                                    version="19.2.0",
                                                    clause="5.2",
                                                    kind="service_requirement"))],
        measurement=MeasurementConfig())

    errs = sc.validate()
    if errs:
        ok = False
        print(f"  [RUN] 시나리오 검증 실패: {errs}")

    cfg = compile_run_config(
        sc, core={"kind": "stub", "amf_addr": "127.0.0.1", "amf_port": 1,
                  "upf_addr": "127.0.0.1", "upf_port": 2},
        gnb={"name": "g", "mcc": "450", "mnc": "05", "gnb_id": 1, "tac": 1,
             "n2_local_addr": "127.0.0.1", "n3_local_addr": "127.0.0.1",
             "n3_local_port": 0, "n3_advertise_addr": "127.0.0.1"},
        security={"key": "4" * 32, "opc": "c" * 32, "amf": "8000"})
    if cfg.total_ues() != 2:
        ok = False
        print(f"  [RUN] 단말 수 컴파일 오류: {cfg.total_ues()}")
    if abs(cfg.traffic.duration - 8.0) > 1e-9:
        ok = False
        print(f"  [RUN] 지속시간 컴파일 오류: {cfg.traffic.duration}")
    if cfg.ue_groups[0].name != "p1" or cfg.ue_groups[0].traffic != "periodic":
        ok = False
        print(f"  [RUN] 그룹 컴파일 오류: {cfg.ue_groups[0]}")
    elif verbose:
        print(f"  [RUN] 컴파일 OK — {cfg.total_ues()}단말, {cfg.traffic.duration}s, "
              f"패턴 {cfg.ue_groups[0].traffic}")

    # 훅: 가짜 단말/템플릿으로 스탬프→해소 왕복
    from ..transport.gtpu import Ipv4UdpTemplate

    class FakeUe:
        ran_ue_ngap_id = 3
        group = "p1"
        imsi = "450050000000001"
        ul_shaper = None
        dl_shaper = None
        traffic_gen = None

    def _other(nid: int, ip: str, port: int):
        class _U(FakeUe):
            ran_ue_ngap_id = nid
            imsi = f"45005000000{nid:04d}"
        return _U(), Ipv4UdpTemplate(ip, "8.8.8.8", port, 33434, payload_len=172)

    h = ScenarioHooks(sc)
    ue = FakeUe()
    # 판정대상 2단말 중 1대만 붙은 상태에서는 평가창이 열리면 안 된다 —
    # 열리면 첫 phase 가 코어가 아니라 세션수립 과도상태를 재게 된다.
    u4, t4 = _other(4, "10.45.0.6", 40001)
    h.stamp_template(u4, t4, 0.0)
    h.on_tick(0.0)
    if h.phase_idx >= 0:
        ok = False
        print("  [RUN] 판정대상이 다 붙기 전에 평가창이 열렸다")
    u5, t5 = _other(5, "10.45.0.7", 40002)
    h.stamp_template(u5, t5, 0.0)
    h.on_tick(0.0)                      # 2/2 활성 → phase 0 시작
    if h.phase_idx != 0:
        ok = False
        print("  [RUN] phase 시작 안 됨")
    elif verbose:
        print(f"  [RUN] 세션수립 대기 후 평가창 개시 OK "
              f"(대기 {h._setup_hold_s}s, 상한도달={h._setup_capped})")
    tmpl = Ipv4UdpTemplate("10.45.0.5", "8.8.8.8", 40000, 33434, payload_len=172)
    h.stamp_template(ue, tmpl, 0.0)
    pkt = tmpl.build(1)
    s = st.decode_from_inner_ip(pkt)
    if s is None or s.flow_id != 3 or s.seq != 0:
        ok = False
        print(f"  [RUN] 스탬프 왕복 실패: {s}")
    else:
        h.on_dl_payload(ue, pkt, 0.001)
        fs = h.flows[3]
        ps = fs.ledger.phase(0)
        # 이 패킷은 phase 시작 직후 = warmup(1 s) 안이므로 **검열되어야** 한다.
        # 워밍업 구간을 분모에 넣으면 등록 직후의 과도상태가 판정을 오염시킨다.
        if ps.censored != 1 or ps.received != 0:
            ok = False
            print(f"  [RUN] 워밍업 검열이 동작하지 않음: "
                  f"censored={ps.censored} received={ps.received}")
        elif verbose:
            print(f"  [RUN] 워밍업 구간 송신을 검열 OK "
                  f"(sent={ps.sent} censored={ps.censored})")

    # 워밍업이 없는 시나리오에서는 같은 왕복이 정상 계상되어야 한다
    sc2 = ServiceScenario(
        id="t2", title="t2", service_class="URLLC",
        populations=list(sc.populations),
        phases=[Phase(name="a", duration_s=4.0, warmup_s=0.0)],
        targets=list(sc.targets), measurement=MeasurementConfig())
    h2 = ScenarioHooks(sc2)
    for nid, ip, port in ((4, "10.45.0.6", 40001), (5, "10.45.0.7", 40002)):
        u, t = _other(nid, ip, port)
        h2.stamp_template(u, t, 0.0)     # 판정대상 2대를 올려 평가창을 연다
    h2.on_tick(0.0)
    if h2.phase_idx != 0:
        ok = False
        print("  [RUN] 워밍업 0 시나리오에서 평가창이 열리지 않음")
    tmpl2 = Ipv4UdpTemplate("10.45.0.5", "8.8.8.8", 40000, 33434, payload_len=172)
    h2.stamp_template(ue, tmpl2, 0.0)
    pkt2 = tmpl2.build(1)
    h2.on_dl_payload(ue, pkt2, 0.001)
    ps2 = h2.flows[3].ledger.phase(0)
    if ps2.received != 1 or ps2.k_within != 1:
        ok = False
        print(f"  [RUN] 정상 해소 실패: received={ps2.received} "
              f"k_within={ps2.k_within}")
    elif verbose:
        print(f"  [RUN] 스탬프→해소 왕복 OK (sent={ps2.sent} rx={ps2.received} "
              f"PDB내 {ps2.k_within})")

    # 너무 작은 패킷은 계측을 건너뛰되 조용히 실패하지 않는다
    small = Ipv4UdpTemplate("10.45.0.5", "8.8.8.8", 40000, 33434, payload_len=8)
    before = h.flows[3].stamped
    h.stamp_template(ue, small, 0.0)
    if h.flows[3].stamped != before:
        ok = False
        print("  [RUN] 너무 작은 패킷에 스탬프가 들어감")
    elif verbose:
        print("  [RUN] 소형 패킷 계측 불가를 경고로 표면화 OK")

    frag = h.result_fragment()
    if frag["scenario_id"] != "t" or not frag["phases"]:
        ok = False
        print(f"  [RUN] 결과 조립 오류: {list(frag)}")
    return ok


if __name__ == "__main__":
    print("RUNNER selftest:", "PASS" if selftest(verbose=True) else "FAIL")
