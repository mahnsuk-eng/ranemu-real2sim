#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.features.catalog — 기지국이 제공하는 5G-Advanced / 6G feature 정의.

각 feature 는 3GPP 릴리즈의 규격값을 근거로 물리 파라미터와 시그널링을 조정한다.
주석의 규격 참조는 그 값이 어디서 왔는지를 밝히기 위한 것이다.
"""
from __future__ import annotations

from .base import Feature, FeatureContext, register

# ═════════════════════════════════════════════════════════════════════════════
# 기본 서비스 유형 (order < 0 : 베이스 프로파일)
# ═════════════════════════════════════════════════════════════════════════════


def _embb(ctx: FeatureContext) -> None:
    p = ctx.profile
    p.label = "eMBB"
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 100.0)
    p.scs_khz = ctx.p("scs_khz", 30)
    p.dl_layers = ctx.p("dl_layers", 4)
    p.ul_layers = ctx.p("ul_layers", 2)
    p.dl_mod_bits = ctx.p("dl_mod_bits", 8)      # 256QAM
    p.ul_mod_bits = ctx.p("ul_mod_bits", 6)      # 64QAM
    p.duplex = ctx.p("duplex", "TDD")
    p.dl_slot_ratio = ctx.p("dl_slot_ratio", 0.75)   # DDDSU
    s = ctx.signaling
    s.five_qi = ctx.p("five_qi", 9)              # 비GBR 기본 베어러
    s.ue_ambr_dl = ctx.p("ue_ambr_dl", 2_000_000_000)
    s.ue_ambr_ul = ctx.p("ue_ambr_ul", 500_000_000)
    ctx.traffic.pattern = ctx.p("pattern", "fullbuffer")


register(Feature(
    name="embb", title="eMBB (초광대역 이동통신)", release="Rel-15", category="service",
    summary="100MHz TDD, 4x2 MIMO, 256QAM 기준 광대역 기본 프로파일",
    apply=_embb, order=-10,
    knobs={"bandwidth_mhz": "반송파 대역폭", "dl_layers": "DL 공간 레이어",
           "dl_mod_bits": "변조 비트수(8=256QAM)", "dl_slot_ratio": "TDD DL 슬롯비"},
))


def _urllc(ctx: FeatureContext) -> None:
    """초고신뢰 저지연 (Rel-15/16/17).

    TS 23.501 Table 5.7.4-1: 5QI 82~85 는 지연예산 5~10ms, PER 1e-5.
    mini-slot(2~7 심볼) + 높은 SCS 로 전송시간을 줄이고, PDCP 중복으로 손실을 낮춘다.
    대신 보수적 MCS/반복전송 때문에 스펙트럼 효율은 떨어진다.
    """
    p = ctx.profile
    p.label = "URLLC"
    p.scs_khz = ctx.p("scs_khz", 60)                 # 짧은 슬롯 → 낮은 지연
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 100.0)
    p.dl_layers = ctx.p("dl_layers", 2)
    p.ul_layers = ctx.p("ul_layers", 1)
    p.dl_mod_bits = ctx.p("dl_mod_bits", 6)          # 보수적 변조
    p.ul_mod_bits = ctx.p("ul_mod_bits", 4)
    p.scheduling_delay_ms = ctx.p("scheduling_delay_ms", 0.25)   # mini-slot + CG
    p.jitter_ms = ctx.p("jitter_ms", 0.05)
    p.residual_bler = ctx.p("residual_bler", 1e-6)   # PDCP 중복 + 반복
    s = ctx.signaling
    s.five_qi = ctx.p("five_qi", 82)                 # 지연 크리티컬 GBR
    s.arp_priority = ctx.p("arp_priority", 2)
    s.rrc_establishment_cause = "highPriorityAccess"
    s.ue_ambr_dl = ctx.p("ue_ambr_dl", 100_000_000)
    s.ue_ambr_ul = ctx.p("ue_ambr_ul", 50_000_000)
    t = ctx.traffic
    t.pattern = ctx.p("pattern", "periodic")
    t.period_ms = ctx.p("period_ms", 1.0)
    t.packet_size = ctx.p("packet_size", 256)
    t.offered_ul_mbps = ctx.p("offered_ul_mbps", 2.0)
    t.offered_dl_mbps = ctx.p("offered_dl_mbps", 2.0)


register(Feature(
    name="urllc", title="URLLC (초고신뢰 저지연)", release="Rel-15/16/17", category="service",
    summary="5QI 82~85, mini-slot·60kHz SCS, PDCP 중복으로 1ms급 지연/1e-6 손실",
    apply=_urllc, order=-10, conflicts=["embb", "mmtc"],
    knobs={"period_ms": "주기 전송 간격", "residual_bler": "잔여 오류율",
           "five_qi": "QoS 식별자(82~85)"},
))


def _mmtc(ctx: FeatureContext) -> None:
    """대규모 사물통신 (Rel-15~). 작고 드문 패킷 + 긴 eDRX."""
    p = ctx.profile
    p.label = "mMTC"
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 5.0)
    p.scs_khz = ctx.p("scs_khz", 15)
    p.dl_layers = p.ul_layers = 1
    p.dl_mod_bits = ctx.p("dl_mod_bits", 2)          # QPSK
    p.ul_mod_bits = ctx.p("ul_mod_bits", 2)
    p.duty_cycle = ctx.p("duty_cycle", 0.01)         # eDRX: 대부분 잠들어 있음
    p.scheduling_delay_ms = ctx.p("scheduling_delay_ms", 20.0)
    p.dl_cap_mbps = ctx.p("dl_cap_mbps", 1.0)
    p.ul_cap_mbps = ctx.p("ul_cap_mbps", 0.5)
    s = ctx.signaling
    s.five_qi = ctx.p("five_qi", 9)
    s.edrx_cycle_s = ctx.p("edrx_cycle_s", 655.36)   # TS 24.008 최대 eDRX
    s.rrc_establishment_cause = "mo-Data"
    s.ue_ambr_dl = ctx.p("ue_ambr_dl", 1_000_000)
    s.ue_ambr_ul = ctx.p("ue_ambr_ul", 500_000)
    t = ctx.traffic
    t.pattern = ctx.p("pattern", "sporadic")
    t.period_ms = ctx.p("period_ms", 60_000.0)       # 1분에 한 번
    t.packet_size = ctx.p("packet_size", 100)
    t.active_ratio = ctx.p("active_ratio", 0.01)
    t.offered_ul_mbps = ctx.p("offered_ul_mbps", 0.01)
    t.offered_dl_mbps = ctx.p("offered_dl_mbps", 0.005)


register(Feature(
    name="mmtc", title="mMTC (대규모 사물통신)", release="Rel-15", category="service",
    summary="5MHz·QPSK·1레이어, eDRX 655초, 분당 100바이트급 산발 전송",
    apply=_mmtc, order=-10, conflicts=["embb", "urllc", "xr"],
    knobs={"edrx_cycle_s": "확장 DRX 주기", "period_ms": "보고 주기"},
))


# ═════════════════════════════════════════════════════════════════════════════
# 5G-Advanced (Rel-17 / Rel-18)
# ═════════════════════════════════════════════════════════════════════════════


def _redcap(ctx: FeatureContext) -> None:
    """RedCap / NR-Light (Rel-17), eRedCap (Rel-18).

    규격 근거 (TS 38.306 §4.1.2 + TS 38.331 RedCap UE capability):
      · 최대 대역폭 FR1 20MHz (Rel-17) / 5MHz (Rel-18 eRedCap)
      · 수신 브랜치 1개(또는 2개) → DL 최대 1레이어(2Rx 라도 랭크1이 일반적)
      · 최대 변조 DL 64QAM(256QAM 은 선택), UL 16/64QAM
      · HD-FDD Type A 지원(반이중) → DL/UL 시간분할
      · eDRX 로 배터리 절감
    결과: 20MHz/30kHz(51RB)/1레이어/64QAM DL 이면 피크 약 85Mbps 급.
    코어 관점에서는 낮은 UE-AMBR 과 작은 UE 무선능력으로 나타난다.
    """
    p = ctx.profile
    variant = ctx.p("variant", "rel17")              # rel17 | rel18(eRedCap)
    bw = ctx.p("bandwidth_mhz", 5.0 if variant == "rel18" else 20.0)
    p.label = f"RedCap({variant})"
    p.bandwidth_mhz = bw
    p.scs_khz = ctx.p("scs_khz", 30)
    p.dl_layers = ctx.p("dl_layers", 1)
    p.ul_layers = 1
    p.dl_mod_bits = ctx.p("dl_mod_bits", 6)          # 64QAM
    p.ul_mod_bits = ctx.p("ul_mod_bits", 4)          # 16QAM
    p.carriers = 1                                   # CA 미지원
    p.half_duplex = ctx.p("half_duplex", True)       # HD-FDD Type A
    if p.half_duplex and p.duplex == "FDD":
        p.duplex = "HD-FDD"
    # 1Rx 브랜치 → 수신 다이버시티 손실 약 3dB
    p.extra_loss_db += ctx.p("rx_branch_loss_db", 3.0 if ctx.p("rx_branches", 1) == 1 else 0.0)
    p.duty_cycle = min(p.duty_cycle, ctx.p("duty_cycle", 0.6))   # eDRX/전력절감
    p.scheduling_delay_ms = max(p.scheduling_delay_ms, ctx.p("scheduling_delay_ms", 4.0))

    s = ctx.signaling
    s.redcap = True
    s.rrc_establishment_cause = ctx.p("rrc_establishment_cause", "mo-Data")
    s.ue_ambr_dl = ctx.p("ue_ambr_dl", 150_000_000 if variant == "rel17" else 10_000_000)
    s.ue_ambr_ul = ctx.p("ue_ambr_ul", 50_000_000 if variant == "rel17" else 5_000_000)
    s.edrx_cycle_s = ctx.p("edrx_cycle_s", 20.48)
    s.tags["redcap_variant"] = variant
    s.tags["rx_branches"] = ctx.p("rx_branches", 1)
    # 축소된 UE 무선능력(코어는 불투명 옥텟으로 저장/전달)
    s.ue_radio_capability = ctx.p(
        "ue_radio_capability",
        bytes([0x00, 0x01, 0x02 if variant == "rel17" else 0x03, int(bw) & 0xFF]))

    t = ctx.traffic
    t.packet_size = ctx.p("packet_size", 512)
    t.pattern = ctx.p("pattern", "periodic")
    t.period_ms = ctx.p("period_ms", 100.0)


register(Feature(
    name="redcap", title="RedCap / NR-Light", release="Rel-17 (eRedCap: Rel-18)",
    category="ue-capability",
    summary="20MHz(Rel-17)/5MHz(Rel-18), 1Rx·1레이어·64QAM, HD-FDD, eDRX — 중저가 단말",
    apply=_redcap, order=0,
    knobs={"variant": "rel17|rel18", "bandwidth_mhz": "최대 대역폭",
           "rx_branches": "수신 브랜치 수(1|2)", "half_duplex": "HD-FDD 여부",
           "ue_ambr_dl": "코어가 강제할 DL 상한"},
))


#: 궤도별 기본 파라미터 — 편도 전파지연은 사용자-위성-게이트웨이 왕복 경로를 포함.
_NTN_ORBITS = {
    # orbit: (고도 km, 서비스링크 편도 ms, 피더링크 편도 ms, 도플러 kHz, 셀체류 s)
    "geo": (35786.0, 119.0, 119.0, 0.5, 1e9),      # 정지궤도: 총 RTT ≈ 477~540ms
    "meo": (8000.0, 27.0, 27.0, 20.0, 1800.0),
    "leo": (600.0, 2.0, 5.0, 48.0, 20.0),          # 저궤도: RTT ≈ 25~50ms, 잦은 셀전환
    "leo1200": (1200.0, 4.0, 8.0, 40.0, 40.0),
    "haps": (20.0, 0.07, 0.07, 1.0, 3600.0),       # 성층권 플랫폼
}


def _ntn(ctx: FeatureContext) -> None:
    """비지상망 (Rel-17 NTN, Rel-18 확장).

    규격 근거 (TR 38.821 / TS 38.300 §16.14):
      · 전파지연이 지배적: GEO 편도 ~238~270ms, LEO(600km) ~2~13ms + 피더링크
      · 큰 도플러 → 사전보상 후에도 잔여 주파수/타이밍 오차 → 지터 증가
      · 링크버짓 제약: S밴드(2GHz) 협대역, 낮은 레이어수, 강건한 변조
      · LEO 는 위성이 이동 → 주기적 셀전환(핸드오버)로 짧은 단절
      · NAS/RRC 타이머 연장(TS 24.501 NTN 확장), TA 사전보상 필요
    """
    orbit = str(ctx.p("orbit", "geo")).lower()
    alt_km, svc_ms, feeder_ms, doppler_khz, dwell_s = _NTN_ORBITS.get(
        orbit, _NTN_ORBITS["geo"])

    p = ctx.profile
    p.label = f"NTN({orbit})"
    p.fr = "FR1"
    p.freq_ghz = ctx.p("freq_ghz", 2.0)              # S 밴드
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 20.0 if orbit != "geo" else 10.0)
    p.scs_khz = ctx.p("scs_khz", 15)                 # NTN 은 낮은 SCS 선호
    p.dl_layers = ctx.p("dl_layers", 1)
    p.ul_layers = 1
    p.dl_mod_bits = ctx.p("dl_mod_bits", 4)          # 16QAM (강건)
    p.ul_mod_bits = ctx.p("ul_mod_bits", 2)          # QPSK
    p.duplex = ctx.p("duplex", "FDD")
    # 전이중 FDD 일 때만 DL 이 시간을 100% 쓸 수 있다. 반이중 단말(RedCap HD-FDD 등)과
    # 조합되면 시간분할이 필요하므로 기존 슬롯비를 유지한다.
    if p.duplex == "FDD" and not p.half_duplex:
        p.dl_slot_ratio = 1.0
    # 위성 링크버짓: 거리 자체를 반영하기보다 별도 손실/이득으로 모델링
    p.distance_m = ctx.p("distance_m", 1000.0)
    p.extra_loss_db += ctx.p("extra_loss_db", 12.0 if orbit == "geo" else 6.0)
    p.bf_gain_db = ctx.p("bf_gain_db", 30.0)         # 위성 안테나 이득

    # 전파지연: 서비스링크 + 피더링크 (편도)
    owd = ctx.p("propagation_delay_ms", svc_ms + feeder_ms)
    p.propagation_delay_ms = owd
    # 도플러 잔여오차와 위성 이동에 의한 지터
    p.jitter_ms = ctx.p("jitter_ms", max(0.5, doppler_khz / 20.0))
    p.scheduling_delay_ms = max(p.scheduling_delay_ms, ctx.p("scheduling_delay_ms", 4.0))
    p.residual_bler = max(p.residual_bler, ctx.p("residual_bler", 1e-3))
    p.notes["ntn_orbit"] = orbit
    p.notes["ntn_altitude_km"] = str(alt_km)

    s = ctx.signaling
    s.ntn = True
    s.ntn_orbit = orbit
    # 큰 RTT 를 견디도록 NAS 타이머 연장 (TS 24.501 NTN 확장)
    s.nas_timer_scale = ctx.p("nas_timer_scale", 4.0 if orbit == "geo" else 2.0)
    s.rrc_establishment_cause = ctx.p("rrc_establishment_cause", "mo-Data")
    s.ue_ambr_dl = ctx.p("ue_ambr_dl", 50_000_000)
    s.ue_ambr_ul = ctx.p("ue_ambr_ul", 10_000_000)
    s.tags["ntn_altitude_km"] = alt_km
    s.tags["ntn_doppler_khz"] = doppler_khz
    s.tags["ntn_cell_dwell_s"] = dwell_s
    s.tags["ntn_rtt_ms_est"] = round(2 * owd, 2)

    t = ctx.traffic
    t.tags["ntn"] = orbit
    # LEO 는 셀 체류시간마다 짧은 단절이 생긴다 → 생성기가 반영
    if dwell_s < 1e6:
        t.tags["interruption_period_s"] = dwell_s
        t.tags["interruption_ms"] = ctx.p("handover_interruption_ms", 50.0)


register(Feature(
    name="ntn", title="NTN (비지상망 / 위성)", release="Rel-17 (확장: Rel-18)",
    category="deployment",
    summary="GEO/MEO/LEO/HAPS 궤도별 전파지연·도플러·링크버짓·셀전환을 반영",
    apply=_ntn, order=5,
    knobs={"orbit": "geo|meo|leo|leo1200|haps", "freq_ghz": "반송파(S밴드 기본 2GHz)",
           "nas_timer_scale": "NAS 타이머 연장배율",
           "handover_interruption_ms": "LEO 셀전환 단절시간"},
))


def _xr(ctx: FeatureContext) -> None:
    """XR / 클라우드 게이밍 (Rel-18 XR Enhancements).

    TS 23.501: 5QI 87~90 이 XR 용으로 정의됨(PDB 10~15ms).
    프레임 단위 버스트(60/90/120fps)가 특징 — 평균 대역폭보다 순간 버스트가 크다.
    """
    fps = ctx.p("fps", 60)
    p = ctx.profile
    p.label = f"XR({fps}fps)"
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 100.0)
    p.scs_khz = ctx.p("scs_khz", 30)
    p.dl_layers = ctx.p("dl_layers", 4)
    p.ul_layers = ctx.p("ul_layers", 2)
    p.dl_mod_bits = ctx.p("dl_mod_bits", 8)
    p.scheduling_delay_ms = ctx.p("scheduling_delay_ms", 1.0)
    p.jitter_ms = ctx.p("jitter_ms", 0.3)
    s = ctx.signaling
    s.five_qi = ctx.p("five_qi", 87)                 # XR 대화형
    s.arp_priority = ctx.p("arp_priority", 3)
    s.ue_ambr_dl = ctx.p("ue_ambr_dl", 200_000_000)
    s.ue_ambr_ul = ctx.p("ue_ambr_ul", 50_000_000)
    t = ctx.traffic
    t.pattern = "burst"
    t.period_ms = ctx.p("period_ms", 1000.0 / max(fps, 1))
    t.offered_dl_mbps = ctx.p("offered_dl_mbps", 45.0)
    t.offered_ul_mbps = ctx.p("offered_ul_mbps", 10.0)
    t.packet_size = ctx.p("packet_size", 1400)
    # 프레임 하나를 몇 개 패킷으로 쪼개는가
    frame_bits = t.offered_dl_mbps * 1e6 / max(fps, 1)
    t.burst_packets = max(1, int(frame_bits / 8 / max(t.packet_size, 1)))
    t.tags["fps"] = fps


register(Feature(
    name="xr", title="XR / 클라우드 게이밍", release="Rel-18", category="service",
    summary="5QI 87~90, 프레임 주기(60/90/120fps) 버스트 트래픽, 낮은 지터 요구",
    apply=_xr, order=-10, conflicts=["mmtc"],
    knobs={"fps": "프레임율", "offered_dl_mbps": "비디오 비트레이트"},
))


def _nes(ctx: FeatureContext) -> None:
    """네트워크 에너지 절감 (Rel-18 NES).

    셀 DTX/DRX 로 기지국이 주기적으로 송신을 끄고, 공간요소 적응으로 안테나 포트를
    줄인다. 코어에서는 '주기적으로 스루풋이 꺼지는' 형태로 관측된다.
    """
    p = ctx.profile
    on_ratio = ctx.p("cell_dtx_on_ratio", 0.6)
    p.duty_cycle *= on_ratio
    p.dl_layers = max(1, int(p.dl_layers * ctx.p("spatial_scale", 0.5)))
    p.tx_dbm -= ctx.p("power_backoff_db", 3.0)
    p.scheduling_delay_ms += ctx.p("wakeup_delay_ms", 2.0)
    p.label += "+NES"
    p.notes["nes_on_ratio"] = str(on_ratio)
    ctx.signaling.tags["nes"] = {"cell_dtx_on_ratio": on_ratio}
    ctx.traffic.tags["nes_dtx_period_ms"] = ctx.p("dtx_period_ms", 320.0)
    ctx.traffic.tags["nes_on_ratio"] = on_ratio


register(Feature(
    name="nes", title="네트워크 에너지 절감 (NES)", release="Rel-18", category="ran-behavior",
    summary="셀 DTX/DRX + 공간요소·전력 적응 — 주기적 가용시간 축소",
    apply=_nes, order=20,
    knobs={"cell_dtx_on_ratio": "송신 활성비", "spatial_scale": "안테나 포트 축소비",
           "dtx_period_ms": "DTX 주기"},
))


def _ltm(ctx: FeatureContext) -> None:
    """L1/L2 트리거 이동성 (Rel-18 LTM).

    기존 L3 핸드오버는 측정보고→RRC재구성으로 30~50ms 단절이 생긴다.
    LTM 은 하위계층 트리거로 사전준비된 셀로 전환해 단절을 0~10ms 로 줄인다.
    """
    interruption = ctx.p("interruption_ms", 5.0)
    ctx.profile.notes["ltm"] = f"interruption={interruption}ms"
    ctx.profile.label += "+LTM"
    ctx.signaling.tags["ltm"] = True
    ctx.traffic.tags["interruption_period_s"] = ctx.p("handover_period_s", 10.0)
    ctx.traffic.tags["interruption_ms"] = interruption
    # 사전준비된 후보셀 덕분에 재접속 지연이 줄어든다
    ctx.profile.scheduling_delay_ms = max(0.2, ctx.profile.scheduling_delay_ms * 0.8)


register(Feature(
    name="ltm", title="L1/L2 트리거 이동성 (LTM)", release="Rel-18", category="mobility",
    summary="하위계층 트리거 핸드오버로 단절시간 30~50ms → 0~10ms",
    apply=_ltm, order=20,
    knobs={"interruption_ms": "핸드오버 단절시간", "handover_period_s": "핸드오버 주기"},
))


def _sbfd(ctx: FeatureContext) -> None:
    """서브밴드 풀듀플렉스 (Rel-18/19 연구 → Rel-19).

    TR 38.858: DL 슬롯 안에 UL 서브밴드를 두어 상향 기회를 상시 확보한다.
    자기간섭(SI) 억제 비용으로 DL 이 소폭 감소한다.
    """
    ctx.profile.sbfd = True
    ctx.profile.sbfd_ul_beta = ctx.p("ul_beta", 0.20)
    ctx.profile.label += "+SBFD"
    ctx.signaling.tags["sbfd"] = {"ul_beta": ctx.profile.sbfd_ul_beta}


register(Feature(
    name="sbfd", title="서브밴드 풀듀플렉스 (SBFD)", release="Rel-18/19", category="phy",
    summary="DL 슬롯 내 UL 서브밴드 확보 — UL 대폭 증가, DL 소폭 감소",
    apply=_sbfd, order=20, knobs={"ul_beta": "UL 서브밴드 비중"},
))


def _mimo_evo(ctx: FeatureContext) -> None:
    """MIMO 진화 (Rel-18): 8Tx 상향, 고차 랭크, CJT."""
    p = ctx.profile
    p.dl_layers = ctx.p("dl_layers", 8)
    p.ul_layers = ctx.p("ul_layers", 4)
    p.bf_gain_db += ctx.p("bf_gain_db", 3.0)
    p.label += "+MIMOevo"
    ctx.signaling.tags["mimo_evolution"] = {"dl_layers": p.dl_layers, "ul_layers": p.ul_layers}


register(Feature(
    name="mimo_evo", title="MIMO 진화 (8Tx UL / 고차 랭크)", release="Rel-18", category="phy",
    summary="상향 8Tx, 하향 최대 8레이어, 다중TRP 결합송신(CJT) 이득",
    apply=_mimo_evo, order=10,
    knobs={"dl_layers": "DL 레이어", "ul_layers": "UL 레이어"},
))


def _ca(ctx: FeatureContext) -> None:
    """반송파 집성 (Rel-15~, 5G-A 에서 대역 확장)."""
    n = int(ctx.p("carriers", 2))
    ctx.profile.carriers = n
    ctx.profile.label += f"+CA{n}"
    ctx.signaling.tags["carrier_aggregation"] = n


register(Feature(
    name="ca", title="반송파 집성 (CA)", release="Rel-15+", category="phy",
    summary="다중 반송파 집성으로 피크율 배수 증가",
    apply=_ca, order=10, conflicts=["redcap"], knobs={"carriers": "집성 반송파 수"},
))


def _ai_ran(ctx: FeatureContext) -> None:
    """AI/ML 기반 공기인터페이스 (Rel-18 연구 / Rel-19 규격화).

    CSI 압축·빔 예측·포지셔닝에 AI 를 적용하면 실효 SINR 과 오버헤드가 개선된다.
    여기서는 유효 이득(dB)과 오버헤드 감소로 근사한다.
    """
    gain = ctx.p("csi_gain_db", 2.0)
    ctx.profile.bf_gain_db += gain
    ctx.profile.extra_loss_db -= ctx.p("overhead_reduction_db", 0.5)
    ctx.profile.label += "+AI"
    ctx.signaling.tags["ai_ran"] = {"csi_gain_db": gain}


register(Feature(
    name="ai_ran", title="AI/ML 공기인터페이스", release="Rel-18 연구 / Rel-19",
    category="6g-candidate",
    summary="AI 기반 CSI 압축·빔 예측으로 실효 SINR 개선 및 오버헤드 절감",
    apply=_ai_ran, order=15, knobs={"csi_gain_db": "실효 SINR 이득"},
))


def _positioning(ctx: FeatureContext) -> None:
    """고정밀 측위 (Rel-16/17/18).

    PRS/SRS 측위 자원이 데이터 자원을 잠식하고, 주기적 측정보고가 상향에 더해진다.
    """
    overhead = ctx.p("prs_overhead", 0.05)
    ctx.profile.resource_share *= (1.0 - overhead)
    ctx.profile.label += "+POS"
    ctx.signaling.tags["positioning"] = {"prs_overhead": overhead,
                                         "target_accuracy_m": ctx.p("accuracy_m", 1.0)}
    ctx.traffic.tags["positioning_report_ms"] = ctx.p("report_period_ms", 1000.0)


register(Feature(
    name="positioning", title="고정밀 측위", release="Rel-16/17/18", category="service",
    summary="PRS/SRS 측위 자원 오버헤드와 주기적 측정보고 트래픽",
    apply=_positioning, order=20,
    knobs={"prs_overhead": "측위 자원 비중", "accuracy_m": "목표 정확도"},
))


def _slicing(ctx: FeatureContext) -> None:
    """네트워크 슬라이싱 (Rel-15~, Rel-17/18 강화).

    S-NSSAI 로 슬라이스를 지정하고 슬라이스별 AMBR 을 강제한다.
    코어가 슬라이스를 실제로 분리하는지 검증하는 데 쓴다.
    """
    s = ctx.signaling
    s.sst = int(ctx.p("sst", 1))
    sd = ctx.p("sd", None)
    s.sd = None if sd in (None, "", "null") else str(sd)
    if ctx.p("slice_ambr_dl", None) is not None:
        s.ue_ambr_dl = int(ctx.p("slice_ambr_dl", s.ue_ambr_dl))
    if ctx.p("slice_ambr_ul", None) is not None:
        s.ue_ambr_ul = int(ctx.p("slice_ambr_ul", s.ue_ambr_ul))
    s.tags["slice"] = {"sst": s.sst, "sd": s.sd}
    ctx.profile.resource_share *= float(ctx.p("resource_share", 1.0))


register(Feature(
    name="slicing", title="네트워크 슬라이싱", release="Rel-15+", category="core-interop",
    summary="S-NSSAI(SST/SD) 지정 + 슬라이스별 AMBR·자원 배분",
    apply=_slicing, order=25,
    knobs={"sst": "슬라이스/서비스 유형", "sd": "슬라이스 구분자(6자리 hex)",
           "slice_ambr_dl": "슬라이스 DL 상한", "resource_share": "무선자원 배분비"},
))


# ═════════════════════════════════════════════════════════════════════════════
# 6G 후보 기능 (연구/초기 규격화 단계 — 파라미터는 대표적 가정값)
# ═════════════════════════════════════════════════════════════════════════════


def _isac(ctx: FeatureContext) -> None:
    """통합 센싱·통신 (ISAC, 6G 핵심 후보 / Rel-19 연구).

    같은 파형으로 통신과 레이더 센싱을 동시에 수행한다. 센싱 자원이 통신 용량을
    잠식하고, 센싱 결과 보고가 주기적 상향 트래픽으로 나타난다.
    """
    duty = ctx.p("sensing_duty", 0.15)
    ctx.profile.resource_share *= (1.0 - duty)
    ctx.profile.label += "+ISAC"
    ctx.signaling.tags["isac"] = {"sensing_duty": duty,
                                  "range_resolution_m": ctx.p("range_resolution_m", 0.3)}
    ctx.traffic.tags["sensing_report_ms"] = ctx.p("report_period_ms", 100.0)
    ctx.traffic.tags["sensing_report_bytes"] = ctx.p("report_bytes", 512)


register(Feature(
    name="isac", title="통합 센싱·통신 (ISAC)", release="6G 후보 / Rel-19 연구",
    category="6g-candidate",
    summary="통신·레이더 센싱 통합 — 센싱 자원 점유 + 주기적 센싱 보고 상향",
    apply=_isac, order=20,
    knobs={"sensing_duty": "센싱 자원 비중", "report_period_ms": "센싱 보고 주기"},
))


def _ambient_iot(ctx: FeatureContext) -> None:
    """앰비언트 IoT (Rel-19 / 6G).

    배터리 없는(에너지 하베스팅) 초저전력 단말. 아주 작은 패킷을 매우 드물게 보낸다.
    """
    p = ctx.profile
    p.label = "AmbientIoT"
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 1.4)
    p.scs_khz = 15
    p.dl_layers = p.ul_layers = 1
    p.dl_mod_bits = p.ul_mod_bits = 2
    p.duty_cycle = ctx.p("duty_cycle", 0.001)
    p.dl_cap_mbps = ctx.p("dl_cap_mbps", 0.1)
    p.ul_cap_mbps = ctx.p("ul_cap_mbps", 0.05)
    p.scheduling_delay_ms = ctx.p("scheduling_delay_ms", 100.0)
    s = ctx.signaling
    s.edrx_cycle_s = ctx.p("edrx_cycle_s", 10485.76)
    s.ue_ambr_dl = 100_000
    s.ue_ambr_ul = 50_000
    s.tags["ambient_iot"] = {"energy_harvesting": True}
    t = ctx.traffic
    t.pattern = "sporadic"
    t.packet_size = ctx.p("packet_size", 32)
    t.period_ms = ctx.p("period_ms", 300_000.0)
    t.active_ratio = ctx.p("active_ratio", 0.001)
    t.offered_ul_mbps = ctx.p("offered_ul_mbps", 0.001)
    t.offered_dl_mbps = ctx.p("offered_dl_mbps", 0.0)


register(Feature(
    name="ambient_iot", title="앰비언트 IoT (무배터리)", release="Rel-19 / 6G",
    category="6g-candidate",
    summary="에너지 하베스팅 초저전력 단말 — 32바이트급 초산발 전송",
    apply=_ambient_iot, order=-10, conflicts=["embb", "xr", "urllc"],
    knobs={"period_ms": "전송 주기", "packet_size": "패킷 크기"},
))


def _upper_mid_band(ctx: FeatureContext) -> None:
    """상위 중대역 FR3 (7~24GHz, 6G 핵심 후보 대역).

    넓은 대역폭과 대규모 MIMO 를 쓰지만 경로손실이 커 셀 반경이 줄어든다.
    """
    p = ctx.profile
    p.fr = "FR1"                                      # RB 표는 FR1 계열 사용
    p.freq_ghz = ctx.p("freq_ghz", 10.0)
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 200.0)
    p.scs_khz = ctx.p("scs_khz", 60)
    p.dl_layers = ctx.p("dl_layers", 8)
    p.ul_layers = ctx.p("ul_layers", 4)
    p.dl_mod_bits = ctx.p("dl_mod_bits", 8)
    p.bf_gain_db = ctx.p("bf_gain_db", 24.0)          # 대규모 MIMO 빔포밍
    p.label = "FR3(upper-mid)"
    ctx.signaling.tags["upper_mid_band"] = {"freq_ghz": p.freq_ghz}


register(Feature(
    name="upper_mid_band", title="상위 중대역 FR3 (7~24GHz)", release="6G 후보",
    category="6g-candidate",
    summary="7~24GHz 광대역 + 대규모 MIMO — 넓은 대역폭, 짧은 커버리지",
    apply=_upper_mid_band, order=-5,
    knobs={"freq_ghz": "반송파 주파수", "bandwidth_mhz": "대역폭"},
))


def _sub_thz(ctx: FeatureContext) -> None:
    """서브테라헤르츠 (100GHz+, 6G 후보). 초광대역·초단거리."""
    p = ctx.profile
    p.fr = "FR2"
    p.freq_ghz = ctx.p("freq_ghz", 140.0)
    p.bandwidth_mhz = ctx.p("bandwidth_mhz", 1600.0)
    p.scs_khz = ctx.p("scs_khz", 960)
    p.dl_layers = ctx.p("dl_layers", 2)
    p.ul_layers = ctx.p("ul_layers", 1)
    p.dl_mod_bits = ctx.p("dl_mod_bits", 6)
    p.bf_gain_db = ctx.p("bf_gain_db", 35.0)
    p.distance_m = ctx.p("distance_m", 50.0)
    p.extra_loss_db += ctx.p("atmospheric_loss_db", 6.0)
    p.label = "sub-THz"
    ctx.signaling.tags["sub_thz"] = {"freq_ghz": p.freq_ghz}


register(Feature(
    name="sub_thz", title="서브테라헤르츠 (100GHz+)", release="6G 후보",
    category="6g-candidate",
    summary="1.6GHz 대역폭·960kHz SCS 초광대역, 수십 미터 커버리지",
    apply=_sub_thz, order=-5, conflicts=["ntn", "redcap"],
    knobs={"freq_ghz": "반송파", "bandwidth_mhz": "대역폭", "distance_m": "거리"},
))
