#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.radio — 무선 물리계층 모델 (기지국이 feature 를 '거동'으로 바꾸는 지점).

이 모듈이 하는 일
=================
RAN 에뮬레이터에는 실제 RF 가 없다. 그러나 코어 관점에서 RedCap 단말과 eMBB 단말은
**사용자평면 트래픽의 성질**로 구별된다(최대 속도, 지연, 버스트성, 손실). 따라서:

    RadioProfile (대역폭/SCS/레이어/변조/듀플렉스/거리 …)
        │  TS 38.306 §4.1.2 피크율 공식
        │  TR 38.901 UMa 경로손실 → SINR → TS 38.214 CQI/MCS
        ▼
    LinkBudget (dl_mbps, ul_mbps, sinr_db, mcs, spectral_efficiency)
        │
        ▼
    shaper 파라미터(rate/delay/jitter/loss) → 실제 GTP-U 송신에 적용

즉 "feature → 물리 파라미터 → 실측 가능한 트래픽 특성" 의 인과가 코드로 이어진다.

`~/ns3_simulation/geri_5g_sim.py` v3.0 의 물리모델과 같은 근거(TS 38.306 피크율,
TR 38.901 링크버짓, TS 38.214 CQI/MCS 테이블)를 쓴다. 다만 저쪽은 시뮬레이션 결과를
보고하는 용도이고, 이쪽은 **실제로 보낼 패킷의 속도를 정하는** 용도다.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field, replace
from typing import Dict, Optional

# ─────────────────────────────────────────────────────────────────────────────
# TS 38.101-1/2 : 대역폭·SCS 별 최대 RB 수
# ─────────────────────────────────────────────────────────────────────────────
_PRB_FR1: Dict[int, Dict[int, int]] = {
    15: {5: 25, 10: 52, 15: 79, 20: 106, 25: 133, 30: 160, 40: 216, 50: 270},
    30: {5: 11, 10: 24, 15: 38, 20: 51, 25: 65, 30: 78, 40: 106, 50: 133,
         60: 162, 70: 189, 80: 217, 90: 245, 100: 273},
    60: {10: 11, 15: 18, 20: 24, 25: 31, 30: 38, 40: 51, 50: 65, 60: 79,
         70: 93, 80: 107, 90: 121, 100: 135},
}
_PRB_FR2: Dict[int, Dict[int, int]] = {
    60: {50: 66, 100: 132, 200: 264},
    120: {50: 32, 100: 66, 200: 132, 400: 264},
    480: {400: 264, 800: 264},     # Rel-17 FR2-2
    960: {400: 132, 800: 264, 1600: 264},
}

#: TS 38.306 §4.1.2 오버헤드 계수 OH
_OVERHEAD = {("FR1", "DL"): 0.14, ("FR1", "UL"): 0.08,
             ("FR2", "DL"): 0.18, ("FR2", "UL"): 0.10}

_RMAX = 948.0 / 1024.0


def n_prb(bandwidth_mhz: float, scs_khz: int, fr: str = "FR1") -> int:
    """대역폭/SCS 조합의 최대 RB 수. 표에 없으면 선형 보간(비율 유지)."""
    table = _PRB_FR1 if fr == "FR1" else _PRB_FR2
    per_scs = table.get(int(scs_khz))
    if not per_scs:
        # 가장 가까운 SCS 로 대체
        per_scs = table[min(table, key=lambda s: abs(s - scs_khz))]
    bw = int(round(bandwidth_mhz))
    if bw in per_scs:
        return per_scs[bw]
    # 표 밖: 가장 가까운 두 점의 RB/MHz 비율로 환산
    nearest = min(per_scs, key=lambda b: abs(b - bw))
    return max(1, int(round(per_scs[nearest] * bw / nearest)))


def nr_peak_mbps(n_prb_: int, scs_khz: int, layers: int, mod_bits: int,
                 fr: str = "FR1", direction: str = "DL",
                 scaling: float = 1.0, carriers: int = 1) -> float:
    """TS 38.306 §4.1.2 피크 데이터율(Mbps).

        R = 1e-6 · Σ_j [ v·Qm·f·Rmax · (N_PRB·12 / Tμ) · (1 − OH) ]
        Tμ = 1e-3 / (14 · 2^μ),  μ = log2(SCS/15)
    """
    mu = max(0, int(round(math.log2(max(scs_khz, 15) / 15.0))))
    t_symbol = 1e-3 / (14 * (2 ** mu))
    oh = _OVERHEAD[(fr, direction)]
    per_cc = (layers * mod_bits * scaling * _RMAX
              * (n_prb_ * 12.0 / t_symbol) * (1.0 - oh)) * 1e-6
    return per_cc * max(1, carriers)


# ─────────────────────────────────────────────────────────────────────────────
# TS 38.214 : SINR → CQI → MCS/변조
# ─────────────────────────────────────────────────────────────────────────────
#: (하한 SINR dB, CQI) — Table 5.2.2.1-2 (64QAM 표) 근사
_CQI_TABLE = [(-6.7, 1), (-4.7, 2), (-2.3, 3), (0.2, 4), (2.4, 5), (4.3, 6),
              (5.9, 7), (8.1, 8), (10.3, 9), (11.7, 10), (14.1, 11), (16.3, 12),
              (18.7, 13), (21.0, 14), (22.7, 15)]

#: CQI → (변조 비트수, 대략적 부호율)
_CQI_MOD = {0: (2, 0.08), 1: (2, 0.08), 2: (2, 0.12), 3: (2, 0.19), 4: (2, 0.30),
            5: (2, 0.44), 6: (2, 0.59), 7: (4, 0.37), 8: (4, 0.48), 9: (4, 0.60),
            10: (6, 0.46), 11: (6, 0.55), 12: (6, 0.65), 13: (6, 0.75),
            14: (6, 0.85), 15: (6, 0.93)}


def sinr_to_cqi(sinr_db: float) -> int:
    cqi = 0
    for lo, c in _CQI_TABLE:
        if sinr_db >= lo:
            cqi = c
    return cqi


def cqi_to_efficiency(cqi: int) -> float:
    """CQI → 스펙트럼 효율 근사(bit/s/Hz per layer)."""
    bits, rate = _CQI_MOD.get(max(0, min(15, cqi)), (2, 0.08))
    return bits * rate


# ─────────────────────────────────────────────────────────────────────────────
# TR 38.901 UMa 경로손실 + 링크버짓
# ─────────────────────────────────────────────────────────────────────────────
def uma_pathloss_db(dist_m: float, freq_ghz: float, los: bool = False,
                    h_bs: float = 25.0, h_ut: float = 1.5) -> float:
    """TR 38.901 Table 7.4.1-1 UMa (간이형)."""
    d = max(float(dist_m), 10.0)
    d3d = math.sqrt(d * d + (h_bs - h_ut) ** 2)
    pl_los = 28.0 + 22.0 * math.log10(d3d) + 20.0 * math.log10(max(freq_ghz, 0.1))
    if los:
        return pl_los
    pl_nlos = (13.54 + 39.08 * math.log10(d3d) + 20.0 * math.log10(max(freq_ghz, 0.1))
               - 0.6 * (h_ut - 1.5))
    return max(pl_los, pl_nlos)


def thermal_noise_dbm(bandwidth_hz: float, nf_db: float = 7.0) -> float:
    return -174.0 + 10.0 * math.log10(max(bandwidth_hz, 1.0)) + nf_db


def link_budget_sinr_db(dist_m: float, freq_ghz: float, bandwidth_mhz: float,
                        tx_dbm: float = 46.0, bf_gain_db: float = 12.0,
                        los: bool = False, interference_margin_db: float = 6.0,
                        extra_loss_db: float = 0.0, nf_db: float = 7.0,
                        cap_db: float = 30.0) -> float:
    """수신 SINR(dB). 셀간 간섭은 여유(margin)로 근사, 상한 포화."""
    pl = uma_pathloss_db(dist_m, freq_ghz, los=los) + extra_loss_db
    rx = tx_dbm + bf_gain_db - pl
    noise = thermal_noise_dbm(bandwidth_mhz * 1e6, nf_db=nf_db)
    return min(cap_db, rx - noise - interference_margin_db)


# ─────────────────────────────────────────────────────────────────────────────
# 프로파일 / 링크버짓 결과
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class RadioProfile:
    """단말 하나가 겪는 무선 설정. feature 플러그인이 이 값을 바꾼다."""
    label: str = "embb-default"
    fr: str = "FR1"
    freq_ghz: float = 3.5
    bandwidth_mhz: float = 100.0
    scs_khz: int = 30
    dl_layers: int = 4
    ul_layers: int = 2
    dl_mod_bits: int = 8            # 256QAM
    ul_mod_bits: int = 6            # 64QAM
    carriers: int = 1
    #: TDD 슬롯 배분(DL 비율). FDD 면 1.0 로 두고 duplex 로 구분.
    duplex: str = "TDD"             # TDD | FDD | HD-FDD
    dl_slot_ratio: float = 0.75     # DDDSU ≈ 0.75
    #: 서브밴드 풀듀플렉스(SBFD) 활성 시 UL 부스트/DL 손실 계수 (TR 38.858)
    sbfd: bool = False
    sbfd_ul_beta: float = 0.20
    #: 거리/전파
    distance_m: float = 300.0
    los: bool = False
    tx_dbm: float = 46.0
    bf_gain_db: float = 12.0
    extra_loss_db: float = 0.0
    #: 전파지연(편도, ms). 지상망은 무시할 수준, NTN 은 매우 큼.
    propagation_delay_ms: float = 0.05
    #: 스케줄링/HARQ 등에 의한 추가 지연과 변동
    scheduling_delay_ms: float = 1.0
    jitter_ms: float = 0.5
    #: 잔여 블록오류율(BLER) — HARQ 후
    residual_bler: float = 1e-4
    #: 이 단말에 할당되는 셀 자원 비율(0~1). 다중단말/NES 등에서 감소.
    resource_share: float = 1.0
    #: 반이중(HD-FDD/RedCap) 이면 DL/UL 이 시간을 나눠 씀
    half_duplex: bool = False
    #: DRX 로 인한 가용시간 비율(1.0=상시)
    duty_cycle: float = 1.0
    #: 최대 속도 하드 상한(Mbps). feature 가 규격상 상한을 강제할 때.
    dl_cap_mbps: Optional[float] = None
    ul_cap_mbps: Optional[float] = None
    #: 진단용 메모
    notes: Dict[str, str] = field(default_factory=dict)


@dataclass
class LinkBudget:
    """RadioProfile 로부터 산출된, 실제로 적용할 값."""
    dl_mbps: float
    ul_mbps: float
    peak_dl_mbps: float
    peak_ul_mbps: float
    sinr_db: float
    cqi: int
    spectral_efficiency: float
    rtt_ms: float
    owd_ms: float
    jitter_ms: float
    loss_rate: float
    n_prb: int
    detail: Dict[str, float] = field(default_factory=dict)


def compute_link(profile: RadioProfile) -> LinkBudget:
    """RadioProfile → LinkBudget. 이 함수가 물리모델의 단일 진입점이다."""
    prb = n_prb(profile.bandwidth_mhz, profile.scs_khz, profile.fr)

    # 1) 설정상 피크율 (TS 38.306)
    peak_dl = nr_peak_mbps(prb, profile.scs_khz, profile.dl_layers, profile.dl_mod_bits,
                           profile.fr, "DL", carriers=profile.carriers)
    peak_ul = nr_peak_mbps(prb, profile.scs_khz, profile.ul_layers, profile.ul_mod_bits,
                           profile.fr, "UL", carriers=profile.carriers)

    # 2) 듀플렉스/슬롯 배분
    if profile.duplex == "TDD":
        dl_frac, ul_frac = profile.dl_slot_ratio, 1.0 - profile.dl_slot_ratio
    elif profile.half_duplex:
        # HD-FDD: 동시에 못 하므로 시간분할. RedCap 의 대표 형태.
        # 반이중은 정의상 한쪽이 시간을 100% 가져갈 수 없다. 다른 feature 가
        # 전이중을 가정하고 dl_slot_ratio 를 1.0 으로 올려놓은 경우(예: NTN 이
        # FDD 로 바꾸면서 1.0 설정) 그대로 두면 UL 이 0 이 되어 버린다.
        ratio = min(max(profile.dl_slot_ratio, 0.05), 0.95)
        dl_frac, ul_frac = ratio, 1.0 - ratio
    else:                                   # FDD 전이중
        dl_frac = ul_frac = 1.0

    # 3) SBFD (TR 38.858): UL 서브밴드를 상시 확보 → UL 증가, DL 소폭 감소
    if profile.sbfd:
        ul_frac = min(1.0, ul_frac + profile.sbfd_ul_beta * dl_frac * 3.0)
        dl_frac *= (1.0 - profile.sbfd_ul_beta * 0.4)

    # 4) 채널품질: SINR → CQI → 스펙트럼효율. 설정 피크 대비 달성률로 반영.
    sinr = link_budget_sinr_db(
        profile.distance_m, profile.freq_ghz, profile.bandwidth_mhz,
        tx_dbm=profile.tx_dbm, bf_gain_db=profile.bf_gain_db, los=profile.los,
        extra_loss_db=profile.extra_loss_db)
    cqi = sinr_to_cqi(sinr)
    eff = cqi_to_efficiency(cqi)
    # 설정 피크는 최고 MCS 를 가정하므로, 달성 효율/최대 효율 비로 낮춘다.
    max_eff_dl = cqi_to_efficiency(15) * (profile.dl_mod_bits / 6.0)
    quality = min(1.0, eff / max(max_eff_dl, 1e-6))

    common = profile.resource_share * profile.duty_cycle
    dl = peak_dl * dl_frac * quality * common
    ul = peak_ul * ul_frac * quality * common

    if profile.dl_cap_mbps is not None:
        dl = min(dl, profile.dl_cap_mbps)
    if profile.ul_cap_mbps is not None:
        ul = min(ul, profile.ul_cap_mbps)

    owd = profile.propagation_delay_ms + profile.scheduling_delay_ms
    return LinkBudget(
        dl_mbps=max(dl, 0.0), ul_mbps=max(ul, 0.0),
        peak_dl_mbps=peak_dl, peak_ul_mbps=peak_ul,
        sinr_db=sinr, cqi=cqi, spectral_efficiency=eff,
        rtt_ms=2.0 * owd, owd_ms=owd, jitter_ms=profile.jitter_ms,
        loss_rate=profile.residual_bler, n_prb=prb,
        detail={"dl_frac": dl_frac, "ul_frac": ul_frac, "quality": quality,
                "resource_share": profile.resource_share,
                "duty_cycle": profile.duty_cycle},
    )


def selftest(verbose: bool = False) -> bool:
    ok = True

    # (1) TS 38.306 예시: 100MHz/30kHz/FR1 → 273 RB
    if n_prb(100, 30, "FR1") != 273:
        ok = False
        print(f"  [RADIO] PRB 표 오류: {n_prb(100, 30)} != 273")
    elif verbose:
        print("  [RADIO] PRB 표(100MHz/30kHz=273) OK")

    # (2) 피크율: 100MHz, 30kHz, 4레이어, 256QAM, DL → 대략 2.3 Gbps 급
    peak = nr_peak_mbps(273, 30, 4, 8, "FR1", "DL")
    if not (2000 < peak < 2800):
        ok = False
        print(f"  [RADIO] DL 피크율이 예상범위 밖: {peak:.0f} Mbps")
    elif verbose:
        print(f"  [RADIO] DL 피크율 {peak:.0f} Mbps (4L/256QAM/100MHz) OK")

    # (3) 레이어/변조가 선형으로 반영되어야 함
    if abs(nr_peak_mbps(273, 30, 2, 8) * 2 - peak) > 1e-6:
        ok = False
        print("  [RADIO] 레이어 선형성 위반")
    if abs(nr_peak_mbps(273, 30, 4, 4) * 2 - peak) > 1e-6:
        ok = False
        print("  [RADIO] 변조차수 선형성 위반")

    # (4) SCS 가 2배면 심볼시간 절반 → 같은 RB 수라면 처리량 2배
    if abs(nr_peak_mbps(100, 60, 4, 8) - 2 * nr_peak_mbps(100, 30, 4, 8)) > 1e-6:
        ok = False
        print("  [RADIO] SCS(numerology) 스케일링 오류")

    # (5) SINR 단조성: 멀수록 낮아야 함
    near = link_budget_sinr_db(100, 3.5, 100)
    far = link_budget_sinr_db(2000, 3.5, 100)
    if not (near > far):
        ok = False
        print(f"  [RADIO] 거리-SINR 단조성 위반: {near:.1f} vs {far:.1f}")
    elif verbose:
        print(f"  [RADIO] SINR 100m={near:.1f}dB, 2km={far:.1f}dB OK")

    # (6) CQI 단조성
    if not all(sinr_to_cqi(s) <= sinr_to_cqi(s + 2) for s in range(-10, 25, 2)):
        ok = False
        print("  [RADIO] CQI 단조성 위반")

    # (7) 링크버짓 전체 경로
    lb = compute_link(RadioProfile())
    if not (lb.dl_mbps > 0 and lb.ul_mbps > 0 and lb.rtt_ms > 0):
        ok = False
        print("  [RADIO] compute_link 기본 프로파일 결과 이상")
    elif verbose:
        print(f"  [RADIO] 기본 eMBB: DL {lb.dl_mbps:.0f} / UL {lb.ul_mbps:.0f} Mbps, "
              f"SINR {lb.sinr_db:.1f}dB, CQI {lb.cqi} OK")

    # (8) 상한(cap)이 실제로 적용되는지
    capped = compute_link(replace(RadioProfile(), dl_cap_mbps=10.0))
    if capped.dl_mbps > 10.0 + 1e-9:
        ok = False
        print("  [RADIO] dl_cap_mbps 가 적용되지 않음")

    # (9) duty_cycle / resource_share 가 선형 반영
    half = compute_link(replace(RadioProfile(), duty_cycle=0.5))
    if abs(half.dl_mbps * 2 - lb.dl_mbps) > 1e-6:
        ok = False
        print("  [RADIO] duty_cycle 선형 반영 실패")

    # (10) SBFD: UL 이 늘고 DL 이 줄어야 함
    sb = compute_link(replace(RadioProfile(), sbfd=True))
    if not (sb.ul_mbps > lb.ul_mbps and sb.dl_mbps < lb.dl_mbps):
        ok = False
        print(f"  [RADIO] SBFD 효과 이상: UL {lb.ul_mbps:.0f}->{sb.ul_mbps:.0f}, "
              f"DL {lb.dl_mbps:.0f}->{sb.dl_mbps:.0f}")
    elif verbose:
        print(f"  [RADIO] SBFD UL {lb.ul_mbps:.0f}→{sb.ul_mbps:.0f} Mbps, "
              f"DL {lb.dl_mbps:.0f}→{sb.dl_mbps:.0f} Mbps OK")
    return ok


if __name__ == "__main__":
    print("RADIO selftest:", "PASS" if selftest(verbose=True) else "FAIL")
