#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.paper.lf_bridge — 캡처 측정오차가 Real2Sim 특징이득 예측으로 전파되는 양.

왜 이 모듈이 필요한가
=====================
Real2Sim 에이전트는 N3 미러에서 수동 캡처한 단말별 처리량 R 을 벤더 정격 피크 P 로
정규화해 부하계수 LF = clip(R/P, LF_min, LF_max) 를 만들고, 문헌 이득 g_base 를
LF 로 스케일해 예측 처리량을 낸다:

    g_f(LF) = 1 + β_f · LF,          β_f = g_f^base − 1
    R_sim   = R · Π_f g_f(LF)

이 사슬의 **입력은 캡처 측정값 하나뿐**이다. 그런데 미러 캡처는 패킷을 잃는다.
잃으면 R 이 과소평가되고, LF 가 과소평가되고, 이득이 과소평가되고, 예측이 틀린다.
제출본은 이 오차를 한 번도 재지 않았다 — 재려면 **정답**이 있어야 하는데 수동
캡처에는 정답이 없기 때문이다.

ranemu 는 알려진 트래픽을 실제 코어에 주입하고 정답 매니페스트를 남기므로, 바로 그
정답을 공급한다. 이 모듈은 그 위에서 두 가지를 한다.

  (1) **해석적 전파.** 이득이 LF 에 아핀이므로 상대오차 전파가 닫힌 형식으로 나온다.
      R̂ = R(1+ε) 이고 클립 안쪽이면 L̂F = LF(1+ε) 이므로

          Δg_f/g_f = ε · κ_f,   κ_f = β_f·LF / (1 + β_f·LF)

      즉 **이득 오차는 측정 오차의 감쇠 사본**이다(β_f>0 이면 0<κ_f<1).
      예측 처리량은 R 자신도 곱해지므로 1차 근사로

          ΔR_sim/R_sim ≈ ε · (1 + Σ_f κ_f) ≡ ε · A

      A 는 **오차 증폭계수**이고 활성 특징 수 F 에 대해 A ≤ 1+F 로 유계다.
      운영자는 이 식으로 "예측을 x% 안에 넣으려면 캡처를 몇 % 안에서 재야 하는가" 를
      역산할 수 있다. 이것이 이 논문이 제안하는 오차예산(error budget)이다.

  (2) **실증.** 정답 대비 캡처 손상을 실제로 걸어 ε 를 만들고, 보정 전/후의 LF 와
      예측 처리량 오차를 측정해 위 1차 근사가 실제로 성립하는지 확인한다.

클립에 대한 주의(제출본이 놓친 것)
--------------------------------
LF < LF_min 인 단말은 clip 이 LF_min 으로 고정하므로 **ΔLF = 0** 이 된다. 겉보기에는
측정오차에 면역인 것처럼 보이지만, 실은 그 단말의 이득 예측이 자기 측정값과 무관해진
것이다. 실측 LF 0.03 인 산발 단말을 0.3 으로 놓으면 부하를 10배로 본 셈이고, 이득도
그만큼 과대평가된다. 감쇠가 아니라 **치환**이다. 이 모듈은 두 경우를 나누어 센다.

재현:
    python3 -m ranemu.paper.lf_bridge --out ranemu/paper/v4
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import statistics
import sys
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..calibrate import sweep, truth_from_pcap
from ..impair import ImpairmentConfig
from ..util import get_logger

log = get_logger("ranemu.paper.lf")

V4 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v4")


# ─────────────────────────────────────────────────────────────────────────────
# 특징 이득표 — 제출본 Table 1 의 전사. 출처와 검증 여부를 함께 들고 다닌다.
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class FeatureGain:
    """문헌 보고 이득 한 건. low/median/high 세 점을 모두 보존한다."""
    name: str
    direction: str                 # "UL" | "DL" | "both" | "latency"
    low: float                     # 배율(1.10 = +10 %)
    median: float
    high: float
    spec: str = ""
    clause: str = ""
    kind: str = "literature_report"
    note: str = ""

    @property
    def beta(self) -> float:
        """β = g_base − 1. 이득의 '초과분' 이며 전파식의 계수."""
        return self.median - 1.0

    def gain(self, lf: float) -> float:
        """식 (2): LF 로 스케일한 이득."""
        return 1.0 + self.beta * lf

    def kappa(self, lf: float) -> float:
        """감쇠계수 κ = β·LF/(1+β·LF). 측정오차 → 이득오차 전달률."""
        g = self.gain(lf)
        return (self.beta * lf / g) if g else 0.0


#: 제출본 Table 1 과 같은 값. LTM 은 지연 전용이라 처리량 전파에서 제외한다.
FEATURES: List[FeatureGain] = [
    FeatureGain("SBFD", "UL", 1.10, 1.35, 1.79, "TR 38.859", "§7",
                note="상향 서브밴드 전이중"),
    FeatureGain("EN-DC", "UL", 1.20, 1.48, 1.65, "TS 37.340", "§4",
                note="LTE-NR 이중연결"),
    FeatureGain("NR-DC", "DL", 1.40, 1.60, 1.80, "TS 37.340", "§4"),
    FeatureGain("NR-DC-UL", "UL", 1.25, 1.45, 1.70, "TS 37.340", "§4"),
    FeatureGain("AI-CSI", "DL", 1.08, 1.15, 1.30, "TR 38.843", "§5",
                note="AI/ML 기반 CSI 압축"),
    FeatureGain("MIMO-adv", "UL", 1.15, 1.40, 1.60, "TS 38.214", "§5"),
    FeatureGain("NES", "both", 0.90, 0.95, 0.98, "TR 38.864", "§6",
                note="에너지 절감 — β<0 이라 전파를 상쇄한다"),
]


# ─────────────────────────────────────────────────────────────────────────────
# (1) 해석적 전파
# ─────────────────────────────────────────────────────────────────────────────
def amplification(features: Sequence[FeatureGain], lf: float) -> float:
    """오차 증폭계수 A = 1 + Σ κ_f. 예측 상대오차 ≈ A · (측정 상대오차)."""
    return 1.0 + sum(f.kappa(lf) for f in features)


def predict(r_mbps: float, lf: float, features: Sequence[FeatureGain],
            cap_mbps: Optional[float] = None) -> float:
    """식 (3): R_sim = R · Π g_f(LF), 필요하면 새 물리 상한으로 자른다."""
    out = r_mbps
    for f in features:
        out *= f.gain(lf)
    if cap_mbps is not None:
        out = min(out, cap_mbps)
    return out


def load_factor(r_mbps: float, peak_mbps: float,
                lf_min: float = 0.30, lf_max: float = 1.00) -> float:
    """식 (1). 클립이 걸렸는지 여부는 호출부에서 따로 확인한다."""
    if peak_mbps <= 0:
        return lf_min
    return max(lf_min, min(lf_max, r_mbps / peak_mbps))


def analytic_table(features: Sequence[FeatureGain],
                   lfs: Sequence[float] = (0.3, 0.5, 0.7, 1.0),
                   subsets: Optional[Sequence[Sequence[str]]] = None
                   ) -> List[Dict[str, Any]]:
    """LF × 활성특징집합 별 κ 와 증폭계수 A."""
    by_name = {f.name: f for f in features}
    subsets = subsets or [
        ["SBFD"],
        ["SBFD", "MIMO-adv"],
        ["SBFD", "MIMO-adv", "EN-DC"],
        ["SBFD", "MIMO-adv", "EN-DC", "NR-DC-UL"],
        ["SBFD", "NES"],
    ]
    rows = []
    for names in subsets:
        fs = [by_name[n] for n in names if n in by_name]
        for lf in lfs:
            rows.append({
                "features": list(names),
                "n_features": len(fs),
                "lf": lf,
                "kappa": {f.name: round(f.kappa(lf), 4) for f in fs},
                "amplification": round(amplification(fs, lf), 4),
                "gain_product": round(math.prod(f.gain(lf) for f in fs), 4),
            })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# (2) 실증 — 정답 대비 캡처 손상 → LF → 예측
# ─────────────────────────────────────────────────────────────────────────────
#: 손상 조건. 기전이 다르면 오차의 성질이 달라지므로 세 계열을 모두 건다.
#: 포화(capacity)는 **정답 처리량보다 낮게** 잡아야 실제로 발동한다 — 처음에 700/500
#: Mb/s 로 뒀다가 정답이 264 Mb/s 라 한 패킷도 안 떨어지는 것을 보고 고쳤다.
#: 값은 정답 처리량 대비 비율로 준다.
_CONDS_REL: List[Tuple[str, Dict[str, Any]]] = [
    ("clean", {}),
    ("uniform2", {"loss_rate": 0.02}),
    ("uniform10", {"loss_rate": 0.10}),
    ("uniform30", {"loss_rate": 0.30}),
    ("sat_80", {"_cap_frac": 0.80}),
    ("sat_60", {"_cap_frac": 0.60}),
    ("sat_40", {"_cap_frac": 0.40}),
    ("coalesce4", {"coalesce_batch": 4.0}),
    ("dup10", {"duplicate_rate": 0.10}),
    ("mixed", {"loss_rate": 0.05, "_cap_frac": 0.80, "duplicate_rate": 0.05}),
]


def _conds_for(truth_mbps: float) -> List[Tuple[str, Dict[str, Any]]]:
    """상대 포화율을 절대 capacity_mbps 로 바꾼다."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    for name, kw in _CONDS_REL:
        kw = dict(kw)
        frac = kw.pop("_cap_frac", None)
        if frac is not None:
            kw["capacity_mbps"] = round(truth_mbps * frac, 3)
        out.append((name, kw))
    return out


def _rel(measured: Optional[float], truth: float) -> Optional[float]:
    if measured is None or truth <= 0:
        return None
    return (measured - truth) / truth


def run_bridge(truth_pcap: str, seeds: Sequence[int] = (42, 43, 44),
               peak_mbps: Optional[float] = None,
               lf_min: float = 0.30, lf_max: float = 1.00,
               active: Sequence[str] = ("SBFD", "MIMO-adv", "EN-DC"),
               workdir: Optional[str] = None,
               run_probe: bool = True) -> Dict[str, Any]:
    """정답 pcap 에 손상을 걸어 ε 를 만들고 LF·예측 오차를 잰다.

    peak_mbps 를 주지 않으면 정답 처리량의 1/LF_target 로 잡아 LF 가 클립 안쪽의
    대표값이 되게 한다 — 클립에 걸린 채로 재면 전파를 관측할 수 없기 때문이다.
    """
    tmp = workdir or tempfile.mkdtemp(prefix="ranemu-lf-")
    os.makedirs(tmp, exist_ok=True)
    truth_mbps, truth_pkts = truth_from_pcap(truth_pcap)
    if truth_mbps <= 0:
        return {"error": "정답 pcap 에서 처리량을 못 구했다"}
    # 대표 운영점 LF≈0.65 (제출본 Table 2 의 'moderate' 단말과 같은 수준)
    peak = peak_mbps if peak_mbps else truth_mbps / 0.65
    by_name = {f.name: f for f in FEATURES}
    feats = [by_name[n] for n in active if n in by_name]

    lf_true = load_factor(truth_mbps, peak, lf_min, lf_max)
    pred_true = predict(truth_mbps, lf_true, feats)

    cond_spec = _conds_for(truth_mbps)
    per_cond: Dict[str, List[Dict[str, Any]]] = {c[0]: [] for c in cond_spec}
    for seed in seeds:
        conds = [(name, ImpairmentConfig(seed=seed, **kw)) for name, kw in cond_spec]
        pts = sweep(truth_pcap, conds, workdir=tmp, run_probe=run_probe)
        for p in pts:
            d = p.as_dict()
            row: Dict[str, Any] = {
                "seed": seed, "label": d["label"],
                "actual_loss_pct": d["actual_loss_pct"],
                "truth_mbps": truth_mbps,
            }
            for tag, mbps in (("probe", p.probe_mbps),
                              ("corrected", p.corrected_mbps)):
                eps = _rel(mbps, truth_mbps)
                if eps is None:
                    row[f"{tag}_eps_pct"] = None
                    continue
                lf_hat = load_factor(mbps, peak, lf_min, lf_max)
                clipped = not (lf_min < (mbps / peak) < lf_max)
                pred_hat = predict(mbps, lf_hat, feats)
                row[f"{tag}_mbps"] = round(mbps, 4)
                row[f"{tag}_eps_pct"] = round(eps * 100, 4)
                row[f"{tag}_lf"] = round(lf_hat, 5)
                row[f"{tag}_lf_err_pct"] = round(
                    (lf_hat - lf_true) / lf_true * 100, 4) if lf_true else None
                row[f"{tag}_clipped"] = clipped
                row[f"{tag}_pred_mbps"] = round(pred_hat, 4)
                row[f"{tag}_pred_err_pct"] = round(
                    (pred_hat - pred_true) / pred_true * 100, 4) if pred_true else None
                # 1차 근사 예측치: ε·A(LF_true)
                row[f"{tag}_pred_err_firstorder_pct"] = round(
                    eps * amplification(feats, lf_true) * 100, 4)
            per_cond[d["label"]].append(row)
        log.info("LF bridge seed=%d 완료", seed)

    def agg(vals: List[Optional[float]]) -> Optional[Dict[str, float]]:
        v = [x for x in vals if x is not None]
        if not v:
            return None
        return {"mean": round(statistics.mean(v), 4),
                "min": round(min(v), 4), "max": round(max(v), 4),
                "n": len(v)}

    rows = []
    for name, kw in cond_spec:
        pts = per_cond[name]
        if not pts:
            continue
        rows.append({
            "label": name, "params": kw,
            "actual_loss_pct": agg([x["actual_loss_pct"] for x in pts]),
            "probe_eps_pct": agg([x.get("probe_eps_pct") for x in pts]),
            "probe_lf_err_pct": agg([x.get("probe_lf_err_pct") for x in pts]),
            "probe_pred_err_pct": agg([x.get("probe_pred_err_pct") for x in pts]),
            "probe_pred_err_firstorder_pct": agg(
                [x.get("probe_pred_err_firstorder_pct") for x in pts]),
            "corrected_eps_pct": agg([x.get("corrected_eps_pct") for x in pts]),
            "corrected_lf_err_pct": agg([x.get("corrected_lf_err_pct") for x in pts]),
            "corrected_pred_err_pct": agg(
                [x.get("corrected_pred_err_pct") for x in pts]),
            "clipped_any": any(x.get("probe_clipped") or x.get("corrected_clipped")
                               for x in pts),
        })

    # 1차 근사가 실제와 얼마나 맞는가 — 이 논문이 제안하는 오차예산의 타당성.
    # 근사는 ε 이 작을 때 정확하고 커질수록 **보수적으로** 빗나간다(과대예측).
    # 어디까지 쓸 수 있는지 밝히지 않으면 오차예산은 주장일 뿐이므로 구간별로 센다.
    resid: List[float] = []
    bands: Dict[str, List[float]] = {"|eps|<=5%": [], "5-20%": [], ">20%": []}
    signed: List[float] = []
    for name in per_cond:
        for x in per_cond[name]:
            a, b = x.get("probe_pred_err_pct"), x.get("probe_pred_err_firstorder_pct")
            e = x.get("probe_eps_pct")
            if a is None or b is None or e is None:
                continue
            resid.append(abs(a - b))
            signed.append(abs(b) - abs(a))       # >0 이면 근사가 과대예측(보수적)
            ae = abs(e)
            key = "|eps|<=5%" if ae <= 5 else ("5-20%" if ae <= 20 else ">20%")
            bands[key].append(abs(a - b))
    lossy = [r for r in rows
             if (r["actual_loss_pct"] or {}).get("mean", 0) > 1.0]

    def worst(rs: List[Dict[str, Any]], key: str) -> Optional[float]:
        v = [abs((r[key] or {}).get("mean", 0.0)) for r in rs if r.get(key)]
        return round(max(v), 4) if v else None

    return {
        "meta": {
            "truth_mbps": round(truth_mbps, 4),
            "truth_packets": truth_pkts,
            "peak_mbps": round(peak, 4),
            "lf_true": round(lf_true, 5),
            "lf_min": lf_min, "lf_max": lf_max,
            "active_features": list(active),
            "amplification": round(amplification(feats, lf_true), 4),
            "kappa": {f.name: round(f.kappa(lf_true), 4) for f in feats},
            "seeds": list(seeds),
            "n_conditions": len(rows),
        },
        "analytic": analytic_table(FEATURES),
        "rows": rows,
        "summary": {
            "worst_probe_eps_pct": worst(lossy, "probe_eps_pct"),
            "worst_probe_lf_err_pct": worst(lossy, "probe_lf_err_pct"),
            "worst_probe_pred_err_pct": worst(lossy, "probe_pred_err_pct"),
            "worst_corrected_eps_pct": worst(lossy, "corrected_eps_pct"),
            "worst_corrected_lf_err_pct": worst(lossy, "corrected_lf_err_pct"),
            "worst_corrected_pred_err_pct": worst(lossy, "corrected_pred_err_pct"),
            "firstorder_abs_residual_pp": (
                {"mean": round(statistics.mean(resid), 4),
                 "max": round(max(resid), 4), "n": len(resid)} if resid else None),
            "firstorder_residual_by_band_pp": {
                k: ({"mean": round(statistics.mean(v), 4),
                     "max": round(max(v), 4), "n": len(v)} if v else None)
                for k, v in bands.items()},
            "firstorder_conservative_frac": (
                round(sum(1 for x in signed if x >= -1e-9) / len(signed), 4)
                if signed else None),
            "clip_fired_conditions": [r["label"] for r in rows
                                      if r.get("clipped_any")],
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# (2-b) 합성 가정의 한계 — 곱셈 합성 vs 교차항 없는 합성
# ─────────────────────────────────────────────────────────────────────────────
def pair_interaction(features: Optional[Sequence[FeatureGain]] = None,
                     lfs: Sequence[float] = (0.003, 0.1, 0.3, 0.65, 1.0)
                     ) -> List[Dict[str, Any]]:
    """식 (3) 의 곱셈 합성이 두 특징에 대해 얼마나 교차항을 만드는가.

    곱셈:      (1+β₁·LF)(1+β₂·LF) = 1 + (β₁+β₂)LF + β₁β₂·LF²
    교차항 없음: 1 + (β₁+β₂)LF
    따라서 상대 편차는 **β₁β₂·LF² / (1+(β₁+β₂)LF)** 로 닫혀 있고, LF² 에 비례한다.
    이것이 뜻하는 바가 실측과 만나면 중요해진다 — 실측 LF 가 10⁻³ 규모이면 편차는
    10⁻⁶ 규모라, 합성 방식을 무엇으로 하든 결과가 같다. 합성 가정 논쟁은 고부하
    구간에서만 실질적이다.
    """
    feats = list(features if features is not None else FEATURES)
    rows: List[Dict[str, Any]] = []
    for i in range(len(feats)):
        for j in range(i + 1, len(feats)):
            a, b = feats[i], feats[j]
            for lf in lfs:
                mult = a.gain(lf) * b.gain(lf)
                nocross = 1.0 + (a.beta + b.beta) * lf
                rows.append({
                    "pair": f"{a.name} × {b.name}",
                    "lf": lf,
                    "beta_product": round(a.beta * b.beta, 5),
                    "multiplicative": round(mult, 6),
                    "no_cross_term": round(nocross, 6),
                    "deviation_pct": round((mult / nocross - 1) * 100, 6)
                    if nocross else None,
                })
    return rows


def pair_summary(rows: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """LF 별 최대 편차와, 3% 를 넘는 쌍의 수."""
    out: Dict[str, Any] = {}
    by_lf: Dict[float, List[Dict[str, Any]]] = {}
    for r in rows:
        by_lf.setdefault(r["lf"], []).append(r)
    for lf, rs in sorted(by_lf.items()):
        devs = [abs(r["deviation_pct"]) for r in rs
                if r["deviation_pct"] is not None]
        worst = max(rs, key=lambda r: abs(r["deviation_pct"] or 0))
        out[f"{lf:g}"] = {
            "n_pairs": len(rs),
            "max_deviation_pct": round(max(devs), 6) if devs else None,
            "worst_pair": worst["pair"],
            "n_over_3pct": sum(1 for d in devs if d > 3.0),
        }
    return out


# ─────────────────────────────────────────────────────────────────────────────
# (3) 클립의 효과 — 감쇠가 아니라 치환
# ─────────────────────────────────────────────────────────────────────────────
def clip_analysis(lf_actuals: Sequence[float] = (0.02, 0.03, 0.05, 0.10, 0.20,
                                                 0.30, 0.50, 0.65, 0.92),
                  lf_min: float = 0.30,
                  active: Sequence[str] = ("SBFD", "MIMO-adv", "EN-DC")
                  ) -> List[Dict[str, Any]]:
    """클립이 저부하 단말의 이득 예측을 얼마나 부풀리는지."""
    by_name = {f.name: f for f in FEATURES}
    feats = [by_name[n] for n in active if n in by_name]
    rows = []
    for lf in lf_actuals:
        used = max(lf_min, lf)
        g_true = math.prod(f.gain(lf) for f in feats)
        g_used = math.prod(f.gain(used) for f in feats)
        rows.append({
            "lf_actual": lf,
            "lf_used": round(used, 4),
            "clipped": used > lf,
            "lf_inflation_x": round(used / lf, 3) if lf > 0 else None,
            "gain_true": round(g_true, 4),
            "gain_used": round(g_used, 4),
            "gain_overstatement_pct": round((g_used / g_true - 1) * 100, 3),
            "sensitivity": 0.0 if used > lf else round(
                sum(f.kappa(lf) for f in feats), 4),
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
def selftest(verbose: bool = False) -> bool:
    """해석식이 스스로 일관되는지 — 네트워크 없이."""
    ok = True
    f = FEATURES[0]                                  # SBFD, β = 0.35
    if abs(f.beta - 0.35) > 1e-9:
        ok = False
        print(f"  [LF] β 계산 오류: {f.beta}")
    # κ 는 0..1 이고 LF 에 대해 단조증가해야 한다(β>0)
    ks = [f.kappa(x) for x in (0.1, 0.3, 0.5, 0.7, 1.0)]
    if not all(0.0 < k < 1.0 for k in ks) or ks != sorted(ks):
        ok = False
        print(f"  [LF] κ 가 (0,1) 단조가 아님: {ks}")
    # NES 는 β<0 이므로 κ<0 — 전파를 상쇄한다
    nes = [x for x in FEATURES if x.name == "NES"][0]
    if nes.kappa(0.65) >= 0:
        ok = False
        print(f"  [LF] NES κ 가 음수가 아님: {nes.kappa(0.65)}")
    # 1차 근사의 정확성: ε 이 작으면 잔차가 ε² 규모여야 한다
    feats = FEATURES[:3]
    lf, r = 0.65, 100.0
    for eps in (1e-3, 1e-2):
        exact = predict(r * (1 + eps), lf * (1 + eps), feats)
        base = predict(r, lf, feats)
        approx = base * (1 + eps * amplification(feats, lf))
        rel_resid = abs(exact - approx) / base
        if rel_resid > 3 * eps * eps * len(feats) + 1e-12:
            ok = False
            print(f"  [LF] 1차 근사 잔차가 ε² 규모를 넘음: ε={eps} 잔차={rel_resid:.3e}")
    # 클립은 감쇠가 아니라 치환 — 민감도 0, 이득 과대평가 > 0
    ca = [x for x in clip_analysis() if x["clipped"]]
    if not ca or any(x["sensitivity"] != 0.0 for x in ca):
        ok = False
        print("  [LF] 클립 구간의 민감도가 0 이 아님")
    if ca and not all(x["gain_overstatement_pct"] > 0 for x in ca):
        ok = False
        print("  [LF] 클립 구간에서 이득 과대평가가 관측되지 않음")
    if ok and verbose:
        a = amplification(feats, 0.65)
        print(f"  [LF] κ={[round(x.kappa(0.65), 3) for x in feats]} → 증폭 A={a:.3f}; "
              f"클립 {ca[0]['lf_actual']}→{ca[0]['lf_used']} 이득 "
              f"+{ca[0]['gain_overstatement_pct']:.1f}%")
    return ok


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="캡처오차 → LF → 특징이득 전파")
    ap.add_argument("--truth-pcap", default=None,
                    help="정답 pcap. 없으면 새로 만든다.")
    ap.add_argument("--out", default=V4)
    ap.add_argument("--seeds", default="42,43,44")
    ap.add_argument("--duration", type=float, default=8.0)
    ap.add_argument("--no-probe", action="store_true",
                    help="기존 프로브 측정을 건너뛴다(보정 추정기만)")
    ap.add_argument("--analytic-only", action="store_true")
    a = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname).1s [%(name)s] %(message)s",
                        datefmt="%H:%M:%S")
    os.makedirs(a.out, exist_ok=True)

    if a.analytic_only:
        res: Dict[str, Any] = {"analytic": analytic_table(FEATURES),
                               "clip": clip_analysis()}
        rows = pair_interaction()
        res["pairs"] = rows
        res["pair_summary"] = pair_summary(rows)
    else:
        truth = a.truth_pcap
        if not truth:
            from .experiments import make_truth_pcap
            made = make_truth_pcap(a.out, seed=42, duration=a.duration)
            truth = made[0] if isinstance(made, tuple) else made
            log.info("정답 pcap 생성: %s", truth)
        seeds = [int(x) for x in a.seeds.split(",") if x.strip()]
        res = run_bridge(truth, seeds, run_probe=not a.no_probe)
        res["clip"] = clip_analysis()
        rows = pair_interaction()
        res["pairs"] = rows
        res["pair_summary"] = pair_summary(rows)

    path = os.path.join(a.out, "L_lf_bridge.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False)
    print(f"저장: {path}")
    s = res.get("summary") or {}
    if s:
        print(f"  프로브 최악: 측정 {s['worst_probe_eps_pct']}% → "
              f"LF {s['worst_probe_lf_err_pct']}% → 예측 "
              f"{s['worst_probe_pred_err_pct']}%")
        print(f"  보정 최악:   측정 {s['worst_corrected_eps_pct']}% → "
              f"LF {s['worst_corrected_lf_err_pct']}% → 예측 "
              f"{s['worst_corrected_pred_err_pct']}%")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
