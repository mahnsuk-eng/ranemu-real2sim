#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.paper.figures_physcomm — Physical Communication 원고 그림.

figures.py 와 같은 규율: 색은 마지막에, 색만으로 식별하지 않는다(마커·선종 이중
인코딩), 이중 y축 금지, 흑백 인쇄에서도 읽히게.

    python3 -m ranemu.paper.figures_physcomm --data ranemu/paper/v4 \
        --out ranemu/paper/physcomm/figures
"""
from __future__ import annotations

import argparse
import json
import math
import os
from typing import Any, Dict, List, Optional, Sequence

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .figures import C, GRID, INK, INK2, LINES, MARKERS, MM, MUTED, W1, W15, W2, _grid, _save, _style
from .lf_bridge import FEATURES, amplification, load_factor


def _load(d: str, name: str) -> Optional[Dict[str, Any]]:
    p = os.path.join(d, name)
    if not os.path.exists(p):
        print(f"  (건너뜀: {name} 없음)")
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
# 그림 1 — 전달계수 κ 와 증폭계수 A
# ─────────────────────────────────────────────────────────────────────────────
def fig_propagation(outdir: str, field: Optional[Dict[str, Any]] = None) -> None:
    """이득이 LF 에 아핀이라 오차 전파가 닫힌 형식으로 나온다는 것을 한 장으로."""
    _style()
    fig, axes = plt.subplots(1, 2, figsize=(W2, 62 * MM))
    lfs = [i / 200.0 for i in range(1, 201)]

    # (a) 특징별 전달계수 κ(LF)
    ax = axes[0]
    show = ["SBFD", "MIMO-adv", "EN-DC", "NES"]
    by = {f.name: f for f in FEATURES}
    for k, name in enumerate(show):
        f = by[name]
        ax.plot(lfs, [f.kappa(x) for x in lfs], LINES[k % len(LINES)],
                color=C[k % len(C)], label=f"{name} (β={f.beta:+.2f})",
                marker=MARKERS[k % len(MARKERS)], markevery=40, ms=4,
                mfc="none", mew=1.2)
    ax.axhline(0, color=INK2, lw=0.8)
    ax.set_xlabel("Load factor LF")
    ax.set_ylabel("Transfer coefficient  κ = βLF/(1+βLF)")
    ax.set_title("(a) Per-feature error transfer", loc="left")
    ax.legend(fontsize=6.6, loc="upper left")
    _grid(ax, "both")

    # (b) 활성 특징 수에 따른 증폭계수 A(LF)
    ax = axes[1]
    subsets = [(["SBFD"], "1 feature"),
               (["SBFD", "MIMO-adv"], "2 features"),
               (["SBFD", "MIMO-adv", "EN-DC"], "3 features"),
               (["SBFD", "MIMO-adv", "EN-DC", "NR-DC-UL"], "4 features")]
    for k, (names, lab) in enumerate(subsets):
        fs = [by[n] for n in names]
        ax.plot(lfs, [amplification(fs, x) for x in lfs], LINES[k % len(LINES)],
                color=C[k % len(C)], label=lab,
                marker=MARKERS[k % len(MARKERS)], markevery=40, ms=4,
                mfc="none", mew=1.2)
    ax.axhline(1.0, color=INK2, lw=1.0, ls=(0, (4, 2)))
    ax.text(0.02, 1.005, "A = 1: prediction error equals capture error",
            fontsize=6.4, color=INK2)
    # 실측 운영점을 같은 축에 표시 — 이론이 어디서 쓰이는지 보이게
    if field:
        p50 = []
        for c in field.get("captures", []):
            d = (c.get("distribution") or {}).get("DL")
            if d:
                p50.append(d["lf_raw"]["p50"])
        if p50:
            ax.axvspan(min(p50), max(p50), color=C[1], alpha=0.18, zorder=0)
            ax.annotate("measured operating range\n(this network)",
                        xy=(max(p50), 1.02), xytext=(0.18, 1.35),
                        fontsize=6.4, color=C[1],
                        arrowprops=dict(arrowstyle="-|>", color=C[1], lw=0.8))
    ax.set_xlabel("Load factor LF")
    ax.set_ylabel("Amplification  A = 1 + Σκ")
    ax.set_title("(b) End-to-end amplification", loc="left")
    ax.legend(fontsize=6.6, loc="upper left")
    _grid(ax, "both")

    fig.tight_layout()
    _save(fig, outdir, "fig1_propagation")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 2 — 정답 대비 실측: 캡처오차 → 예측오차, 보정 전/후
# ─────────────────────────────────────────────────────────────────────────────
def fig_bridge(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = data["rows"]
    A = data["meta"]["amplification"]

    def g(r, k):
        v = r.get(k)
        return (v or {}).get("mean")

    pts = [(abs(g(r, "probe_eps_pct") or 0.0), abs(g(r, "probe_pred_err_pct") or 0.0),
            abs(g(r, "corrected_eps_pct") or 0.0),
            abs(g(r, "corrected_pred_err_pct") or 0.0), r["label"])
           for r in rows]
    pts.sort()

    fig, axes = plt.subplots(1, 2, figsize=(W2, 62 * MM))

    # (a) 측정오차 → 예측오차, 1차 근사선과 함께
    ax = axes[0]
    xs = [p[0] for p in pts]
    ax.plot(xs, [p[1] for p in pts], LINES[0], color=C[0], marker=MARKERS[0],
            ms=5, mfc="none", mew=1.3, label="measured (uncorrected probe)")
    lim = max(xs) * 1.05 if xs else 1
    ax.plot([0, lim], [0, lim * A], LINES[1], color=INK2, lw=1.1,
            label=f"first-order budget  ε·A  (A={A:.3f})")
    ax.plot([0, lim], [0, lim], ":", color=MUTED, lw=1.0,
            label="no amplification (A = 1)")
    ax.set_xlabel("Capture measurement error |ε| (%)")
    ax.set_ylabel("Predicted-throughput error (%)")
    ax.set_title("(a) Propagation against ground truth", loc="left")
    ax.legend(fontsize=6.4, loc="upper left")
    _grid(ax, "both")

    # (b) 보정 전/후 — 로그축이라야 5자릿수 차이가 보인다
    ax = axes[1]
    labels = [p[4] for p in pts]
    idx = range(len(pts))
    FLOOR = 1e-4
    ax.barh([i + 0.2 for i in idx], [max(FLOOR, p[1]) for p in pts], height=0.38,
            color=C[1], edgecolor="white", linewidth=0.6, label="uncorrected")
    ax.barh([i - 0.2 for i in idx], [max(FLOOR, p[3]) for p in pts], height=0.38,
            color=C[2], edgecolor="white", linewidth=0.6, hatch="///",
            label="capture-loss corrected")
    ax.set_yticks(list(idx))
    ax.set_yticklabels(labels, fontsize=6.6)
    ax.set_xscale("log")
    ax.set_xlabel("Predicted-throughput error (%, log)")
    ax.set_title("(b) Effect of the capture-loss correction", loc="left")
    ax.legend(fontsize=6.6, loc="lower right")
    _grid(ax, "x")

    fig.tight_layout()
    _save(fig, outdir, "fig2_bridge")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 3 — 실측 부하계수 분포와 클립 바닥
# ─────────────────────────────────────────────────────────────────────────────
def fig_field(outdir: str, data: Dict[str, Any],
              lf_min: float = 0.30) -> None:
    _style()
    caps = data.get("captures") or []
    if not caps:
        return
    fig, axes = plt.subplots(1, 2, figsize=(W2, 68 * MM))

    # (a) LF 분위수 — 캡처×방향별. 로그축(두 자릿수 아래라 선형으로는 안 보인다)
    ax = axes[0]
    labels, lo, mid, hi, mx, cols = [], [], [], [], [], []
    for ci, c in enumerate(caps):
        # 파일명이 길어 축에서 겹친다. 날짜(MMDD)와 시작시각만 남긴다.
        stem = c["meta"]["pcap"].replace(".pcap", "")
        parts = stem.split("_")
        name = (f"{parts[0][2:4]}/{parts[0][4:6]}\n{parts[1][:2]}:{parts[1][2:]}"
                if len(parts) >= 2 and len(parts[0]) >= 6 else stem)
        for di, d in enumerate(("DL", "UL")):
            x = (c.get("distribution") or {}).get(d)
            if not x:
                continue
            r = x["lf_raw"]
            labels.append(f"{name}\n{d}")
            lo.append(max(r["p05"], 1e-6)); mid.append(max(r["p50"], 1e-6))
            hi.append(max(r["p95"], 1e-6)); mx.append(max(r["max"], 1e-6))
            cols.append(C[0] if d == "DL" else C[1])
    idx = list(range(len(labels)))
    for i in idx:
        ax.plot([i, i], [lo[i], hi[i]], "-", color=cols[i], lw=2.2,
                solid_capstyle="round", zorder=2)
        ax.plot([i], [mid[i]], "o", color=cols[i], ms=6, mfc="white", mew=1.6,
                zorder=3)
        ax.plot([i], [mx[i]], "^", color=cols[i], ms=5, mfc="none", mew=1.2,
                zorder=3)
    ax.axhline(lf_min, color=INK, lw=1.4, ls=(0, (5, 2)), zorder=4)
    ax.text(len(idx) - 0.5, lf_min * 1.25, f"clipping floor LF_min = {lf_min:g}",
            fontsize=6.8, color=INK, ha="right")
    ax.set_yscale("log")
    ax.set_xticks(idx)
    ax.set_xticklabels(labels, fontsize=5.6)
    ax.set_ylabel("Load factor  R / P  (log)")
    ax.set_title("(a) Measured load factors vs. the floor", loc="left")
    ax.plot([], [], "o", color=MUTED, mfc="white", mew=1.4, label="median")
    ax.plot([], [], "-", color=MUTED, lw=2.2, label="p05–p95")
    ax.plot([], [], "^", color=MUTED, mfc="none", label="max")
    ax.legend(fontsize=6.4, loc="lower left")
    _grid(ax, "y")

    # (b) 클립이 만들어내는 이득 과대평가
    ax = axes[1]
    by = {f.name: f for f in FEATURES}
    feats = [by[n] for n in ("SBFD", "MIMO-adv", "EN-DC")]
    xs = [10 ** (-5.2 + 5.2 * i / 300) for i in range(301)]
    true_g = [math.prod(f.gain(x) for f in feats) for x in xs]
    used_g = [math.prod(f.gain(max(lf_min, x)) for f in feats) for x in xs]
    ax.plot(xs, true_g, LINES[0], color=C[2], lw=1.6,
            label="physically consistent  Π g(LF)")
    ax.plot(xs, used_g, LINES[1], color=C[1], lw=1.6,
            label="as specified, with clip")
    ax.fill_between(xs, true_g, used_g, color=C[1], alpha=0.15)
    ax.axvline(lf_min, color=INK, lw=1.2, ls=(0, (5, 2)))
    # 실측 구간
    p50 = [(( c.get("distribution") or {}).get("DL") or {}).get("lf_raw", {}).get("p50")
           for c in caps]
    p50 = [x for x in p50 if x]
    if p50:
        ax.axvspan(min(p50), max(p50), color=C[0], alpha=0.20, zorder=0)
        ax.annotate("measured\noperating range", xy=(max(p50), 1.05),
                    xytext=(2e-3, 1.55), fontsize=6.6, color=C[0],
                    arrowprops=dict(arrowstyle="-|>", color=C[0], lw=0.8))
    ax.set_xscale("log")
    ax.set_xlabel("True load factor (log)")
    ax.set_ylabel("Composed gain  Π g")
    ax.set_title("(b) Gain manufactured by the clip", loc="left")
    ax.legend(fontsize=6.6, loc="upper left")
    _grid(ax, "both")

    fig.tight_layout()
    _save(fig, outdir, "fig3_field")


def main() -> int:
    ap = argparse.ArgumentParser(description="Physical Communication 그림")
    ap.add_argument("--data", default="ranemu/paper/v4")
    ap.add_argument("--out", default="ranemu/paper/physcomm/figures")
    a = ap.parse_args()
    print(f"데이터: {a.data} → 그림: {a.out}")
    field = _load(a.data, "M_lf_field.json")
    fig_propagation(a.out, field)
    b = _load(a.data, "L_lf_bridge.json")
    if b:
        fig_bridge(a.out, b)
    if field:
        fig_field(a.out, field)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
