#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.paper.figures — 논문 그림 생성.

설계 원칙
=========
* **색은 마지막에.** 형태(무엇을 보여야 하는가)를 먼저 고르고 색을 배정한다.
* **색만으로 식별하지 않는다.** 학술지는 흑백 인쇄가 흔하므로 계열마다
  마커 모양과 선 종류를 함께 바꾼다(이중 인코딩). 색각이상 안전 팔레트를
  고정 순서로 쓰되, 색이 사라져도 읽히게 만든다.
* **이중 y축 금지.** 척도가 다른 두 측정치는 패널을 나눈다.
* 폭은 학술지 규격에 맞춘다: 1단 89 mm, 2단 183 mm.

출력: PNG(600 dpi, 워드 삽입용) + PDF(벡터, 최종 조판용).
"""
from __future__ import annotations

import json
import math
import os
from typing import Any, Dict, List, Optional, Sequence, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
from matplotlib.ticker import FuncFormatter, LogLocator

# ── 고정 순서 범주형 팔레트(색각이상 검증 통과) ────────────────────────────
C = ["#0072B2", "#D55E00", "#009E73", "#E69F00", "#CC79A7"]
INK = "#1a1a1a"
INK2 = "#4d4d4d"
MUTED = "#8a8a8a"
GRID = "#d9d9d9"
SURFACE = "#ffffff"

# 이중 인코딩용(색이 사라져도 계열이 구분되도록)
MARKERS = ["o", "s", "^", "D", "v"]
LINES = ["-", "--", "-.", ":", (0, (3, 1, 1, 1))]
HATCH = ["", "///", "...", "\\\\\\", "xxx"]

MM = 1 / 25.4
W1 = 89 * MM          # 1단
W2 = 183 * MM         # 2단
W15 = 140 * MM        # 1.5단


def _style() -> None:
    plt.rcParams.update({
        "figure.facecolor": SURFACE, "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.family": "DejaVu Sans", "font.size": 8,
        "axes.labelsize": 8, "axes.titlesize": 8.5,
        "xtick.labelsize": 7.5, "ytick.labelsize": 7.5,
        "legend.fontsize": 7.5, "legend.frameon": False,
        "axes.edgecolor": INK2, "axes.linewidth": 0.6,
        "axes.labelcolor": INK, "text.color": INK,
        "xtick.color": INK2, "ytick.color": INK2,
        "xtick.major.width": 0.6, "ytick.major.width": 0.6,
        "xtick.major.size": 2.5, "ytick.major.size": 2.5,
        "grid.color": GRID, "grid.linewidth": 0.5,
        "lines.linewidth": 1.4, "lines.markersize": 4,
        "axes.spines.top": False, "axes.spines.right": False,
        "figure.dpi": 150, "savefig.bbox": "tight", "savefig.pad_inches": 0.02,
    })


def _grid(ax, axis: str = "y") -> None:
    ax.grid(True, axis=axis, alpha=0.7, zorder=0)
    ax.set_axisbelow(True)


def _save(fig, outdir: str, name: str) -> None:
    os.makedirs(outdir, exist_ok=True)
    for ext, dpi in (("png", 600), ("pdf", 600)):
        fig.savefig(os.path.join(outdir, f"{name}.{ext}"), dpi=dpi)
    plt.close(fig)
    print(f"  그림: {name}.png / .pdf")


def _load(d: str, name: str) -> Optional[Dict[str, Any]]:
    p = os.path.join(d, name)
    if not os.path.exists(p):
        print(f"  (건너뜀: {name} 없음)")
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _m(a: Any, key: str = "mean", default: float = float("nan")) -> float:
    """agg() 딕셔너리에서 값을 꺼낸다(스칼라면 그대로)."""
    if isinstance(a, dict):
        v = a.get(key)
        return float(v) if v is not None else default
    return float(a) if a is not None else default


def _sd(a: Any) -> float:
    return _m(a, "sd", 0.0) if isinstance(a, dict) else 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 그림 1 — 시스템 구조
# ─────────────────────────────────────────────────────────────────────────────
def fig_architecture(outdir: str) -> None:
    _style()
    fig, ax = plt.subplots(figsize=(W2, 78 * MM))
    ax.set_xlim(0, 100); ax.set_ylim(0, 56); ax.axis("off")

    def box(x, y, w, h, label, sub="", fc="#f2f6fa", ec=C[0], lw=0.9, fs=7.5):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5,rounding_size=1.2",
                                    fc=fc, ec=ec, lw=lw, zorder=2))
        ax.text(x + w / 2, y + h / 2 + (1.4 if sub else 0), label, ha="center",
                va="center", fontsize=fs, color=INK, zorder=3, weight="bold")
        if sub:
            ax.text(x + w / 2, y + h / 2 - 2.4, sub, ha="center", va="center",
                    fontsize=6.4, color=INK2, zorder=3)

    def arrow(x1, y1, x2, y2, label="", color=INK2, style="-|>", off=1.2, fs=6.4):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                                     mutation_scale=8, lw=0.9, color=color, zorder=1))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + off, label, ha="center",
                    va="bottom", fontsize=fs, color=color, zorder=3)

    # 에뮬레이터(왼쪽)
    ax.add_patch(FancyBboxPatch((1.5, 3), 40, 50, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc="#fbfcfd", ec=MUTED, lw=0.7, ls=(0, (4, 2)), zorder=0))
    ax.text(21.5, 50.6, "RAN emulator (this work)", ha="center", fontsize=8,
            color=INK, weight="bold")

    box(4, 41, 16, 6.6, "Feature plugins", "RedCap · NTN · URLLC · XR …", ec=C[2])
    box(22.5, 41, 16, 6.6, "Physical model", "TS 38.306 · TR 38.901 · TS 38.214", ec=C[2])
    box(4, 31, 16, 6.6, "UE state machine", "5G-AKA · NAS security", ec=C[0])
    box(22.5, 31, 16, 6.6, "Traffic shaper", "token bucket · delay · loss", ec=C[0])
    box(4, 21, 34.5, 6.2, "gNB orchestrator", "NGAP/APER · GTP-U · single event loop", ec=C[0])
    box(4, 10.5, 34.5, 6.6, "Ground-truth manifest",
        "SUPI ↔ UE IP ↔ TEID · injected bytes · radio profile", ec=C[1], fc="#fdf4ee")

    arrow(12, 41, 12, 37.9)
    arrow(30.5, 41, 30.5, 37.9)
    arrow(12, 31, 12, 27.4)
    arrow(30.5, 31, 30.5, 27.4)
    arrow(21.2, 21, 21.2, 17.3)

    # 코어(오른쪽)
    box(58, 40, 34, 8, "Production 5G core", "AMF · SMF · UPF", ec=C[0], fc="#f2f6fa")
    box(58, 26.5, 34, 8, "Capture path", "SPAN / TAP — lossy, coalescing, duplicating",
        ec=C[1], fc="#fdf4ee")
    box(58, 15.5, 34, 7, "Passive probe", "per-UE throughput estimate", ec=C[1], fc="#fdf4ee")
    box(58, 4, 34, 7.4, "Corrected estimate", "in-band counter gaps → loss → rate",
        ec=C[2], fc="#f0faf6")

    arrow(41.5, 46.5, 58, 45, "N2  NGAP/SCTP", color=C[0], off=0.9)
    arrow(41.5, 41.0, 58, 42.0, "N3  GTP-U", color=C[0], off=-2.6)
    arrow(75, 40, 75, 34.7, "mirror")
    arrow(75, 26.5, 75, 22.7)
    arrow(75, 15.5, 75, 11.6, "§3.3")

    # 대조(정답 ↔ 프로브)
    ax.add_patch(FancyArrowPatch((38.5, 13.8), (58, 8.5), arrowstyle="<|-|>",
                                 mutation_scale=8, lw=1.1, color=C[1],
                                 connectionstyle="arc3,rad=-0.13", zorder=1))
    ax.text(48, 15.2, "join by IMSI → UE IP → TEID\nper-UE measurement error",
            ha="center", va="bottom", fontsize=6.6, color=C[1], weight="bold")

    _save(fig, outdir, "fig1_architecture")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 2 — 프로브 오차는 캡처 손실과 1:1, 보정은 그것을 제거
# ─────────────────────────────────────────────────────────────────────────────
def fig_probe_error(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = data["rows"]
    pts = [(_m(r["actual_loss_pct"]), _m(r["probe_error_pct"]),
            _m(r["corrected_error_pct"]), _sd(r["probe_error_pct"]),
            _sd(r["corrected_error_pct"]), r["mechanism"])
           for r in rows if not math.isnan(_m(r["probe_error_pct"]))]
    pts.sort()

    fig, axes = plt.subplots(1, 2, figsize=(W2, 66 * MM))

    # (a) 프로브 오차 vs 주입 손실.
    # 범주는 손실 **기전**으로 셋만 둔다: 크기독립 손실 / 버스트(tail-drop) /
    # 패킷을 지우지 않는 손상. 원자료의 7개 라벨을 그대로 쓰면 색이 순환해
    # 서로 다른 계열이 같은 색·마커를 갖게 되고, 그림의 논지(두 기전이 서로
    # 다르게 거동한다)도 흐려진다.
    def group(mech: str) -> str:
        if mech in ("uniform", "mixed"):
            return "size-independent loss"
        if mech == "tail-drop":
            return "burst loss (tail-drop)"
        return "no packet loss"

    ax = axes[0]
    lim = max(p[0] for p in pts) * 1.06
    ax.plot([0, lim], [0, -lim], color=MUTED, lw=1.0, ls=(0, (4, 2)), zorder=1)
    ax.text(lim * 0.60, -lim * 0.72, "error = −loss", fontsize=6.8,
            color=MUTED, ha="left", va="center", rotation=-33,
            rotation_mode="anchor")
    for k, g in enumerate(["size-independent loss", "burst loss (tail-drop)",
                           "no packet loss"]):
        sel = [p for p in pts if group(p[5]) == g]
        if not sel:
            continue
        ax.errorbar([p[0] for p in sel], [p[1] for p in sel],
                    yerr=[p[3] for p in sel], fmt=MARKERS[k],
                    color=C[k], ms=4.4, lw=0, elinewidth=0.8,
                    capsize=1.6, mfc="none", mew=1.2, label=g, zorder=3)
    # 관계가 깨지는 두 점을 지목한다 — 그림의 핵심 관찰
    off = sorted([p for p in pts if group(p[5]) == "burst loss (tail-drop)"
                  and abs(p[1]) < p[0] - 8], key=lambda p: -p[0])
    if off:
        p0 = off[0]
        ax.annotate("phase detector collapses:\nerror ≪ loss",
                    xy=(p0[0], p0[1]), xytext=(p0[0] - 34, p0[1] + 22),
                    fontsize=6.6, color=C[1], ha="left",
                    arrowprops=dict(arrowstyle="-|>", color=C[1], lw=0.8,
                                    shrinkA=0, shrinkB=3))
    ax.set_xlabel("Injected capture loss (%)")
    ax.set_ylabel("Probe throughput error (%)")
    ax.set_title("(a) Uncorrected passive probe", loc="left")
    ax.legend(loc="lower left", handletextpad=0.4)
    _grid(ax, "both")

    # (b) 보정 후 오차 — 축척이 5자리 다르므로 별도 패널.
    # 계열 인코딩은 (a) 와 동일하게 유지한다(같은 색=같은 조건군).
    ax = axes[1]
    ax.axhline(0, color=MUTED, lw=0.8, ls=(0, (4, 2)), zorder=1)
    for k, g in enumerate(["size-independent loss", "burst loss (tail-drop)",
                           "no packet loss"]):
        sel = [p for p in pts if group(p[5]) == g]
        if not sel:
            continue
        ax.errorbar([p[0] for p in sel], [p[2] for p in sel],
                    yerr=[p[4] for p in sel], fmt=MARKERS[k], color=C[k],
                    ms=4.4, lw=0, elinewidth=0.8, capsize=1.6, mfc="none",
                    mew=1.2, zorder=3)
    ys = [p[2] for p in pts]
    es = [p[4] for p in pts]
    ax.set_xlabel("Injected capture loss (%)")
    ax.set_ylabel("Corrected throughput error (%)")
    ax.set_title("(b) After loss correction", loc="left")
    m = max(0.004, max(abs(y) + e for y, e in zip(ys, es)) * 1.35)
    ax.set_ylim(-m, m)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:+.3f}"))
    _grid(ax, "both")

    fig.tight_layout(w_pad=2.0)
    _save(fig, outdir, "fig2_probe_error_and_correction")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 3 — 손실률 추정 정확도
# ─────────────────────────────────────────────────────────────────────────────
def fig_loss_estimate(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = [r for r in data["rows"] if _m(r["actual_loss_pct"]) > 0.5]
    rows.sort(key=lambda r: _m(r["actual_loss_pct"]))
    x = [_m(r["actual_loss_pct"]) for r in rows]
    y = [_m(r["estimated_loss_pct"]) for r in rows]
    err = [abs(_m(r["loss_estimate_error_pp"])) for r in rows]

    fig, axes = plt.subplots(1, 2, figsize=(W2, 62 * MM),
                             gridspec_kw={"width_ratios": [1, 1]})
    ax = axes[0]
    lim = max(x) * 1.06
    ax.plot([0, lim], [0, lim], color=MUTED, lw=1.0, ls=(0, (4, 2)), zorder=1,
            label="y = x")
    ax.plot(x, y, MARKERS[0], color=C[0], ms=4.2, mfc="none", mew=1.1, lw=0,
            zorder=3, label="estimate")
    ax.set_xlabel("Injected loss (%)")
    ax.set_ylabel("Estimated loss (%)")
    ax.set_title("(a) Loss estimate vs. injected loss", loc="left")
    ax.legend(loc="upper left")
    _grid(ax, "both")

    ax = axes[1]
    ax.bar(range(len(err)), err, color=C[2], width=0.72, zorder=3,
           edgecolor=SURFACE, linewidth=0.8)
    ax.set_xticks(range(len(err)))
    ax.set_xticklabels([f"{v:.0f}" for v in x], rotation=0)
    ax.set_xlabel("Injected loss (%)")
    ax.set_ylabel("|estimate − injected|  (pp)")
    ax.set_title("(b) Absolute estimation error", loc="left")
    _grid(ax, "y")

    fig.tight_layout(w_pad=2.0)
    _save(fig, outdir, "fig3_loss_estimate")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 4 — 보정이 깨지는 영역
# ─────────────────────────────────────────────────────────────────────────────
def fig_limits(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = data["rows"]
    profiles: List[str] = []
    for r in rows:
        if r["size_profile"] not in profiles:
            profiles.append(r["size_profile"])
    order = ["uniform-1400", "uniform-random-64..1400", "trimodal-64/512/1400",
             "bimodal-64/1400"]
    profiles = [p for p in order if p in profiles] + \
               [p for p in profiles if p not in order]
    short = {"uniform-1400": "uniform\n1400 B",
             "uniform-random-64..1400": "uniform rand.\n64–1400 B",
             "trimodal-64/512/1400": "trimodal\n64/512/1400 B",
             "bimodal-64/1400": "bimodal\n64/1400 B"}

    def get(p: str, mech: str, key: str) -> Tuple[float, float]:
        for r in rows:
            if r["size_profile"] == p and r["loss_mechanism"] == mech:
                return _m(r[key]), _sd(r[key])
        return float("nan"), 0.0

    fig, axes = plt.subplots(1, 2, figsize=(W2, 66 * MM), sharey=True)
    for ax, mech, title in ((axes[0], "size-independent", "(a) Size-independent loss"),
                            (axes[1], "tail-drop", "(b) Size-correlated loss (tail-drop)")):
        idx = range(len(profiles))
        w = 0.38
        series = [("uncorrected", "probe_err_pct", C[1], HATCH[0]),
                  ("corrected", "corrected_err_pct", C[2], HATCH[1])]
        for k, (lab, key, col, hat) in enumerate(series):
            vals = [get(p, mech, key)[0] for p in profiles]
            errs = [get(p, mech, key)[1] for p in profiles]
            ax.bar([i + (k - 0.5) * w for i in idx], vals, width=w * 0.92,
                   yerr=errs, color=col, label=lab, zorder=3, hatch=hat,
                   edgecolor=SURFACE, linewidth=0.8,
                   error_kw={"elinewidth": 0.8, "capsize": 1.6, "ecolor": INK2})
        ax.axhline(0, color=INK2, lw=0.7)
        ax.set_xticks(list(idx))
        ax.set_xticklabels([short.get(p, p) for p in profiles], fontsize=6.8)
        ax.set_title(title, loc="left")
        _grid(ax, "y")
        # 플래그 표시
        for i, p in enumerate(profiles):
            fr = None
            for r in rows:
                if r["size_profile"] == p and r["loss_mechanism"] == mech:
                    fr = r.get("flag_rate")
            if fr is not None:
                ax.text(i, 4.5, "flagged" if fr >= 0.5 else "clean",
                        ha="center", fontsize=6.2,
                        color=C[1] if fr >= 0.5 else MUTED)
    axes[0].set_ylabel("Throughput error (%)")
    axes[0].legend(loc="lower left")
    fig.tight_layout(w_pad=1.4)
    _save(fig, outdir, "fig4_correction_limits")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 5 — 검출기 동작특성
# ─────────────────────────────────────────────────────────────────────────────
def fig_detector(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    roc = data["roc"]
    cur = data["current_operating_point"]
    best = data.get("best_youden") or {}

    fig, axes = plt.subplots(1, 2, figsize=(W2, 64 * MM))

    ax = axes[0]
    th = [r["threshold"] for r in roc]
    sens = [r["sensitivity"] for r in roc]
    spec = [r["specificity"] for r in roc]
    ax.plot(th, sens, LINES[0], color=C[0], marker=MARKERS[0], ms=2.8,
            markevery=3, label="sensitivity")
    ax.plot(th, spec, LINES[1], color=C[1], marker=MARKERS[1], ms=2.8,
            markevery=3, label="specificity")
    ax.axvline(data.get("current_threshold", 0.25), color=MUTED, lw=0.9,
               ls=(0, (1, 2)))
    ax.text(data.get("current_threshold", 0.25) - 0.03, 0.10,
            "deployed\nCV = 0.25", fontsize=6.4, color=INK2, ha="right")
    if best.get("threshold") is not None:
        ax.axvline(best["threshold"], color=C[2], lw=0.9, ls=(0, (3, 1, 1, 1)))
        ax.text(best["threshold"] + 0.02, 0.30,
                f"max Youden\nCV = {best['threshold']:.2f}", fontsize=6.4, color=C[2])
    ax.set_xlabel("Packet-size CV threshold")
    ax.set_ylabel("Rate")
    ax.set_ylim(-0.03, 1.06)
    ax.set_title("(a) Operating characteristic", loc="left")
    ax.legend(loc="center right")
    _grid(ax, "both")

    ax = axes[1]
    sm = data.get("samples", [])
    # 값이 모두 0 이상이므로 순수 로그축을 쓴다(symlog 의 음수 구간은 여기서
    # 의미가 없고 축만 어지럽힌다). 정확히 0 인 점은 바닥값으로 눌러 표시한다.
    FLOOR = 1e-3
    for k, mech in enumerate(["size-independent", "tail-drop"]):
        sel = [s for s in sm if s["mechanism"] == mech]
        ax.plot([s["size_cv"] for s in sel],
                [max(abs(s["corrected_abs_err_pct"]), FLOOR) for s in sel],
                MARKERS[k], color=C[k], ms=3.6, mfc="none", mew=1.0, lw=0,
                label=mech, zorder=3)
    thr = data.get("definition", {}).get("bias_threshold_pct", 5.0)
    ax.axhline(thr, color=MUTED, lw=0.9, ls=(0, (4, 2)))
    ax.axvline(data.get("current_threshold", 0.25), color=MUTED, lw=0.9,
               ls=(0, (1, 2)))
    ax.set_yscale("log")
    ax.set_ylim(FLOOR * 0.6, 200)
    ax.text(2.28, thr * 1.4, f"bias criterion {thr:g}%", fontsize=6.4,
            color=INK2, ha="right")
    ax.text(0.28, FLOOR * 1.1, "CV = 0.25", fontsize=6.4, color=INK2)
    ax.set_xlabel("Observed packet-size CV")
    ax.set_ylabel("|corrected error| (%, log)")
    ax.set_title("(b) Residual error vs. size heterogeneity", loc="left")
    ax.legend(loc="lower right", handletextpad=0.4)
    _grid(ax, "both")

    fig.tight_layout(w_pad=2.0)
    _save(fig, outdir, "fig5_detector")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 6 — 기준선 비교
# ─────────────────────────────────────────────────────────────────────────────
def fig_baselines(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = data["rows"]
    labels = [r["condition"] for r in rows]
    # B1(전역 카운터)은 오차가 세 자리라 같은 축에 그리면 나머지가 전부 0 선으로
    # 뭉갠다. 축을 나누기보다(이중축 금지) 패널을 나눈다.
    series = [("B0 no correction", "B0_no_correction_err_pct", C[1], HATCH[0]),
              ("B2 unsigned difference", "B2_unsigned_diff_err_pct", C[3], HATCH[2]),
              ("B3 proposed", "B3_proposed_err_pct", C[2], HATCH[1]),
              ("B4 oracle", "B4_oracle_err_pct", C[0], HATCH[3])]

    fig, axes = plt.subplots(1, 2, figsize=(W2, 64 * MM),
                             gridspec_kw={"width_ratios": [2.1, 1]})
    ax = axes[0]
    idx = range(len(labels))
    w = 0.2
    for k, (lab, key, col, hat) in enumerate(series):
        vals = [_m(r[key]) for r in rows]
        errs = [_sd(r[key]) for r in rows]
        ax.bar([i + (k - 1.5) * w for i in idx], vals, width=w * 0.9, yerr=errs,
               color=col, label=lab, zorder=3, hatch=hat, edgecolor=SURFACE,
               linewidth=0.7,
               error_kw={"elinewidth": 0.7, "capsize": 1.3, "ecolor": INK2})
    ax.axhline(0, color=INK2, lw=0.7)
    ax.set_xticks(list(idx))
    ax.set_xticklabels(labels, fontsize=6.6, rotation=14, ha="right")
    ax.set_ylabel("Throughput error (%)")
    ax.set_title("(a) B0, B2, B3, B4", loc="left")
    ax.legend(loc="lower left", ncol=2, handletextpad=0.4, columnspacing=1.0,
              fontsize=6.8)
    _grid(ax, "y")

    ax = axes[1]
    key = "B1_global_counter_err_pct"
    vals = [_m(r[key]) for r in rows]
    ax.bar(list(idx), vals, width=0.66, yerr=[_sd(r[key]) for r in rows],
           color=C[4], zorder=3, hatch=HATCH[4], edgecolor=SURFACE, linewidth=0.7,
           error_kw={"elinewidth": 0.7, "capsize": 1.3, "ecolor": INK2})
    ax.axhline(0, color=INK2, lw=0.7)
    ax.set_xticks(list(idx))
    ax.set_xticklabels(labels, fontsize=6.0, rotation=45, ha="right")
    ax.set_ylabel("Throughput error (%)")
    ax.set_title("(b) B1 global counter — note scale", loc="left")
    _grid(ax, "y")

    fig.tight_layout(w_pad=1.8)
    _save(fig, outdir, "fig6_baselines")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 7 — feature 별 동적 범위
# ─────────────────────────────────────────────────────────────────────────────
def fig_features(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = [r for r in data["rows"] if _m(r["ul_applied_mbps"]) > 0]
    rows.sort(key=lambda r: _m(r["ul_applied_mbps"]))
    names = [r["group"] for r in rows]
    applied = [_m(r["ul_applied_mbps"]) for r in rows]
    measured = [_m(r["ul_measured_mbps"]) for r in rows]
    rtt = [_m(r["rtt_ms"]) for r in rows]

    fig, axes = plt.subplots(1, 2, figsize=(W2, 68 * MM))

    ax = axes[0]
    lo = min(min(applied), min(measured)) * 0.45
    hi = max(max(applied), max(measured)) * 2.2
    ax.plot([lo, hi], [lo, hi], color=MUTED, lw=1.0, ls=(0, (4, 2)), zorder=1)
    ax.plot(applied, measured, MARKERS[0], color=C[0], ms=4.6, mfc="none",
            mew=1.2, lw=0, zorder=3)
    for n, a, m in zip(names, applied, measured):
        ax.annotate(n, (a, m), textcoords="offset points", xytext=(4, -6),
                    fontsize=6.0, color=INK2)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlim(lo, hi); ax.set_ylim(lo, hi)
    ax.set_xlabel("Configured rate (Mb/s, log)")
    ax.set_ylabel("Measured rate (Mb/s, log)")
    ax.set_title("(a) Rate reproduction over 4 decades", loc="left")
    _grid(ax, "both")

    ax = axes[1]
    ordr = sorted(range(len(names)), key=lambda i: rtt[i])
    ax.barh([names[i] for i in ordr], [rtt[i] for i in ordr], color=C[0],
            height=0.62, zorder=3, edgecolor=SURFACE, linewidth=0.7)
    ax.set_xscale("log")
    ax.set_xlabel("Modelled RTT (ms, log)")
    ax.set_title("(b) Latency signature per feature", loc="left")
    ax.tick_params(axis="y", labelsize=6.6)
    _grid(ax, "x")

    fig.tight_layout(w_pad=2.0)
    _save(fig, outdir, "fig7_features")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 8 — 확장성과 용량(패널 분리: 이중 y축 금지)
# ─────────────────────────────────────────────────────────────────────────────
def fig_scaling(outdir: str, scal: Optional[Dict[str, Any]],
                ceil: Optional[Dict[str, Any]]) -> None:
    _style()
    ncol = (1 if scal else 0) + (1 if scal else 0) + (1 if ceil else 0)
    if ncol == 0:
        return
    fig, axes = plt.subplots(1, ncol, figsize=(W2, 60 * MM))
    if ncol == 1:
        axes = [axes]
    i = 0
    if scal:
        rows = scal["rows"]
        n = [r["n_ue"] for r in rows]
        ax = axes[i]; i += 1
        ax.errorbar(n, [_m(r["reg_ms_mean"]) for r in rows],
                    yerr=[_sd(r["reg_ms_mean"]) for r in rows],
                    fmt=MARKERS[0] + LINES[0], color=C[0], ms=4, mfc="none",
                    mew=1.1, elinewidth=0.8, capsize=1.8, label="mean", zorder=3)
        ax.errorbar(n, [_m(r["reg_ms_max"]) for r in rows],
                    yerr=[_sd(r["reg_ms_max"]) for r in rows],
                    fmt=MARKERS[1] + LINES[1], color=C[1], ms=4, mfc="none",
                    mew=1.1, elinewidth=0.8, capsize=1.8, label="max", zorder=3)
        ax.set_xlabel("Concurrent UEs")
        ax.set_ylabel("Registration latency (ms)")
        ax.set_title("(a) Control-plane latency", loc="left")
        ax.legend(loc="upper left")
        _grid(ax, "both")

        ax = axes[i]; i += 1
        ax.errorbar(n, [_m(r["agg_ul_mbps"]) for r in rows],
                    yerr=[_sd(r["agg_ul_mbps"]) for r in rows],
                    fmt=MARKERS[2] + LINES[0], color=C[2], ms=4, mfc="none",
                    mew=1.1, elinewidth=0.8, capsize=1.8, zorder=3)
        ax.set_xlabel("Concurrent UEs")
        ax.set_ylabel("Aggregate uplink (Mb/s)")
        ax.set_title("(b) Aggregate injected load", loc="left")
        _grid(ax, "both")
    if ceil:
        rows = ceil["rows"]
        ax = axes[i]
        n = [r["n_ue"] for r in rows]
        ax.errorbar(n, [_m(r["throughput_mbps"]) for r in rows],
                    yerr=[_sd(r["throughput_mbps"]) for r in rows],
                    fmt=MARKERS[3] + LINES[0], color=C[0], ms=4, mfc="none",
                    mew=1.1, elinewidth=0.8, capsize=1.8, zorder=3)
        ax.axhline(1000, color=MUTED, lw=0.9, ls=(0, (4, 2)))
        ax.text(n[0], 1015, "1 GbE mirror", fontsize=6.4, color=INK2)
        ax.set_xlabel("Concurrent UEs")
        ax.set_ylabel("User-plane throughput (Mb/s)")
        ax.set_title("(c) Single-process capacity", loc="left")
        _grid(ax, "both")
    fig.tight_layout(w_pad=2.0)
    _save(fig, outdir, "fig8_scaling")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 9 — 쉐이퍼 충실도
# ─────────────────────────────────────────────────────────────────────────────
def fig_shaper(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = data["rows"]
    tgt = [r["target_mbps"] for r in rows]
    err = [_m(r["err_pct"]) for r in rows]
    sd = [_sd(r["err_pct"]) for r in rows]
    clamped = [_m(r["applied_mbps"]) < t * 0.99 for r, t in zip(rows, tgt)]

    fig, ax = plt.subplots(figsize=(W1, 58 * MM))
    x = range(len(tgt))
    cols = [C[1] if c else C[0] for c in clamped]
    ax.bar(list(x), err, yerr=sd, width=0.66, color=cols, zorder=3,
           edgecolor=SURFACE, linewidth=0.7,
           error_kw={"elinewidth": 0.8, "capsize": 1.6, "ecolor": INK2})
    ax.axhline(0, color=INK2, lw=0.7)
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{t:g}" for t in tgt], fontsize=7)
    ax.set_xlabel("Target uplink rate (Mb/s)")
    ax.set_ylabel("Rate error (%)")
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(facecolor=C[0], label="within link budget"),
                       Patch(facecolor=C[1], label="clamped by link budget")],
              loc="upper left", fontsize=6.6)
    _grid(ax, "y")
    fig.tight_layout()
    _save(fig, outdir, "fig9_shaper")


# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# 그림 10 — 요구 조항에서 판정까지의 사슬 (통합본 Figure 1)
# ─────────────────────────────────────────────────────────────────────────────
def fig_chain(outdir: str) -> None:
    """이 도구의 논지 자체를 한 장으로: 규격 조항이 어떻게 판정이 되는가."""
    _style()
    fig, ax = plt.subplots(figsize=(W2, 80 * MM))
    ax.set_xlim(-1, 101); ax.set_ylim(-2, 52); ax.axis("off")

    def node(x, y, w, h, title, sub, ec, fc):
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                                    boxstyle="round,pad=0.5,rounding_size=1.1",
                                    fc=fc, ec=ec, lw=1.0, zorder=2))
        ax.text(x + w / 2, y + h / 2 + 1.7, title, ha="center", va="center",
                fontsize=7.4, weight="bold", color=INK, zorder=3)
        ax.text(x + w / 2, y + h / 2 - 2.1, sub, ha="center", va="center",
                fontsize=6.2, color=INK2, zorder=3)

    def arrow(x1, y1, x2, y2, label="", dy=1.3, color=INK2):
        ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
                                     mutation_scale=9, lw=1.0, color=color,
                                     zorder=1))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + dy, label, ha="center",
                    va="bottom", fontsize=6.0, color=color, zorder=3)

    # 윗줄: 규격 → 목표 → 시나리오 → 모집단
    node(1.5, 34, 21, 12, "3GPP requirement", "TS 22.104 · 22.186 · 23.501",
         C[0], "#f2f6fa")
    node(27, 34, 20, 12, "KPI target", "predicate + provenance\n(spec·version·clause·kind)",
         C[0], "#f2f6fa")
    node(51.5, 34, 20, 12, "Service scenario", "phases · KPI set", C[0], "#f2f6fa")
    node(76, 34, 22.5, 12, "UE population", "features → radio model", C[2], "#f0faf6")
    arrow(22.5, 40, 27, 40)
    arrow(47, 40, 51.5, 40)
    arrow(71.5, 40, 76, 40)

    # 아랫줄(역방향): 트래픽 → 실코어 → 실측 → 통계 → 판정
    node(76, 14, 22.5, 12, "Derived traffic", "TS 38.306 · TR 38.901\n· TS 38.214",
         C[2], "#f0faf6")
    node(51.5, 14, 20, 12, "Real 5G core", "N2 NGAP · N3 GTP-U", C[1], "#fdf4ee")
    node(27, 14, 20, 12, "In-band measurement", "RTT · loss · survival", C[1],
         "#fdf4ee")
    node(1.5, 14, 21, 12, "Statistical gate", "Clopper–Pearson bound", C[1],
         "#fdf4ee")
    arrow(87, 34, 87, 26.3)
    arrow(76, 20, 71.5, 20)
    arrow(51.5, 20, 47, 20)
    arrow(27, 20, 22.5, 20)

    # 판정 상자 — 통계 게이트 바로 아래에 두어 연결선이 직선이 되게 한다
    node_w = 45
    ax.add_patch(FancyBboxPatch((1.5, 0.5), node_w, 9.0,
                                boxstyle="round,pad=0.5,rounding_size=1.1",
                                fc="#fbf6fa", ec=C[4], lw=1.2, zorder=2))
    ax.text(1.5 + node_w / 2, 6.6, "Requirement-traceable verdict", ha="center",
            fontsize=7.6, weight="bold", color=INK, zorder=3)
    ax.text(1.5 + node_w / 2, 3.0,
            "PASS · FAIL · INCONCLUSIVE · NOT MEASURABLE",
            ha="center", fontsize=6.4, color=C[4], zorder=3, weight="bold")
    arrow(12, 14, 12, 9.8, color=C[4])

    # 신뢰 근거 — 오른쪽 아래 빈 공간에 별도 블록으로 (상자와 겹치지 않게)
    ax.add_patch(FancyBboxPatch((52, 0.5), 46.5, 9.0,
                                boxstyle="round,pad=0.5,rounding_size=1.1",
                                fc="#fcfcfb", ec=MUTED, lw=0.7,
                                linestyle=(0, (4, 2)), zorder=2))
    ax.text(53.5, 7.6, "why the chain can be trusted", fontsize=6.6,
            style="italic", color=INK2, zorder=3)
    for k, t in enumerate((
            "physical model  →  traffic is representative of the service",
            "independent-oracle encoding  →  we inject what we intend",
            "incremental checksum  →  measuring does not perturb the load")):
        ax.text(53.5, 5.4 - k * 1.9, t, fontsize=5.5, color=MUTED, zorder=3)

    _save(fig, outdir, "fig10_chain")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 11 — 측정점과 측정 가능성 (통합본 Figure 2)
# ─────────────────────────────────────────────────────────────────────────────
def fig_measurement(outdir: str) -> None:
    """무엇을 어디서 재고, 무엇은 왜 잴 수 없는가."""
    _style()
    fig, axes = plt.subplots(2, 1, figsize=(W2, 92 * MM),
                             gridspec_kw={"height_ratios": [1.05, 1]})

    # (a) 측정점
    ax = axes[0]
    ax.set_xlim(0, 100); ax.set_ylim(0, 34); ax.axis("off")
    ax.set_title("(a) Timestamp points on the user-plane path", loc="left",
                 fontsize=8)
    boxes = [(2, "gNB emulator", C[2]), (28, "5G core\n(UPF)", C[1]),
             (54, "N6 reflector", C[0]), (80, "gNB emulator", C[2])]
    for x, lab, col in boxes:
        ax.add_patch(FancyBboxPatch((x, 16), 18, 11,
                                    boxstyle="round,pad=0.4,rounding_size=1.0",
                                    fc="#fbfcfd", ec=col, lw=1.0, zorder=2))
        ax.text(x + 9, 21.5, lab, ha="center", va="center", fontsize=6.8,
                color=INK, zorder=3)
    for x1, x2, t in ((20, 28, "t1"), (46, 54, "t2"), (72, 80, "t4")):
        ax.add_patch(FancyArrowPatch((x1, 21.5), (x2, 21.5), arrowstyle="-|>",
                                     mutation_scale=8, lw=1.0, color=INK2, zorder=1))
    for x, t, c in ((20.5, "t1", C[2]), (53.0, "t2", C[0]), (55.5, "t3", C[0]),
                    (79.5, "t4", C[2])):
        ax.text(x, 28.6, t, fontsize=7.2, color=c, weight="bold", ha="center")
    ax.text(50, 12.0, "rtt_wire = t4 − t1        "
                      "rtt_net = (t4 − t1) − (t3 − t2)",
            ha="center", fontsize=6.8, color=INK)
    ax.text(50, 7.6, "one-way delay claimable only when the two endpoints share a "
                     "clock domain", ha="center", fontsize=6.4, color=C[1],
            style="italic")
    ax.text(50, 3.2, "owd ≤ rtt_net  ⇒  a PASS on RTT basis is always safe",
            ha="center", fontsize=6.8, color=C[2], weight="bold")

    # (b) 측정 가능성 행렬
    ax = axes[1]
    metrics = ["offered / sent", "rtt_wire", "rtt_net", "reliability (RTT)",
               "one-way delay", "DL goodput", "registration"]
    cols = ["T0\nno peer", "T1\ndumb echo", "T2\nreflector", "T2 + shared\nclock"]
    #  2 = 측정 가능, 1 = 제한적, 0 = 불가
    M = [[2, 2, 2, 2],
         [0, 2, 2, 2],
         [0, 0, 2, 2],
         [0, 2, 2, 2],
         [0, 0, 0, 2],
         [0, 1, 2, 2],
         [2, 2, 2, 2]]
    shades = {0: "#f6f6f6", 1: "#fdf0e6", 2: "#eaf6f1"}
    marks = {0: ("—", MUTED), 1: ("limited", C[1]), 2: ("✓", C[2])}
    for i, row in enumerate(M):
        for j, v in enumerate(row):
            ax.add_patch(plt.Rectangle((j, len(M) - 1 - i), 1, 1,
                                       fc=shades[v], ec=SURFACE, lw=1.4))
            txt, col = marks[v]
            ax.text(j + 0.5, len(M) - 1 - i + 0.5, txt, ha="center", va="center",
                    fontsize=6.6, color=col, weight="bold")
    ax.set_xlim(0, len(cols)); ax.set_ylim(0, len(metrics))
    ax.set_xticks([j + 0.5 for j in range(len(cols))])
    ax.set_xticklabels(cols, fontsize=6.4)
    ax.set_yticks([len(metrics) - 1 - i + 0.5 for i in range(len(metrics))])
    ax.set_yticklabels(metrics, fontsize=6.6)
    ax.xaxis.tick_top(); ax.xaxis.set_label_position("top")
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0)
    ax.set_title("(b) What each deployment can measure — enforced in code",
                 loc="left", fontsize=8, pad=22)

    fig.tight_layout(h_pad=1.2)
    _save(fig, outdir, "fig11_measurement")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 12 — 계측기 유효 동작범위 (왕복지연의 편도 분해)
# ─────────────────────────────────────────────────────────────────────────────
def fig_envelope(outdir: str, pps: Optional[Dict[str, Any]],
                 bg: Optional[Dict[str, Any]]) -> None:
    """무엇이 제약인가: 패킷율이 아니라 배경 full-buffer 부하다."""
    _style()
    n = (1 if pps else 0) + (1 if bg else 0)
    if n == 0:
        return
    fig, axes = plt.subplots(1, n, figsize=(W2, 66 * MM))
    if n == 1:
        axes = [axes]
    i = 0

    def _panel(ax, rows, xkey, xlabel, title, logx=False):
        x = [r[xkey] for r in rows]
        series = [("RTT p50", "rtt_p50", C[0], MARKERS[0], LINES[0]),
                  ("owd_ul p50", "owd_ul_p50", C[1], MARKERS[1], LINES[1]),
                  ("owd_dl p50", "owd_dl_p50", C[2], MARKERS[2], LINES[2]),
                  ("access hold", "access_hold_ms", C[3], MARKERS[3], LINES[3])]
        for lab, key, col, mk, ls in series:
            y = [r.get(key) for r in rows]
            if all(v is None for v in y):
                continue
            xs = [a for a, b in zip(x, y) if b is not None]
            ys = [b for b in y if b is not None]
            ax.plot(xs, ys, ls, color=col, marker=mk, ms=3.8, mfc="none",
                    mew=1.1, label=lab, zorder=3)
        ax.axhline(0.0037, color=MUTED, lw=0.9, ls=(0, (1, 2)))
        ax.text(x[0], 0.0042, "socket floor 3.7 µs", fontsize=6.2, color=INK2)
        ax.set_yscale("log")
        if logx:
            ax.set_xscale("log")
        ax.set_xlabel(xlabel)
        ax.set_title(title, loc="left")
        _grid(ax, "both")

    if pps:
        ax = axes[i]; i += 1
        _panel(ax, pps["rows"], "target_pps", "Offered packet rate (pkt/s, log)",
               "(a) Packet rate is not the constraint", logx=True)
        ax.set_ylabel("Delay (ms, log)")
        ax.legend(loc="lower left", fontsize=6.6, ncol=2, handletextpad=0.4,
                  columnspacing=0.9)
    if bg:
        ax = axes[i]
        rows = bg["rows"]
        _panel(ax, rows, "bg_ues", "Background full-buffer UEs",
               "(b) Background load is")
        ax.set_title("(b) Background load is the constraint", loc="left")
        ax.set_ylabel("Delay (ms, log)")
        if i == 0:
            ax.legend(loc="lower right", fontsize=6.6, ncol=2)
        # 유효 경계 표시
        ax.axvspan(-0.3, 1.5, color=C[2], alpha=0.07, zorder=0)
        ax.text(0.2, max(r["rtt_p50"] for r in rows) * 0.5, "valid\nenvelope",
                fontsize=6.4, color=C[2], ha="left", weight="bold")
    fig.tight_layout(w_pad=2.0)
    _save(fig, outdir, "fig12_envelope")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 13 — 시나리오별 판정 요약
# ─────────────────────────────────────────────────────────────────────────────
def fig_verdicts(outdir: str, data: Dict[str, Any]) -> None:
    _style()
    rows = [r for r in data["rows"] if "counts" in r]
    rows.sort(key=lambda r: -sum(r["counts"].values()))
    names = [r["id"] for r in rows]
    order = ["PASS", "FAIL", "INCONCLUSIVE", "NOT_MEASURABLE"]
    cols = {"PASS": C[2], "FAIL": C[1], "INCONCLUSIVE": C[3],
            "NOT_MEASURABLE": MUTED}
    hats = {"PASS": "", "FAIL": "///", "INCONCLUSIVE": "...",
            "NOT_MEASURABLE": "xxx"}

    fig, ax = plt.subplots(figsize=(W2, 62 * MM))
    left = [0.0] * len(rows)
    for v in order:
        vals = [r["counts"].get(v, 0) for r in rows]
        ax.barh(names, vals, left=left, color=cols[v], hatch=hats[v],
                edgecolor=SURFACE, linewidth=0.8, label=v, zorder=3, height=0.62)
        left = [a + b for a, b in zip(left, vals)]
    ax.set_xlabel("Number of (target × phase) verdicts")
    ax.tick_params(axis="y", labelsize=6.8)
    # 막대 위쪽에 두어 가장 긴 막대와 겹치지 않게 한다
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=4,
              fontsize=6.8, handletextpad=0.4, columnspacing=1.2)
    _grid(ax, "x")
    fig.tight_layout()
    _save(fig, outdir, "fig13_verdicts")


# ─────────────────────────────────────────────────────────────────────────────
# 그림 14 — 표본이 판정을 바꾼다
# ─────────────────────────────────────────────────────────────────────────────
def fig_gating(outdir: str, data: Dict[str, Any]) -> None:
    """관측 성공률이 아니라 신뢰하한이 임계를 넘어야 PASS 임을 한 장으로.

    phase 마다 조건이 다르므로 **phase 별로 계열을 나눈다.** 하나로 이으면 서로
    다른 조건의 점이 연결돼 없는 추세가 보인다.
    """
    _style()
    by_phase: Dict[str, List[Tuple[int, float, float, float, str]]] = {}
    thr = None
    for row in data["rows"]:
        for t in row.get("ratio_targets", []):
            if not t.get("n") or t.get("ci_lower") is None:
                continue
            ph = t.get("phase") or "run"
            by_phase.setdefault(ph, []).append(
                (t["n"], t["estimate"], t["ci_lower"], t["ci_upper"],
                 t["verdict"]))
            thr = t["threshold"]
    if not by_phase:
        print("  (건너뜀: 게이팅 표본 없음)")
        return

    fig, ax = plt.subplots(figsize=(W15, 66 * MM))
    # **판정을 정하는 양은 신뢰상한**이므로 그것을 선으로 그린다.
    # 관측 실패율을 로그축에 그리면 "0건" 을 바닥값(예: 1e-7)에 찍게 되는데,
    # 그러면 실패율이 1e-7 인 것처럼 읽힌다 — 관측 0 은 표식으로만 알린다.
    tgt = 1.0 - thr if thr else 1e-5
    bottom = tgt / 20.0
    zero_pts: List[Tuple[int, float]] = []
    for k, (ph, pts) in enumerate(sorted(by_phase.items())):
        pts.sort()
        n = [p[0] for p in pts]
        hi = [1.0 - p[2] for p in pts]          # 신뢰하한 → 실패율 상한
        ax.plot(n, hi, LINES[k % len(LINES)], color=C[k % len(C)],
                marker=MARKERS[k % len(MARKERS)], ms=4, mfc="none", mew=1.2,
                label=f"phase: {ph}", zorder=3)
        for p in pts:
            if 1.0 - p[1] <= 0:
                zero_pts.append((p[0], 1.0 - p[2]))
    if thr:
        ax.axhline(tgt, color=INK2, lw=1.2, ls=(0, (4, 2)), zorder=2)
        ax.text(min(min(p[0] for p in v) for v in by_phase.values()),
                tgt * 1.35, f"target failure rate {tgt:.0e}",
                fontsize=6.6, color=INK2)

    # 판정 표식 — 무실패인데 표본이 모자란 점(INCONCLUSIVE)이 핵심
    marks = {"PASS": (C[2], "^"), "FAIL": (C[1], "v"),
             "INCONCLUSIVE": (C[3], "o"), "NOT_MEASURABLE": (MUTED, "x")}
    seen = set()
    for ph, pts in by_phase.items():
        for n_, e, lo, hi_, v in pts:
            col, mk = marks.get(v, (MUTED, "o"))
            ax.plot([n_], [1.0 - lo], mk, color=col, ms=7,
                    mfc="none", mew=1.7, zorder=4,
                    label=v if v not in seen else None)
            seen.add(v)
    # 관측 0건 지점을 명시 — 선이 아니라 글로.
    for n_, hi_ in zero_pts:
        ax.annotate("0 observed failures —\nbound still above target",
                    xy=(n_, hi_), xytext=(n_ * 1.7, bottom * 2.2),
                    fontsize=6.4, color=C[3], ha="left",
                    arrowprops=dict(arrowstyle="-|>", color=C[3],
                                    lw=0.8, shrinkA=2, shrinkB=5))
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_ylim(bottom=bottom)
    ax.set_xlabel("Evaluated samples n (log)")
    ax.set_ylabel("Failure rate 1 − R\n(95% upper bound, log)")
    ax.legend(loc="upper right", fontsize=6.6, ncol=2, handletextpad=0.4,
              columnspacing=1.0, framealpha=0.9)
    _grid(ax, "both")
    fig.tight_layout()
    _save(fig, outdir, "fig14_gating")


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="논문 그림 생성")
    ap.add_argument("--data", default="ranemu/paper/v2")
    ap.add_argument("--scn", default="ranemu/paper/v3",
                    help="시나리오 계열 데이터(그림 12–14)")
    ap.add_argument("--out", default="ranemu/paper/figures")
    a = ap.parse_args()

    print(f"데이터: {a.data} → 그림: {a.out}")
    fig_architecture(a.out)
    fig_chain(a.out)          # 통합본 Figure 1 — 데이터 불필요
    fig_measurement(a.out)    # 통합본 Figure 2 — 데이터 불필요
    e = _load(a.data, "E_calibration.json")
    if e:
        fig_probe_error(a.out, e)
        fig_loss_estimate(a.out, e)
    f = _load(a.data, "F_limits.json")
    if f:
        fig_limits(a.out, f)
    g = _load(a.data, "G_detector.json")
    if g:
        fig_detector(a.out, g)
    h = _load(a.data, "H_baselines.json")
    if h:
        fig_baselines(a.out, h)
    c = _load(a.data, "C_features.json")
    if c:
        fig_features(a.out, c)
    b = _load(a.data, "B_scalability.json")
    d = _load(a.data, "D_ceiling.json")
    if b or d:
        fig_scaling(a.out, b, d)
    s = _load(a.data, "A_shaper.json")
    if s:
        fig_shaper(a.out, s)

    # 시나리오 계열(그림 12–14). 여기서 부르지 않으면 실험을 다시 돌려도 그림만
    # 옛 데이터로 남는다 — 원고의 표와 그림이 어긋나는 가장 조용한 경로다.
    ep = _load(a.scn, "E_envelope.json")
    eb = _load(a.scn, "E_background.json")
    if ep or eb:
        fig_envelope(a.out, ep, eb)
    sv = _load(a.scn, "S_survey.json")
    if sv:
        fig_verdicts(a.out, sv)
    gt = _load(a.scn, "G_gating.json")
    if gt:
        fig_gating(a.out, gt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
