#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ranemu.paper.build_physcomm — Physical Communication 원고의 수치 자동 삽입.

`build.py`(캡처손실 계열 v2), `build_scenario.py`(시나리오 계열 v3) 와 같은 규율이다:
본문에는 `{{키}}` 만 쓰고 값은 원시 JSON 에서 한 번만 계산해 채운다. 실험을 다시
돌리면 원고 수치도 함께 갱신되므로 표와 본문이 어긋날 수 없다.

읽는 데이터
    v4/L_lf_bridge.json   정답 대비 캡처오차 → LF → 예측이득 전파(오차예산)
    v4/M_lf_field.json    실측 사설 5G 캡처의 단말별 부하계수 분포
    v2/*.json             캡처손실 보정 계열(선택, --v2 로 지정)

    python3 -m ranemu.paper.build_physcomm --list
    python3 -m ranemu.paper.build_physcomm paper.md --v2 ranemu/paper/v2 \
        --style elsevier
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import sys
from typing import Any, Dict, List, Optional, Sequence

V4 = os.path.join(os.path.dirname(os.path.abspath(__file__)), "v4")


def _load(d: str, name: str) -> Optional[Dict[str, Any]]:
    p = os.path.join(d, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def _mean(v: Optional[Dict[str, Any]], key: str = "mean") -> Optional[float]:
    if not isinstance(v, dict):
        return None
    x = v.get(key)
    return float(x) if x is not None else None


def neg(s: str) -> str:
    """마이너스를 U+2212 로(활자 품질)."""
    return s.replace("-", "−")


class PhysCommPaper:
    """v4 실험 JSON → 본문 치환값과 표."""

    def __init__(self, data_dir: str = V4):
        self.d = data_dir
        self.B = _load(data_dir, "L_lf_bridge.json")
        self.F = _load(data_dir, "M_lf_field.json")
        self.vals: Dict[str, str] = {}
        self._derive_bridge()
        self._derive_field()
        self._derive_clip()

    # ── 오차예산(정답 대비) ───────────────────────────────────────────────
    def _derive_bridge(self) -> None:
        if not self.B:
            return
        v, m, s = self.vals, self.B["meta"], self.B["summary"]
        v["lfb_truth_mbps"] = f"{m['truth_mbps']:.1f}"
        v["lfb_truth_packets"] = f"{m['truth_packets']:,}"
        v["lfb_lf"] = f"{m['lf_true']:.2f}"
        v["lfb_seeds"] = str(len(m.get("seeds") or []))
        v["lfb_conditions"] = str(m.get("n_conditions", "?"))
        v["lfb_features"] = ", ".join(m.get("active_features") or [])
        v["lfb_amplification"] = f"{m['amplification']:.3f}"
        for name, k in (m.get("kappa") or {}).items():
            v[f"lfb_kappa_{name.replace('-', '_').lower()}"] = f"{k:.3f}"
        v["lfb_kappa_list"] = ", ".join(f"{n} {k:.3f}"
                                        for n, k in (m.get("kappa") or {}).items())

        for tag, key in (("probe", "worst_probe"), ("corr", "worst_corrected")):
            for what in ("eps", "lf_err", "pred_err"):
                x = s.get(f"{key}_{what}_pct")
                if x is not None:
                    v[f"lfb_{tag}_{what}"] = f"{x:.4f}" if abs(x) < 1 else f"{x:.1f}"
        # 개선 배수 — 논문의 헤드라인
        wp, wc = s.get("worst_probe_pred_err_pct"), s.get("worst_corrected_pred_err_pct")
        if wp and wc:
            v["lfb_improvement_x"] = f"{wp / wc:,.0f}"
            v["lfb_improvement_decades"] = f"{math.log10(wp / wc):.1f}"

        band = s.get("firstorder_residual_by_band_pp") or {}
        small = band.get("|eps|<=5%")
        if small:
            v["lfb_resid_small_mean"] = f"{small['mean']:.3f}"
            v["lfb_resid_small_max"] = f"{small['max']:.3f}"
            v["lfb_resid_small_n"] = str(small["n"])
        mid, big = band.get("5-20%"), band.get(">20%")
        if mid:
            v["lfb_resid_mid_mean"] = f"{mid['mean']:.2f}"
        if big:
            v["lfb_resid_big_mean"] = f"{big['mean']:.1f}"
            v["lfb_resid_big_max"] = f"{big['max']:.1f}"
        cf = s.get("firstorder_conservative_frac")
        if cf is not None:
            v["lfb_conservative_pct"] = f"{cf * 100:.0f}"
        cl = s.get("clip_fired_conditions") or []
        v["lfb_clip_fired"] = ", ".join(cl) if cl else "none"

    # ── 실측 부하계수 분포 ────────────────────────────────────────────────
    def _derive_field(self) -> None:
        if not self.F or not self.F.get("captures"):
            return
        v = self.vals
        caps = self.F["captures"]
        v["field_n_captures"] = str(len(caps))
        v["field_packets"] = f"{sum(c['meta']['packets'] for c in caps):,}"
        dups = [c["meta"]["duplication_factor"] for c in caps]
        v["field_dup_min"] = f"{min(dups):.2f}"
        v["field_dup_max"] = f"{max(dups):.2f}"
        v["field_peak_dl"] = f"{caps[0]['meta']['peak_dl_mbps']:.0f}"
        v["field_peak_ul"] = f"{caps[0]['meta']['peak_ul_mbps']:.1f}"
        v["field_window_s"] = f"{caps[0]['meta']['window_s']:.0f}"
        v["field_lf_min"] = f"{caps[0]['meta']['lf_min']:.2f}"

        wins = 0
        clipped = 0
        dl_p50: List[float] = []
        ul_p50: List[float] = []
        dl_max: List[float] = []
        for c in caps:
            for k in ("DL", "UL"):
                x = (c.get("distribution") or {}).get(k)
                if not x:
                    continue
                wins += x["n_windows"]
                clipped += int(round(x["clipped_frac"] * x["n_windows"]))
                (dl_p50 if k == "DL" else ul_p50).append(x["lf_raw"]["p50"])
                if k == "DL":
                    dl_max.append(x["lf_raw"]["max"])
        v["field_windows"] = f"{wins:,}"
        v["field_clipped_windows"] = f"{clipped:,}"
        v["field_clipped_pct"] = f"{clipped / wins * 100:.1f}" if wins else "—"
        if dl_p50:
            v["field_dl_lf_p50_min"] = f"{min(dl_p50):.5f}"
            v["field_dl_lf_p50_max"] = f"{max(dl_p50):.4f}"
            v["field_dl_lf_max"] = f"{max(dl_max):.4f}"
        if ul_p50:
            v["field_ul_lf_p50_min"] = f"{min(ul_p50):.5f}"
            v["field_ul_lf_p50_max"] = f"{max(ul_p50):.5f}"
        # 클립 바닥이 실측 중앙값보다 몇 배 위인가
        if dl_p50:
            lo = caps[0]["meta"]["lf_min"]
            v["field_clip_ratio_min"] = f"{lo / max(dl_p50):,.0f}"
            v["field_clip_ratio_max"] = f"{lo / min(dl_p50):,.0f}"

        # 단말 수·측정일수 — "한 단말 하루" 라는 지적을 미리 막는다
        ues = sorted({u for c in caps for u in (c["meta"].get("ues") or [])})
        v["field_n_ues"] = str(len(ues))
        days = sorted({c["meta"]["pcap"][:6] for c in caps})
        v["field_n_days"] = str(len(days))
        v["field_ue_selection"] = caps[0]["meta"].get("ue_selection", "—")
        # 전수 클립의 통계적 상한(rule of three, 95 %)
        if wins:
            v["field_unclipped_upper95_pct"] = f"{3.0 / wins * 100:.3f}"

        # 대안 분모(단말 자신의 관측 최고치)로 정규화했을 때의 분포
        p50s, p95s, clips = [], [], []
        for c in caps:
            for k in ("DL", "UL"):
                a = (c.get("distribution_own_peak") or {}).get(k)
                if not a:
                    continue
                p50s.append(a["lf"]["p50"])
                p95s.append(a["lf"]["p95"])
                clips.append(a["clipped_frac"])
        if p50s:
            v["own_p50_min"] = f"{min(p50s):.4f}"
            v["own_p50_max"] = f"{max(p50s):.4f}"
            v["own_p95_min"] = f"{min(p95s):.2f}"
            v["own_p95_max"] = f"{max(p95s):.2f}"
            v["own_clip_min"] = f"{min(clips) * 100:.0f}"
            v["own_clip_max"] = f"{max(clips) * 100:.0f}"

    # ── 클립이 만들어내는 이득 ────────────────────────────────────────────
    def _derive_clip(self) -> None:
        """실측 LF 에서 클립이 합성이득을 얼마나 부풀리는지 — 해석적으로 정확."""
        from .lf_bridge import FEATURES, amplification
        v = self.vals
        act = ((self.B or {}).get("meta") or {}).get("active_features") \
            or ["SBFD", "MIMO-adv", "EN-DC"]
        by = {f.name: f for f in FEATURES}
        feats = [by[n] for n in act if n in by]
        lf_min = float(v.get("field_lf_min", 0.30))

        def over(lf: float) -> float:
            gt = math.prod(f.gain(lf) for f in feats)
            gu = math.prod(f.gain(max(lf_min, lf)) for f in feats)
            return (gu / gt - 1) * 100.0

        v["clip_gain_at_floor"] = f"{math.prod(f.gain(lf_min) for f in feats):.3f}"
        for tag, key in (("min", "field_dl_lf_p50_min"),
                         ("max", "field_dl_lf_p50_max")):
            if key in v:
                lf = float(v[key])
                v[f"clip_overstate_{tag}"] = f"{over(lf):.1f}"
                g = math.prod(f.gain(lf) for f in feats)
                v[f"clip_physical_gain_{tag}"] = f"{g:.4f}"
                # 배율을 % 이득으로도 준다 — 본문이 "1.0037" 을 그대로 쓰면 읽히지 않는다
                v[f"clip_physical_pct_{tag}"] = f"{(g - 1) * 100:.2f}"
        v["clip_gain_at_floor_pct"] = \
            f"{(math.prod(f.gain(lf_min) for f in feats) - 1) * 100:.1f}"
        # 합성 가정 편차 — 실측 운영점과 고부하에서
        from .lf_bridge import pair_interaction, pair_summary
        ps = pair_summary(pair_interaction())
        for lf_key, tag in (("0.003", "field"), ("0.65", "mid"), ("1", "full")):
            if lf_key in ps:
                v[f"pair_maxdev_{tag}"] = f"{ps[lf_key]['max_deviation_pct']:.5f}" \
                    if ps[lf_key]["max_deviation_pct"] is not None else "—"
                v[f"pair_over3_{tag}"] = str(ps[lf_key]["n_over_3pct"])
                v[f"pair_worst_{tag}"] = ps[lf_key]["worst_pair"]
                v["pair_n"] = str(ps[lf_key]["n_pairs"])
        # 클립을 뺐을 때의 증폭계수(민감도가 살아난다)
        if "field_dl_lf_p50_max" in v:
            lf = float(v["field_dl_lf_p50_max"])
            v["field_amp_unclipped"] = f"{amplification(feats, lf):.4f}"
            v["field_amp_clipped"] = f"{amplification(feats, lf_min):.3f}"

    # ── 표 ───────────────────────────────────────────────────────────────
    @staticmethod
    def _tbl(header: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
        out = ["| " + " | ".join(header) + " |",
               "|" + "|".join(["---"] * len(header)) + "|"]
        for r in rows:
            out.append("| " + " | ".join(str(x) for x in r) + " |")
        return "\n".join(out)

    def table_field(self) -> str:
        if not self.F:
            return "_(no data)_"
        rows = []
        for c in self.F["captures"]:
            m = c["meta"]
            for k in ("DL", "UL"):
                x = (c.get("distribution") or {}).get(k)
                if not x:
                    continue
                r = x["lf_raw"]
                a = (c.get("distribution_own_peak") or {}).get(k) or {}
                rows.append([
                    m["pcap"].replace(".pcap", ""), k,
                    str(len(m.get("ues") or [])), f"{x['n_windows']:,}",
                    f"{m['duplication_factor']:.2f}×",
                    f"{r['p50']:.5f}", f"{r['p95']:.5f}", f"{r['max']:.4f}",
                    f"{x['clipped_frac'] * 100:.0f}%",
                    f"{a.get('lf', {}).get('p95', float('nan')):.2f}"
                    if a else "—"])
        return self._tbl(["Capture", "Dir.", "UEs", "Windows", "Dup.",
                          "LF p50", "LF p95", "LF max", "Clipped",
                          "LF p95 (own-peak)"], rows)

    def table_bridge(self) -> str:
        if not self.B:
            return "_(no data)_"
        rows = []
        for r in self.B["rows"]:
            g = lambda k: _mean(r.get(k))            # noqa: E731
            loss = g("actual_loss_pct")
            rows.append([
                r["label"],
                f"{loss:.1f}" if loss is not None else "—",
                neg(f"{g('probe_eps_pct'):.2f}") if g("probe_eps_pct") is not None else "—",
                neg(f"{g('probe_lf_err_pct'):.2f}") if g("probe_lf_err_pct") is not None else "—",
                neg(f"{g('probe_pred_err_pct'):.2f}") if g("probe_pred_err_pct") is not None else "—",
                neg(f"{g('probe_pred_err_firstorder_pct'):.2f}")
                if g("probe_pred_err_firstorder_pct") is not None else "—",
                neg(f"{g('corrected_pred_err_pct'):.4f}")
                if g("corrected_pred_err_pct") is not None else "—"])
        return self._tbl(["Impairment", "Loss (%)", "ε (%)", "ΔLF (%)",
                          "ΔR_sim (%)", "ε·A (%)",
                          "ΔR_sim corrected (%)"], rows)

    def table_analytic(self) -> str:
        if not self.B or not self.B.get("analytic"):
            return "_(no data)_"
        rows = []
        for r in self.B["analytic"]:
            rows.append([" + ".join(r["features"]), f"{r['lf']:.1f}",
                         ", ".join(f"{v:.3f}" for v in r["kappa"].values()),
                         f"{r['gain_product']:.3f}", f"{r['amplification']:.3f}"])
        return self._tbl(["Active features", "LF", "κ per feature",
                          "Π g", "A = 1 + Σκ"], rows)

    def table_clip(self) -> str:
        if not self.B or not self.B.get("clip"):
            return "_(no data)_"
        rows = []
        for r in self.B["clip"]:
            rows.append([f"{r['lf_actual']:.3f}", f"{r['lf_used']:.2f}",
                         ("—" if not r["clipped"]
                          else f"{r['lf_inflation_x']:.0f}×"),
                         f"{r['gain_true']:.4f}", f"{r['gain_used']:.4f}",
                         f"{r['gain_overstatement_pct']:.1f}",
                         f"{r['sensitivity']:.3f}"])
        return self._tbl(["LF measured", "LF used", "Inflation", "Π g true",
                          "Π g used", "Overstatement (%)",
                          "Sensitivity Σκ"], rows)

    def table_pairs(self) -> str:
        """합성 가정 편차 — LF 별 최대편차와 3 % 초과 쌍 수."""
        from .lf_bridge import pair_interaction, pair_summary
        s = pair_summary(pair_interaction())
        rows = []
        for lf, v in s.items():
            rows.append([lf, str(v["n_pairs"]),
                         f"{v['max_deviation_pct']:.5f}"
                         if v["max_deviation_pct"] is not None else "—",
                         v["worst_pair"], str(v["n_over_3pct"])])
        return self._tbl(["LF", "Pairs", "Max deviation (%)", "Worst pair",
                          "Pairs > 3%"], rows)

    def table_features(self) -> str:
        from .lf_bridge import FEATURES
        rows = []
        for f in FEATURES:
            rows.append([f.name, f.direction,
                         f"{(f.low - 1) * 100:+.0f}%", f"{(f.median - 1) * 100:+.0f}%",
                         f"{(f.high - 1) * 100:+.0f}%", f"{f.beta:+.2f}",
                         f"{f.spec} {f.clause}".strip()])
        return self._tbl(["Feature", "Dir.", "Low", "Median", "High",
                          "β", "Source"], rows)

    def tables(self) -> Dict[str, str]:
        return {
            "TABLE_FIELD": self.table_field(),
            "TABLE_BRIDGE": self.table_bridge(),
            "TABLE_ANALYTIC": self.table_analytic(),
            "TABLE_CLIP": self.table_clip(),
            "TABLE_FEATURES": self.table_features(),
            "TABLE_PAIRS": self.table_pairs(),
        }

    def substitute(self, text: str) -> str:
        tables = self.tables()
        missed: List[str] = []

        def repl(mo: "re.Match[str]") -> str:
            k = mo.group(1)
            if k in tables:
                return tables[k]
            if k in self.vals:
                return self.vals[k]
            missed.append(k)
            return mo.group(0)

        out = re.sub(r"\{\{([A-Za-z0-9_]+)\}\}", repl, text)
        if missed:
            print(f"  (physcomm 빌더가 못 채운 키: {', '.join(sorted(set(missed)))})",
                  file=sys.stderr)
        return out


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Physical Communication 수치 삽입")
    ap.add_argument("source", nargs="?")
    ap.add_argument("--data", default=V4)
    ap.add_argument("--v2", default=None, help="캡처손실 계열 데이터(선택)")
    ap.add_argument("--style", default="elsevier")
    ap.add_argument("--out-md", default=None)
    ap.add_argument("--out-docx", default=None)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)

    p = PhysCommPaper(a.data)
    if a.list or not a.source:
        print(f"데이터: {a.data}\n\n본문 치환값 {len(p.vals)}개")
        for k in sorted(p.vals):
            print(f"  {{{{{k}}}}} = {p.vals[k]}")
        print(f"\n표: {', '.join(sorted(p.tables()))}")
        if a.v2:
            from .build import Paper
            q = Paper(a.v2)
            print(f"\n─── v2 계열({a.v2}) 치환값 {len(q.vals)}개 ───")
            for k in sorted(q.vals):
                print(f"  {{{{{k}}}}} = {q.vals[k]}")
        return 0

    with open(a.source, encoding="utf-8") as f:
        text = f.read()
    filled = p.substitute(text)
    if a.v2:
        from .build import Paper
        filled = Paper(a.v2).substitute(filled)

    unresolved: Dict[str, int] = {}
    for mo in re.finditer(r"\{\{([A-Za-z0-9_]+)\}\}", filled):
        unresolved[mo.group(1)] = unresolved.get(mo.group(1), 0) + 1
    if unresolved:
        print(f"\n[미해결 자리표시자 {len(unresolved)}종]", file=sys.stderr)
        for k in sorted(unresolved):
            print(f"  {{{{{k}}}}} ×{unresolved[k]}", file=sys.stderr)

    out_md = a.out_md or os.path.splitext(a.source)[0] + ".filled.md"
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(filled)
    print(f"작성: {out_md}")

    from .mkdocx import convert
    out_docx = a.out_docx or os.path.splitext(a.source)[0] + ".docx"
    convert(out_md, out_docx, style=a.style,
            base_dir=os.path.dirname(os.path.abspath(a.source)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
