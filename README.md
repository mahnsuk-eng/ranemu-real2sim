# Real2Sim error propagation — code and data artifact

Companion artifact for:

> M. Yoon, Y.-A. Jung, S.-H. Lee, *Ground truth for Real-to-Simulation agents:
> closed-form error propagation, capture-loss correction, and the load-factor
> clipping floor on operational private 5G traffic*, submitted to
> *Physical Communication* (Elsevier).

Every number, table and figure in the manuscript is regenerated from this
repository. Nothing in the paper is transcribed by hand.

---

## What this repository contains

| Path | Contents |
|---|---|
| `ranemu/` | RAN emulator used to manufacture packet-level ground truth (gNB/UE/NGAP/NAS/GTP-U, impairment injection, capture-loss estimator) |
| `ranemu/paper/lf_bridge.py` | Ground-truth bridge: error propagation, transfer coefficients κ, amplification A, impairment sweep |
| `ranemu/paper/lf_field.py` | Load-factor extraction from operational N3 captures (dedup, windowing, clipping) |
| `ranemu/paper/figures_physcomm.py` | Figures 1–3 |
| `ranemu/paper/build_physcomm.py` | Manuscript builder — substitutes result files into the source text |
| `ranemu/paper/v4/L_lf_bridge.json` | Raw results: error budget vs. ground truth, 10 impairment conditions × 3 seeds |
| `ranemu/paper/v4/M_lf_field.json` | Raw results: per-capture load-factor statistics (Table 7) |
| `ranemu/paper/v4/M_lf_series.csv` | **Derived load-factor series** — 4,190 windows, the input to Section 6 |
| `ranemu/paper/physcomm/` | Manuscript source and figures |

### `M_lf_series.csv` — column reference

| Column | Meaning |
|---|---|
| `capture` | Source capture file (operational N3 mirror) |
| `ue_ip` | Terminal address within the operator UE subnet `10.1.17.0/24` |
| `direction` | `DL` or `UL`, defined relative to the terminal |
| `window_index` | Sequential five-second window within the capture |
| `window_s` | Window length in seconds (5) |
| `throughput_mbps` | Deduplicated per-terminal throughput for the window |
| `lf_raw` | Load factor before clipping, i.e. R/P of Eq. (1) |
| `lf_used` | Load factor the method actually applies, after `clip(·, 0.30, ·)` |

4,190 rows, 5 captures, 5 terminals, 2,113 DL / 2,077 UL windows.
`lf_used` takes exactly one distinct value (0.30) across all 4,190 rows — this
is the paper's central empirical finding, and it is directly checkable:

```bash
python3 - <<'EOF'
import csv
r = list(csv.DictReader(open('ranemu/paper/v4/M_lf_series.csv')))
clipped = sum(abs(float(x['lf_raw']) - float(x['lf_used'])) > 1e-12 for x in r)
print(f"{clipped}/{len(r)} windows clipped "
      f"({100*clipped/len(r):.1f}%);  distinct lf_used = "
      f"{sorted({float(x['lf_used']) for x in r})}")
EOF
# 4190/4190 windows clipped (100.0%);  distinct lf_used = [0.3]
```

---

## What is *not* included, and why

**Operational N3 captures.** The five captures analysed in Section 6 carry
production user-plane traffic from a live private 5G network and cannot be
released. What the analysis consumes is not the packets but the per-terminal,
per-window throughput series derived from them — and that series
(`M_lf_series.csv`), together with the deduplication statistics of Table 7
(`M_lf_field.json`), *is* released. Sections 6 and 7 are therefore reproducible
end to end from what is here. `lf_field.py` is released as well, so the
derivation can be repeated by any party holding equivalent captures.

**`truth_s42.pcap` (277 MB).** Exceeds GitHub's 100 MB per-file limit, and does
not need to be shipped: it is generated deterministically from seed 42 by the
command below. Regenerate it rather than downloading it.

---

## Reproducing the paper

Requires Python 3.11+, `matplotlib`, and `tshark` on `PATH`.

```bash
# 0. emulator self-test
python3 -m ranemu.cli selftest

# 1. ground truth -> capture-error propagation (regenerates truth_s42.pcap from seed 42)
python3 -m ranemu.paper.lf_bridge --out ranemu/paper/v4

# 2. operational captures -> load-factor distribution
#    (requires the withheld captures; the released M_lf_series.csv is this step's output)
python3 -m ranemu.paper.lf_field \
    --ue-subnet 10.1.17.0/24 \
    --pcap <capture>.pcap ... \
    --out ranemu/paper/v4

# 3. figures
python3 -m ranemu.paper.figures_physcomm \
    --data ranemu/paper/v4 --out ranemu/paper/physcomm/figures

# 4. manuscript
python3 -m ranemu.paper.build_physcomm \
    ranemu/paper/physcomm/paper.md --style elsevier
```

Step 4 alone, run against the result files already in `ranemu/paper/v4/`,
rebuilds the manuscript body from this repository. The builder writes any
placeholder it could not fill to stderr; a clean run means every number in the
text came from a result file.

Every experiment is seeded and the seed is recorded in the corresponding result
file (`L_lf_bridge.json` carries seeds 42, 43, 44).

> **Note on the manuscript source.** `ranemu/paper/physcomm/paper.md` is the
> builder input. The version of record submitted to the journal carries
> copy-editing applied after this source (abstract and introduction wording,
> three additional references). The numerical content is identical; the
> reproduction path above is what backs every reported value.

---

## Licence

- **Code** (`ranemu/`, all `*.py`): MIT — see [`LICENSE`](LICENSE).
- **Data and figures** (`ranemu/paper/v4/*`, `ranemu/paper/physcomm/figures/*`):
  Creative Commons Attribution 4.0 International (CC BY 4.0) — see
  [`LICENSE-DATA`](LICENSE-DATA).

If you use this artifact, please cite the paper (see [`CITATION.cff`](CITATION.cff)).

## Acknowledgement

Supported by the Institute of Information & Communications Technology Planning &
Evaluation (IITP) grant funded by the Korea government (MSIT)
(No. RS-2025-02311938; No. RS-2025-25455300).
