---
title: "Load-Factor Calibration for Real-to-Simulation Estimation of 5G-Advanced Feature Impact: A Measured Error Budget and Its Degeneracy on Operational Private-5G Traffic"
authors:
  - "Mahnsuk Yoon a,*"
  - "Yong-An Jung a"
  - "Sung-Hun Lee a"
affiliations:
  - "a ICT Device Research Center, Gumi Electronics & Information Technology Research Institute, Gumi 39253, Republic of Korea"
corresponding: "Corresponding author. E-mail address: yms@geri.re.kr (M. Yoon)"
abstract: "Operators of private 5G networks must commit to multi-year radio and core licensing before any 5G-Advanced feature reaches generally available firmware, and therefore need to estimate feature impact from the traffic they already carry. Real-to-Simulation (Real2Sim) agents address this by capturing user-plane traffic passively at the N3 mirror interface, normalizing each terminal's measured throughput by a vendor-rated peak into a load factor, scaling literature-reported feature gains by that load factor, and injecting the result into a network simulator. The construction is attractive because it grounds the estimate in the operator's own measurements, but it inherits every error of those measurements, and that inheritance has not previously been quantified — quantifying it requires ground truth, which passive capture by definition does not have. This paper supplies the missing ground truth and reports three results. First, because the scaled gain is affine in the load factor, the propagation of relative measurement error into predicted throughput admits a closed form: the per-feature transfer coefficient is κ = βLF/(1 + βLF) and the end-to-end amplification is A = 1 + Σκ, bounded by one plus the number of active features. Against a packet-level ground-truth manifest obtained by injecting known traffic into a real 5G core, the first-order budget εA is exact to within {{lfb_resid_small_max}} percentage points for |ε| ≤ 5% and is conservative in {{lfb_conservative_pct}}% of the {{lfb_conditions}} impairment conditions tested. Second, an in-band capture-loss correction reduces the worst-case propagated prediction error from {{lfb_probe_pred_err}}% to {{lfb_corr_pred_err}}%, a factor of {{lfb_improvement_x}}. Third, and most consequential for practice, we extract the load-factor distribution from {{field_n_captures}} operational private-5G N3 captures ({{field_packets}} packets) and find that every one of the {{field_windows}} measurement windows falls below the clipping floor the method specifies: real median load factors are {{field_dl_lf_p50_min}}–{{field_dl_lf_p50_max}} downlink against a floor of {{field_lf_min}}, a gap of {{field_clip_ratio_min}}× to {{field_clip_ratio_max}}×, so the calibration degenerates to a constant and overstates the composed feature gain by {{clip_overstate_max}}%. We show that removing the floor restores the physically correct behaviour — a peak-throughput feature confers no benefit on a terminal using a fraction of a percent of capacity — and we state precisely which claims of the method survive this correction and which do not."
keywords:
  - 5G-Advanced
  - Real-to-Simulation
  - load factor
  - pre-deployment estimation
  - passive measurement
  - error propagation
  - private 5G
highlights:
  - "Closed-form error budget from N3 capture error to predicted 5G-Advanced feature gain"
  - "Ground-truth validation: budget exact to 0.03 pp for capture error below 5%"
  - "Capture-loss correction cuts propagated prediction error by five orders of magnitude"
  - "All 4,190 windows of real private-5G traffic fall below the LF clipping floor"
  - "The clip degenerates the calibration to a constant and overstates gains by 41%"
---

## 1. Introduction

A private 5G deployment commits its operator years in advance. Radio and core
licensing for a manufacturing site, a port, or a logistics hub is contracted
before the 3GPP Release 17/18/19 features that motivate the investment reach
generally available firmware, and often before the vendor will commit to a date.
The operator therefore has to answer a counterfactual question from data it
already possesses: *given the traffic my network carries today, what would
sub-band full duplex, or an additional dual-connectivity leg, or AI-assisted
channel state feedback, be worth to me?*

The Real-to-Simulation (Real2Sim) paradigm answers this by refusing to invent the
traffic. An agent captures user-plane packets passively at the N3 mirror port of
the 3GPP core — a facility every deployment already has, and one that modifies
nothing — decapsulates GTP-U to recover per-terminal flows, normalizes each
terminal's measured throughput by a vendor-rated peak to obtain a *load factor*,
scales literature-reported feature gains by that load factor, and injects the
calibrated result into a network simulator. The appeal is that the answer is
anchored to the operator's own measured load distribution rather than to a vendor
datasheet.

That appeal carries an obligation that the literature has not discharged. The
entire chain has exactly one empirical input — the throughput measured at the
mirror — and mirror capture is not a faithful observer. It duplicates: the same
user-plane packet is seen at both tunnel endpoints, and often again on N6. It
loses: a 1 GbE span port tail-drops at the downlink peak. In the captures
analysed in Section 6 the observed duplication factor ranges from
{{field_dup_min}}× to {{field_dup_max}}×, which means naive byte summation would
overstate throughput by up to a factor of seven before any modelling begins. If
the measured throughput is wrong, the load factor is wrong, the scaled gain is
wrong, and the operator's investment decision is wrong — and nothing in the
method reports that this has happened.

The reason this error has not been quantified is structural rather than one of
diligence: quantifying measurement error requires ground truth, and passive
capture of production traffic has none. Nobody knows how many packets the mirror
dropped, because the only record of them is the mirror.

This paper supplies that ground truth and follows it through the chain. We inject
traffic of exactly known volume into a real 5G core through standard N2/N3
interfaces using an instrumented RAN emulator that emits a machine-readable
manifest of what it sent, subject the resulting capture to controlled impairment,
and measure what the agent would have concluded. This turns an unmeasurable
question into a measurable one. Our contributions are:

1. **A closed-form error budget** (Section 4). Because the load-factor-scaled
   gain is affine in the load factor, relative measurement error propagates
   analytically: the per-feature transfer coefficient is κ = βLF/(1 + βLF),
   strictly less than one for a gain-increasing feature, and the end-to-end
   amplification of a relative capture error into a relative prediction error is
   A = 1 + Σ_f κ_f, bounded above by one plus the number of active features. The
   budget inverts: to hold prediction error within a target, hold capture error
   within that target divided by A.

2. **Ground-truth validation of the budget and of the correction**
   (Section 5). Across {{lfb_conditions}} impairment conditions and
   {{lfb_seeds}} seeds, the first-order budget εA is exact to within
   {{lfb_resid_small_max}} percentage points for |ε| ≤ 5% and never
   under-predicts the error in any condition tested. An in-band capture-loss
   correction reduces the worst-case propagated prediction error from
   {{lfb_probe_pred_err}}% to {{lfb_corr_pred_err}}%.

3. **The load-factor degeneracy in operational traffic** (Section 6). Extracting
   per-terminal load factors from {{field_n_captures}} production private-5G N3
   captures, we find that **all {{field_windows}} of {{field_windows}} five-second
   windows fall below the clipping floor** the method prescribes. The calibration
   therefore never uses a measured load factor on this network; it substitutes a
   constant, and in doing so overstates the composed feature gain by
   {{clip_overstate_max}}%. We show why removing the floor is the physically
   correct repair and what it costs.

The third result reframes the first two. An error budget matters most where the
quantity being measured actually drives the answer; the field data show that, as
specified, it does not. Section 7 states which of the method's claims survive and
proposes the minimal change that restores the mechanism it advertises.

## 2. Related Work

**Real2Sim and network digital twins.** Digital-twin architectures for mobile
networks are specified in ITU-T Y.3090 [1] and Y.3092 [2], and instantiated for
5G/B5G by systems such as B5GEMINI [3]. These target model fidelity to a live
network and its orchestration, and report aggregate agreement between twin and
network. They do not propagate per-terminal heterogeneity into a counterfactual
feature estimate, which is the specific question here, and — relevant to this
paper — they treat the measurement that feeds the twin as given.

**Standards-driven simulation.** ns-3 5G-LENA [4] and Simu5G [5] provide detailed
NR physical-layer and QoS-flow models and are the usual vehicles for
system-level evaluation of new features. Both are driven by synthetic traffic
models rather than by an operator's measured load, which is precisely the gap
Real2Sim addresses; conversely, neither inherits a measurement error, because
neither has a measurement. A recent survey of 6G simulators [6] confirms the
division of the landscape into tools that attach to real interfaces and tools
that model services richly. Simulator-integration efforts that couple ns-3 to
live control interfaces target algorithm development at the radio-intelligent
controller rather than per-terminal user-plane estimation, and report agreement
at that level.

**Passive measurement and its error.** That span-port capture is lossy and
duplicating is well known operationally, and correction techniques based on
in-band sequence information are established for loss estimation. What is absent
is any published treatment of how that measurement error propagates through a
*downstream estimation model* to a decision-grade output. Our closest analogue in
spirit is uncertainty propagation in measurement science; the contribution here
is that the specific model used by load-factor Real2Sim admits a closed-form
propagation, and that ground truth for the input error can be manufactured with
an emulator even though it cannot be observed in production.

**Positioning.** Table 1 summarizes. To our knowledge, no prior work on
Real2Sim-style feature estimation reports (i) the measurement error of its own
input against ground truth, (ii) a propagation bound from that error to its
output, or (iii) the load-factor distribution of real operational traffic against
the clipping floor its own method prescribes.

**Table 1.** Positioning against representative approaches. "n/r" = not reported.

| Capability | 5G-LENA [4] / Simu5G [5] | B5GEMINI [3] | Load-factor Real2Sim (Section 3) | This work |
|---|---|---|---|---|
| Driven by operator-measured traffic | no | partly | yes | yes |
| Per-terminal granularity | yes | n/r | yes | yes |
| Counterfactual feature estimate | yes | no | yes | yes |
| Input measurement error quantified | n/a | n/r | no | **yes** |
| Error propagation to output | n/r | n/r | no | **yes** |
| Operating-point distribution reported | n/a | n/r | no | **yes** |

## 3. The Agent and Its Load-Factor Calibration

We restate the method under study in the notation used throughout. The agent
operates on a five-second pipeline. It captures GTP-U [12] at the passive N3 mirror,
decapsulates to inner IP, attributes flows to terminals using an
operator-supplied inventory, computes per-terminal throughput, applies the
calibration below, invokes the simulator, and presents measured and simulated
values side by side.

**Load factor.** Let R_d(u) be the measured throughput of terminal u in direction
d ∈ {DL, UL} over a window, and P_d the vendor-rated single-terminal peak. The
load factor is

> LF_d(u) = clip( R_d(u) / P_d , LF_min , LF_max ),  (1)

with LF_min = {{field_lf_min}} and LF_max = 1.0 as specified. The single-terminal
peak is chosen as the denominator because it is a vendor-grounded constant rather
than a quantity that shifts with the number of attached terminals. On the
reference testbed it was measured by single-terminal throughput test as
P_DL = {{field_peak_dl}} Mb/s and P_UL = {{field_peak_ul}} Mb/s.

**Scaled gain and composition.** For a feature f with a literature-reported gain
multiplier g_f^base, write β_f = g_f^base − 1. The load-scaled gain and the
composed prediction are

> g_f(LF) = 1 + β_f · LF,  (2)
>
> R_d^sim(u) = R_d(u) · Π_{f ∈ F(u)} g_f(LF_d(u)),  (3)

capped at the post-activation physical maximum where a feature adds spectrum or
carriers. The intent of (2) is that a lightly loaded terminal cannot realize a
capacity gain, so the gain should shrink toward unity as LF → 0. Section 6 shows
that the clip in (1) defeats this intent on real traffic.

**Feature library.** Table 2 lists the features and their literature gain
intervals: sub-band full duplex [7], LTE–NR and NR–NR dual connectivity [8],
AI/ML-assisted channel state feedback [9], advanced MIMO [10], and network energy
saving [11]. Two properties matter for what follows. Each entry is a *transcription
of reported values*, not a measurement of our own; we therefore carry the low,
median and high estimates rather than a point value, and we mark the source
clause. And β is signed: network energy saving reduces throughput, so β < 0, and
its transfer coefficient κ is correspondingly negative — it partially cancels the
propagation of other features rather than adding to it.

{{TABLE_FEATURES}}

**Table 2.** Feature gain library. Values are transcriptions of reported ranges;
β = median − 1 is the coefficient that enters (2). Latency-only features (L1/L2
triggered mobility) are excluded from throughput propagation and handled by an
additive latency term.

## 4. Error Propagation: From Capture Error to Predicted Gain

### 4.1. Closed form

Suppose the mirror reports R̂ = R(1 + ε) instead of the true R, where ε is the
relative capture error — negative under loss, positive under uncounted
duplication. Provided the resulting load factor stays inside the clip interval,
L̂F = LF(1 + ε), and substituting into (2),

> ĝ_f = 1 + β_f · LF(1 + ε) = g_f + β_f · LF · ε,

so the relative gain error is

> Δg_f / g_f = ε · κ_f,  κ_f = β_f · LF / (1 + β_f · LF).  (4)

For a gain-increasing feature (β_f > 0) we have 0 < κ_f < 1: **the gain error is
an attenuated copy of the measurement error.** The attenuation is not a
convenience but a property of the affine form — the constant 1 in (2) dilutes any
error in the LF-dependent term.

The predicted throughput (3) carries the measurement error twice, once in the
leading R and once through each gain. Writing R̂_sim = R(1+ε)·Π_f g_f(1 + κ_f ε)
and expanding the product while discarding terms of order ε², the cross terms
vanish and the coefficients add, giving

> ΔR_sim / R_sim ≈ ε · ( 1 + Σ_{f ∈ F} κ_f ) ≡ ε · A.  (5)

We call A the **error amplification factor**. Since each κ_f < 1, A < 1 + |F|:
the prediction can never be wrong by more than one plus the number of active
features times the measurement error. The budget inverts usefully — to hold
prediction error within a target τ, the capture must be accurate to τ/A.

Table 3 evaluates κ and A over feature subsets and load factors. Two features of
the structure are worth noting. A grows with load factor, so the accuracy demand
on the capture is *strictest at high load* — which is precisely where a 1 GbE
mirror is most likely to be saturating and therefore least accurate. And a
negative-β feature reduces A, so an energy-saving configuration is intrinsically
more tolerant of measurement error than a throughput-boosting one.

![**Fig. 1.** Closed-form error propagation. (a) The per-feature transfer coefficient κ = βLF/(1+βLF) is strictly below one for a gain-increasing feature and negative for network energy saving, which subtracts from the total. (b) The end-to-end amplification A = 1 + Σκ grows with load factor and with the number of active features; the shaded band marks the load-factor range actually measured on the operational network of Section 6.](figures/fig1_propagation.png)

{{TABLE_ANALYTIC}}

**Table 3.** Transfer coefficients and amplification. κ_f from (4), A from (5).
The load factors shown span the interval the method assumes; Section 6 reports
where real traffic actually sits.

### 4.2. What the clip does to the propagation

Equation (4) assumed the load factor stays inside the clip. When R/P < LF_min the
clip pins LF to LF_min and ΔLF = 0, so by (4) every κ_f vanishes. It is tempting
to read this as the clip conferring immunity to measurement error. It does not.
It replaces the terminal's measured load with a constant, so the gain prediction
for that terminal is no longer a function of its measurement at all. The
sensitivity is zero because the signal is gone, not because the noise is
suppressed.

The cost is a systematic overstatement. Table 4 evaluates it: a terminal whose
true load factor is 0.03 has its load inflated tenfold, and its composed gain
overstated by 36.5%. The distortion grows as the true load falls. Section 6 shows
that real private-5G terminals sit three to four decades below the floor, where
the overstatement saturates near {{clip_overstate_min}}%.

{{TABLE_CLIP}}

**Table 4.** Effect of the clipping floor. "Sensitivity" is Σκ, the responsiveness
of the prediction to the terminal's own measurement; it is identically zero
wherever the clip binds.


### 4.3. Latency propagates differently

The agent predicts latency additively rather than multiplicatively: a
load-dependent feature contributes Δ_f · LF_UL and a control-plane feature such as
L1/L2-triggered mobility contributes its absolute Δ_f irrespective of load. The
propagation therefore has no amplification term. Writing L̂ = L + Σ Δ_f·LF(1+ε),
the *absolute* latency error is ε · LF · Σ_{f ∈ F_load} Δ_f, independent of the
baseline latency, and the control-plane contributions carry no measurement error
at all. In the regime of Section 6 (LF ≈ 10⁻³) the load-dependent latency term is
itself negligible, so predicted latency reduces to the baseline plus the
control-plane deltas — a prediction that requires no capture accuracy whatsoever.
Latency and throughput therefore make opposite demands on the measurement, and an
operator interested only in handover interruption need not solve the capture
problem this paper addresses.

### 4.4. When does the composition rule matter?

Equation (3) composes features multiplicatively. An obvious alternative is to add
the excess gains without a cross term, and the difference between the two is
available in closed form: for a pair,

> (1 + β₁LF)(1 + β₂LF) − [1 + (β₁+β₂)LF] = β₁β₂ · LF²,

so the relative deviation is β₁β₂·LF² / (1 + (β₁+β₂)LF) — **quadratic in the load
factor.** Table 5 evaluates it over all {{pair_n}} pairs in the library. At full
load the worst pair ({{pair_worst_full}}) deviates by {{pair_maxdev_full}}% and
{{pair_over3_full}} of {{pair_n}} pairs exceed 3%, so the choice of composition
rule is a live question. At the load factors actually measured in Section 6 the
worst deviation is {{pair_maxdev_field}}% and no pair exceeds 3%: the question is
empty. This is the same lesson as Section 6.3 arriving from a different
direction — modelling choices that matter at the load factors the method assumes
may be irrelevant at the load factors the operator has.

{{TABLE_PAIRS}}

**Table 5.** Deviation between multiplicative and cross-term-free composition,
over all pairs of throughput-affecting features. The deviation grows as LF²,
so it is negligible at the measured operating point and material only near full
load.

## 5. Ground-Truth Validation

### 5.1. Manufacturing ground truth

Passive capture has no ground truth, so we manufacture it. An instrumented RAN
emulator registers terminals against a real 5G core over NGAP [14] on N2 and
injects user-plane traffic over GTP-U [12] on N3, implementing the protocol stack
directly rather than through an external RAN. Because it generates every packet,
it records exactly what it sent: a manifest of per-terminal identities, tunnel
endpoints and injected byte and packet counts, together with a lossless capture
of the injected stream. The injected reference used here carries
{{lfb_truth_packets}} packets at {{lfb_truth_mbps}} Mb/s.

We then subject that lossless capture to controlled impairment reproducing the
three mechanisms a production mirror exhibits — uniform loss, capacity saturation
with tail-drop, and timestamp coalescing, plus multi-tap duplication — and pass
the impaired capture to two estimators: a conventional throughput probe, and a
corrected estimator that recovers the loss ratio from in-band sequence
information and rescales accordingly. The correction is the standard one for
tunnelled user planes and we state it for self-containedness: GTP-U carries a
per-tunnel sequence number and the inner IPv4 header a per-source identifier, so a
capture that is missing packets exhibits gaps in an otherwise monotone sequence.
Summing the gaps over a window estimates the loss ratio ℓ of the *capture*, and
dividing the observed byte count by (1 − ℓ) restores the offered volume. The
estimate is unbiased whenever losses are independent of packet size; under
tail-drop it is not, which is why the saturation conditions below are included.
For each condition we compute the resulting
load factor and the prediction of (3), and compare against the values the ground
truth implies. The operating point is LF = {{lfb_lf}} with
{{lfb_features}} active, for which A = {{lfb_amplification}}
(κ: {{lfb_kappa_list}}).

### 5.2. Results

![**Fig. 2.** Validation against ground truth. (a) Measured propagation of capture error into predicted-throughput error, against the first-order budget ε·A and the no-amplification reference; the measured curve tracks the budget closely at small ε and falls below it as ε grows, so the budget is conservative throughout. (b) Predicted-throughput error before and after the in-band capture-loss correction, per impairment condition (log scale).](figures/fig2_bridge.png)

{{TABLE_BRIDGE}}

**Table 6.** Propagation of capture error to predicted throughput,
{{lfb_conditions}} impairment conditions × {{lfb_seeds}} seeds. ε is the relative
error of the measured throughput against ground truth; ΔLF and ΔR_sim are the
resulting relative errors in load factor and predicted throughput; ε·A is the
first-order budget of (5); the last column is the prediction error after
capture-loss correction.

Three findings. First, **the propagation is real and large.** A capture error of
24% becomes a prediction error of 35%; the worst condition tested turns
{{lfb_probe_eps}}% into {{lfb_probe_pred_err}}%. An operator acting on such a
prediction would misjudge the value of a feature by more than the feature's own
claimed benefit.

Second, **the first-order budget holds where it matters and errs safely
elsewhere.** For |ε| ≤ 5% the residual between εA and the measured prediction
error has mean {{lfb_resid_small_mean}} and maximum {{lfb_resid_small_max}}
percentage points over {{lfb_resid_small_n}} cases — the budget is exact for
practical purposes. It degrades as ε grows (mean residual
{{lfb_resid_mid_mean}} pp for 5–20%, {{lfb_resid_big_mean}} pp beyond 20%),
because (5) discards second-order terms that the multiplicative form of (3)
retains. Crucially the residual is one-signed: in {{lfb_conservative_pct}}% of all
conditions the budget *over*-predicts the error. A budget that is exact in the
operating region and conservative outside it is usable as a design rule; one that
under-predicts would not be. We state the scope of that claim precisely: every
condition here produces ε < 0, because the impairments model a capture that
*loses* packets, which is what a span port does. Over-reporting arises from the
opposite mechanism — duplicated copies counted twice — and the estimators used
here deduplicate, which is why the `dup10` condition produces no error at all.
The magnitude of the un-deduplicated duplication error is not a modelling
assumption but a measurement, and we report it on production traffic in
Section 6, where it reaches {{field_dup_max}}×.

Third, **the correction collapses the propagated error.** The corrected estimator
holds capture error to {{lfb_corr_eps}}% and prediction error to
{{lfb_corr_pred_err}}%, against {{lfb_probe_pred_err}}% uncorrected — an
improvement of {{lfb_improvement_decades}} orders of magnitude. This is the
quantitative case for treating measurement validation as part of the estimation
method rather than as infrastructure beneath it.

One condition, {{lfb_clip_fired}}, is instructive: its capture error of
{{lfb_probe_eps}}% produced a load-factor error of only
{{lfb_probe_lf_err}}% because the clip bound and truncated it — and yet the
prediction error was still {{lfb_probe_pred_err}}%, because the leading R in (3)
is not clipped. The clip hides the error in the intermediate quantity without
removing it from the output. This is the mechanism of Section 4.2 observed in
measurement.

## 6. Load-Factor Distribution in Operational Private-5G Traffic

### 6.1. Method

The preceding sections characterize what happens to a measurement error at a
given load factor. Whether that matters depends on where real terminals sit. We
therefore extracted the load-factor distribution from
{{field_n_captures}} N3 mirror captures taken on a production private-5G network
over {{field_n_days}} separate days ({{field_packets}} packets in total,
{{field_n_ues}} distinct terminals, approximately one hour per capture).

**Identifying terminals.** Attribution is not incidental, and our first attempt
at it was wrong in a way worth recording. We initially assumed a single server
and credited only the traffic exchanged with it, which discarded most of the
capture: production terminals contact hundreds of distinct Internet hosts, so the
population with few peers is the servers, not the terminals. Terminals are
therefore identified by the operator's UE subnet ({{field_ue_selection}}), with a
fallback that selects private-range hosts having many distinct peers; direction is
then defined relative to the terminal rather than to any server. Under the
original assumption every load factor reported below would have been too small by
roughly an order of magnitude, which would have strengthened our conclusion for
the wrong reason.

Duplication must be removed before any throughput is computed, or the load factor
inherits the duplication factor directly. We deduplicate globally rather than
per-window: a TCP segment is credited once per (flow, sequence, length),
regardless of how far apart in time the mirror copies land, and datagram traffic
once per (five-tuple, IP identifier, length). Windowing then follows the agent's
own five-second cadence, and each window's throughput is normalized by the same
vendor peaks the agent uses.

### 6.2. Results

![**Fig. 3.** Operational load factors and the clipping floor. (a) Per-capture, per-direction load-factor quantiles on a logarithmic axis; every distribution lies three to five decades below the floor the method prescribes. (b) The composed gain the model applies (with clip) against the physically consistent gain (without); the shaded area between them is gain manufactured by the floor, and the vertical band marks the measured operating range.](figures/fig3_field.png)

{{TABLE_FIELD}}

**Table 7.** Load-factor distribution in operational traffic. "Dup." is the
observed duplication factor before deduplication. LF values are *raw*
R/P quotients, before the clip of (1) is applied; the final column reports the
fraction of windows the clip would bind.

The result is unambiguous and does not depend on which capture is examined.
Observed duplication ranges from {{field_dup_min}}× to {{field_dup_max}}×. The
spread across captures is itself informative: the factor depends on how many
mirror taps were active and on the share of traffic visible on both N3 and N6, so
it is a property of the capture configuration on the day rather than a constant
of the deployment. An agent cannot assume a fixed correction; it has to
deduplicate. Naive byte summation is not a viable starting point at any of these
factors. Median
downlink load factors lie between {{field_dl_lf_p50_min}} and
{{field_dl_lf_p50_max}}; the largest single window observed reaches
{{field_dl_lf_max}}. Uplink medians are of the same order. Against
these values the clipping floor of {{field_lf_min}} stands
{{field_clip_ratio_min}}× to {{field_clip_ratio_max}}× above the median, and

> **all {{field_clipped_windows}} of {{field_windows}} windows — every window in
> every capture, on every day, in both directions — fall below the floor.**

With no exception in {{field_windows}} windows, the rule of three places a 95%
upper bound of {{field_unclipped_upper95_pct}}% on the fraction of windows that
would sit above the floor on this network. The finding is not a property of one
capture or one hour.

### 6.3. The calibration degenerates

The consequence follows directly from Section 4.2. If every window clips, then
LF ≡ LF_min for every terminal at every instant, and (3) reduces to

> R_d^sim(u) = R_d(u) · Π_f (1 + β_f · LF_min),

a *fixed multiplier* — {{clip_gain_at_floor}} for the three-feature configuration
used here — applied uniformly to whatever the mirror reported. The mechanism the
method advertises, propagation of per-terminal heterogeneity through a measured
load factor, does not operate at all in the regime this operator occupies. The
per-terminal calibration is present in the code and absent from the result.

The substitution is not neutral. At the observed median load factors the
physically consistent composed gain is at most {{clip_physical_gain_max}} — a
benefit of {{clip_physical_pct_max}}%, indistinguishable from none — because a
terminal drawing a
fraction of a percent of the cell's single-terminal capacity cannot benefit much
from a feature that raises peak capacity. The clipped model instead predicts
{{clip_gain_at_floor}}, a benefit of {{clip_gain_at_floor_pct}}% — an
overstatement of {{clip_overstate_max}}–{{clip_overstate_min}}% applied to every
terminal in the network. Reported as a business case, that is the difference
between a feature that pays for itself and one that does not.

This also settles a question about the floor's stated purpose. The clip is
motivated as noise suppression at low load, and at first reading that is
plausible: relative measurement noise is largest when the signal is smallest, and
the floor removes the model's sensitivity to it. But Table 4 shows what the floor
substitutes in place of that sensitivity. Where the true load factor is two
orders of magnitude below the floor, the clip does not suppress a small noisy
quantity — it replaces the measurement with a constant that is
{{field_clip_ratio_min}}–{{field_clip_ratio_max}}× larger, and the resulting bias
dwarfs the noise it was introduced to control. Suppressing noise by discarding
the signal is not a favourable trade.

## 7. Discussion

### 7.1. Which claims survive

We separate the method's claims by what the evidence now supports.

*Survives.* The architecture — passive N3 capture, per-terminal attribution,
five-second windowing, simulator injection — is sound and imposes no burden on
the production network. The affine gain form (2) is analytically tractable and,
as Section 4 shows, yields a usable error budget precisely because it is affine.
The intent behind LF-scaling is physically correct: a lightly loaded terminal
should not be credited with a capacity gain.

*Requires restatement.* Trace-replay fidelity — the agreement between the
simulator's output and the measured trace when no feature is enabled — is a
pipeline integrity check, not a validation of feature-gain prediction. With
F(u) = ∅ equation (3) reduces to R^sim = R identically, so the comparison tests
the simulator's scheduling and framing, and nothing about the estimate the method
exists to produce. It should be reported as such.

*Does not survive as validation.* Confirming that predicted gains fall inside the
literature intervals from which they were derived is an algebraic identity, not
evidence. By (2) the prediction is 1 + βLF with LF ∈ [LF_min, 1] and β fixed from
the interval's median, so it lies inside [1, g^base] ⊆ [low, high] by
construction and cannot fall outside for any input whatsoever. It is a useful
regression check on the implementation and must not be presented as predictive
validity.

*Does not survive at all.* The per-terminal load-factor calibration, as specified
with LF_min = {{field_lf_min}} and a single-terminal-peak denominator, does not
function on the operational traffic we measured.

### 7.2. The minimal repair

Two changes restore the mechanism, and they are not equivalent.

**Remove the floor.** Setting LF_min = 0 makes (2) behave as intended: gains
shrink toward unity as load falls, and a terminal at LF = 0.003 is credited with
{{clip_physical_gain_max}} rather than {{clip_gain_at_floor}}. This is physically
correct and costs nothing to implement. Its consequence is that on this network
the honest estimate of throughput-feature benefit is close to zero — which is
information, not failure. It also means the estimate becomes insensitive to
capture error in exactly the low-load regime (A → 1 as LF → 0, and indeed
A = {{field_amp_unclipped}} at the observed median), so the accuracy demand on the
mirror relaxes where the load is light and tightens where it is heavy.

**Re-base the denominator.** If the operator's question is "what fraction of the
resource available *to this terminal under current conditions* is it using", then
the single-terminal vendor peak is the wrong denominator, because it is never
available to a terminal sharing a cell. We tested the simplest alternative that
requires no additional telemetry — normalize each terminal by its own observed
peak over the capture — on the same windows. The dynamic range returns at the top
of the distribution: the 95th percentile of the re-based load factor lies between
{{own_p95_min}} and {{own_p95_max}} across the ten terminal-direction series,
against {{field_dl_lf_max}} for the vendor-peak denominator, so the busiest
windows now land inside the region where (2) is sensitive to the measurement.
The median does not: it remains {{own_p50_min}}–{{own_p50_max}}, and
{{own_clip_min}}–{{own_clip_max}}% of windows still clip. Re-basing therefore
helps and does not suffice — the floor is what has to go, and re-basing is what
makes the remaining load factor informative once it does.

We report this as a measurement rather than a recommendation. An own-peak
denominator is self-referential: a terminal that never loads the cell has a small
peak and is credited with a high load factor, which is not what the model means.
A scheduler-aware resource share would be the principled denominator, and we do
not have the telemetry to validate one here. Substituting a denominator we could
not check would repeat the error this paper documents.

### 7.3. Threats to validity

*The field captures are from one network.* Three captures on one private 5G
deployment establish that the degeneracy occurs, not how common it is. A network
carrying sustained high-rate traffic — a fixed-wireless-access or video-uplink
deployment — could sit above the floor. The finding to carry forward is not "load
factors are always small" but "the operating-point distribution must be measured
before a clipped calibration is trusted", which no prior treatment does.

*Ground truth is generated by an emulator, not by production traffic.* The
propagation experiments of Section 5 use injected traffic whose volume is known
exactly. This is what makes ground truth possible, and it is also a limitation:
the traffic's statistical structure is ours, not an operator's. The propagation
law (4)–(5) is a property of the model rather than of the traffic, so we expect
it to transfer; the specific ε values under saturation would differ with a
different burst structure.

*Feature gains remain literature transcriptions.* Nothing in this paper validates
the g^base values themselves, and no measurement can until the corresponding
firmware ships. We regard this as the central open item and have kept the low,
median and high estimates separate so that the resulting spread is visible rather
than collapsed into a point prediction. When Release 17/18/19 features become
available on the testbed, the same ground-truth apparatus used here for the
measurement chain can be turned on the gains themselves — an A/B measurement with
the feature disabled and enabled, against the same injected reference.

*The error budget is first-order.* Equation (5) discards second-order terms.
Section 5.2 quantifies where this matters and shows the residual is conservative
throughout, but an operator working at ε > 20% should use (3) directly rather
than the budget.

## 8. Conclusion

Load-factor Real2Sim estimation is attractive because it grounds a counterfactual
in the operator's own measurements, and fragile for exactly the same reason.
This paper traced the single empirical input of that method — throughput measured
at a passive N3 mirror — through to its output. Because the calibration is affine
in the load factor, the propagation has a closed form: per-feature transfer
κ = βLF/(1 + βLF), end-to-end amplification A = 1 + Σκ, bounded by one plus the
number of active features and invertible into an accuracy requirement on the
capture. Against ground truth manufactured by injecting known traffic into a real
core, the first-order budget is exact to {{lfb_resid_small_max}} percentage points
for capture errors within 5% and conservative in every condition tested, and an
in-band capture-loss correction reduces the worst propagated prediction error from
{{lfb_probe_pred_err}}% to {{lfb_corr_pred_err}}%.

Applying the same lens to operational data produced the result that matters most
for practice. In {{field_n_captures}} production private-5G captures, every one of
{{field_windows}} measurement windows falls below the load-factor clipping floor
the method prescribes, by {{field_clip_ratio_min}}× to {{field_clip_ratio_max}}×
at the median. The per-terminal
calibration therefore degenerates to a constant multiplier and overstates composed
feature gains by {{clip_overstate_max}}%. Removing the floor restores the
physically correct behaviour and, on this network, changes the honest answer from
a substantial predicted gain to nearly none.

We think the general lesson outlives the particular method. An estimation
pipeline anchored to measurement inherits the measurement's error, and the
inheritance is quantifiable if the model is written down carefully enough. Where
ground truth is unavailable in production, it can be manufactured; where a
calibration is clipped, the operating-point distribution decides whether the
calibration exists at all. Both checks are cheap, and neither was being performed.

## CRediT authorship contribution statement

**Mahnsuk Yoon:** Conceptualization, Methodology, Software, Validation, Formal
analysis, Investigation, Data curation, Writing – original draft, Writing –
review & editing, Visualization. **Yong-An Jung:** Methodology, Validation,
Writing – review & editing. **Sung-Hun Lee:** Supervision, Project
administration, Funding acquisition, Writing – review & editing.

## Declaration of competing interest

The authors declare that they have no known competing financial interests or
personal relationships that could have appeared to influence the work reported in
this paper.

## Data availability

The data and code that support the findings of this study are openly available in
the GitHub repository https://github.com/mahnsuk-eng/ranemu-real2sim (release
v1.0.0), archived at https://doi.org/10.5281/zenodo.XXXXXXX. The repository
contains the RAN emulator used to generate ground truth, the load-factor
extraction and error-propagation code, the feature gain library with its source
annotations, the raw result files underlying every table and figure, and the
build script that substitutes those files into the manuscript, so that every
reported number can be regenerated rather than transcribed. The derived
load-factor series of Section 6 is released as a documented CSV (4,190 windows;
per-window throughput, load factor before clipping, and load factor after
clipping), so the central finding is checkable directly from the released file.
Every experiment is seeded and its seed is recorded in the corresponding result
file; the ground-truth capture is regenerated deterministically from seed 42
rather than distributed. Code is released under the MIT licence and data under
CC BY 4.0.

One dataset is withheld and one is included in derived form. The operational N3
mirror captures analysed in Section 6 contain production user-plane traffic from
a live private network and cannot be released. What the analysis consumes is not
the packets but the per-terminal, per-window throughput series derived from them,
and that series — together with the deduplication statistics of Table 7 — is
included in the archive, so Sections 6 and 7 are reproducible end to end from
released data. The extraction code is released as well, so the derivation can be
repeated by any party holding equivalent captures.

## Acknowledgements

This work was partly supported by the Institute of Information & Communications
Technology Planning & Evaluation (IITP) grant funded by the Korea government
(MSIT) (No. RS-2025-02311938, Development of 6G Open Service Verification
Platform Technology, 50%; No. RS-2025-25455300, Development of Intelligent
On-Device Network Interoperability Test Platform, 50%).

## References

[1] ITU-T Recommendation Y.3090, Digital twin network — Requirements and architecture, ITU-T, 2022.

[2] ITU-T Recommendation Y.3092, Digital twin for management and orchestration of IMT-2020 networks, ITU-T, 2024.

[3] A. Mozo, A. Karamchandani, S. Gómez-Canaval, M. Sanz, J.I. Moreno, A. Pastor, B5GEMINI: AI-driven network digital twin, Sensors 22 (11) (2022) 4106. doi:10.3390/s22114106.

[4] N. Patriciello, S. Lagen, B. Bojovic, L. Giupponi, An E2E simulator for 5G NR networks, Simul. Model. Pract. Theory 96 (2019) 101933. doi:10.1016/j.simpat.2019.101933.

[5] G. Nardini, D. Sabella, G. Stea, P. Thakkar, A. Virdis, Simu5G — An OMNeT++ library for end-to-end performance evaluation of 5G networks, IEEE Access 8 (2020) 181176–181191. doi:10.1109/ACCESS.2020.3028550.

[6] D. Evgenieva, et al., A comprehensive survey of 6G simulators, Electronics 14 (16) (2025) 3313. doi:10.3390/electronics14163313.

[7] 3GPP TR 38.859, Study on evolution of NR duplex operation, v18.0.0, 2023.

[8] 3GPP TS 37.340, Multi-connectivity; Stage 2, v18.x.

[9] 3GPP TR 38.843, Study on artificial intelligence (AI)/machine learning (ML) for NR air interface, v18.0.0, 2023.

[10] 3GPP TS 38.214, NR; Physical layer procedures for data, v18.x.

[11] 3GPP TR 38.864, Study on network energy savings for NR, v18.0.0, 2023.

[12] 3GPP TS 29.281, General Packet Radio System (GPRS) Tunnelling Protocol User Plane (GTPv1-U), v18.x.

[13] 3GPP TS 38.300, NR; Overall description; Stage 2, v18.x.

[14] 3GPP TS 38.413, NG-RAN; NG Application Protocol (NGAP), v18.x.

