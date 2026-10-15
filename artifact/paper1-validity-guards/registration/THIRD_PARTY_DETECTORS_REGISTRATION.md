# Registration: three independent detectors through the validity conditions

Status: LOCKED at the commit that adds this file. No detector named below has
been run on any data named below before that commit. Changes after the lock are
appended to `THIRD_PARTY_DETECTORS_AMENDMENTS.md` with a timestamp and reason; no
amendment may change a prediction or a pass/fail criterion.

## 1. Question

The temporal screen (TEMPORAL_SCREEN_PROTOCOL.md) sorts published evaluations by
design into EXPOSED (temporal aggregation, ordered evaluation, no warm-up
handling), MITIGATED (the same, with lookback state handled), and NOT EXPOSED
(no cross-record temporal state). We ask whether those design categories predict
how real, independent detectors behave under the same replay and the same twelve
conditions that were applied to Chiron, and whether the conditions behave on
those detectors as the positive control says they should.

## 2. Detectors (one per category)

| ID | Detector | Category by design | Why |
|---|---|---|---|
| D1 | Slips (Stratosphere Linux IPS), release v1.1.22, Docker image `stratosphereips/slips` pinned by digest at run time | temporal state, per-IP profiles in time windows (default `time_window_width` 1 h) | Same lab as CTU-13; trailing-window behavioral state of the kind that produces the replay-age confound |
| D2 | Kitsune / KitNET (Mirsky et al., NDSS 2018), `ymirsky/Kitsune-py`, commit pinned at run time | temporal state with explicit warm-up: damped incremental statistics; first FMgrace + ADgrace packets train and are not scored | Built-in warm-up handling |
| D3 | Per-flow random forest (scikit-learn, version pinned at run time) on CTU-13 binetflow fields | no cross-record state | Negative control |

All detectors run with their published defaults except where this file fixes a
value. Version strings, image digest and commit hash are written to
`runs/third_party/VERSIONS.txt` before the first run.

## 3. Data

- **D1, D3:** the five development CTU-13 scenarios already reported in the
  paper (s1, s2, s6, s8, s9), labeled flows only (background excluded), exactly
  the flows the Chiron CTU-13 replays score. The eight held-out CTU-13 scenarios
  under HELDOUT_REGISTRATION.md are not touched.
- **D2:** CTU-Mixed-Capture-1 (pcap), with the infection boundary already
  derived from the matched malware-only capture Botnet-131-1 for Paper 2. Packets
  before the boundary are benign; packets to or from the confirmed C2
  destinations after it are malicious; other post-boundary packets from the
  infected host are malicious; all other packets are benign. Kitsune needs
  packets, and CTU-13 publishes only botnet-side pcaps, so CTU-13 is not used
  for D2.

## 4. Two time modes (the manipulation)

- **TRUE:** each record keeps its recorded timestamp (binetflow `StartTime`,
  pcap timestamp). Windows and detector state run on true time.
- **ARRIVAL:** timestamps are rewritten to the constant-rate arrival times the
  Chiron CTU-13 replay assigns (same rate, same start, same order, taken from
  the recorded replay metadata), so the detector sees the stream as the Chiron
  replay presented it. For D2 the pcap is retimed with the same rule using
  `editcap`/`tcprewrite`; D2 ARRIVAL is exploratory (Section 8).

Nothing else differs between modes.

## 5. Window scores and alerts (fixed before running)

Windows: 1 min and 5 min, tumbling, aligned to the first record of the stream
in each mode, as in the paper.

- **D1 Slips:** window score = sum over Slips evidence whose timestamp falls in
  the window of the evidence's threat level × confidence, with threat levels
  mapped to numbers exactly as the pinned version's source does (the map is
  copied into VERSIONS.txt). Window alert = Slips raised an alert for any
  profile with evidence in the window, under the pinned defaults
  (`time_window_width: 3600`, `evidence_detection_threshold: 0.25`,
  `risk_accumulated_threat_level: 5` in `config/slips.yaml` on `develop` as of
  2026-10-14; the values in the pinned release are recorded and used). The
  confusion-matrix threshold is Slips' own alert decision.
- **D2 Kitsune:** window score = maximum per-packet RMSE in the window.
  FMgrace = 5,000, ADgrace = 50,000 (the repository's example values). Threshold
  = the 1 − 10⁻³ quantile of a log-normal fitted to the RMSE of the 10,000
  packets after ADgrace; these packets and the grace packets are training and
  are excluded from evaluation windows. If the pre-boundary prefix holds fewer
  than 65,000 packets, both grace values and the threshold sample are scaled by
  the same factor so the training period ends before the boundary; the factor
  is recorded.
- **D3 random forest:** features `Dur, Proto, Dir, State, sTos, dTos, TotPkts,
  TotBytes, SrcBytes` (categoricals one-hot; no addresses, ports, timestamps or
  label-derived fields). Leave-one-scenario-out: trained on the other four
  development scenarios, scored on the fifth. 300 trees, `class_weight=
  "balanced"`, seed 20261015. Window score = mean flow probability of the
  botnet class in the window; window alert = score ≥ 0.5.

Window ground truth and admissibility: exactly as in the paper's positive
control (botnet fraction per window, the twelve conditions in
`code/scripts/guard_audit.py`).

## 6. The conditions, unchanged except one parameter

`guard_audit.py` is run unmodified except that the lookback used by
INCOMPLETE_LOOKBACK and FOREIGN_LOOKBACK becomes a parameter (default 60 min,
which reproduces every published audit exactly). It is set to each detector's
declared lookback, fixed here:

- D1 Slips: 60 min (one time window).
- D2 Kitsune: 10 min. The default decay factors are `Lambdas = [5,3,1,.1,.01]`
  (`netStat.py`); under the paper's 2^(−λt) decay the slowest has a 100 s
  half-life, and six half-lives ≈ 10 min. The decay form is checked against the
  pinned AfterImage source before the first run; if it differs, the lookback is
  restated by amendment before any detector is run. This is the only amendment
  permitted before running.
- D3 random forest: 0 (no lookback; both lookback conditions are NA).

## 7. Predictions (registered)

Replay-age statistic: Pearson r between window score and T (minutes since the
first record of the stream) over benign windows with traffic, with a Fisher z
interval against n_eff = n·step/window, as in the paper. Window-age statistic:
the same against τ (minutes since the start of the detector's own current time
window), for D1 only.

- **P1 (D1, ARRIVAL).** On every scenario where all benign windows with traffic
  end less than 60 min after the stream start, INCOMPLETE_LOOKBACK withholds the
  run. (Deterministic given the data; it checks that the condition transfers.)
- **P2 (D1).** Slips' score depends on how long its state has been accumulating:
  r(score, τ) over benign windows has a Fisher lower bound > 0 on at least three
  of the five scenarios in TRUE mode.
- **P3 (D1, TRUE vs ARRIVAL).** On at least three of five scenarios, the sign or
  the 95% interval of r(score, ground truth) differs between modes.
- **P4 (D2, TRUE).** After the grace period, the r(score, T) interval over
  benign windows includes 0, and neither lookback condition fires.
- **P5 (D3, both modes).** Per-flow scores are identical across modes by
  construction; the r(score, T) interval over benign windows includes 0 on every
  scenario, and no lookback condition applies. Any condition that withholds a D3
  run is named and reported; it cannot be the confound.
- **P6 (overall).** The screen's categories predict behavior if P2 and P3 hold
  for D1, P4 for D2 and P5 for D3.

Each prediction is reported as held or failed, with its statistic and interval.
A failed prediction is reported as a result, not explained away.

## 8. Exploratory, not tested against predictions

D2 in ARRIVAL mode; balanced accuracy and F1 of every admissible run; which of
the twelve conditions withholds each inadmissible run; Q5 state scope for D1
(whether Slips state persists across scenarios if fed concatenated).

## 9. Outputs

`runs/third_party/<detector>/<scenario>/<mode>/` with raw detector output,
window scores, the guard audit CSV and the r statistics; one summary table
`runs/third_party/SUMMARY.tsv`; this file's SHA-256 recorded in
`THIRD_PARTY_DETECTORS_SHA256.txt` at the lock commit.
