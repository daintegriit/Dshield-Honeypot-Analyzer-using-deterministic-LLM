# Amendments to THIRD_PARTY_DETECTORS_REGISTRATION.md

## A1 (2026-10-15, before any detector was run): operational clarifications

None of these changes a prediction or a pass/fail criterion; each fixes how one
is computed where the registration left it open. Committed with the run kit
(`code/thirdparty/`) before the first run.

- **C1. Window size.** P1–P5 are judged on 1-minute windows, the paper's primary
  window. 5-minute results are reported alongside and judge nothing.
- **C2. "Differs" in P3.** The signs of r(score, ground truth) differ between
  TRUE and ARRIVAL, or their 95% Fisher intervals do not overlap.
- **C3. Undefined r.** If a detector's score is constant over the windows in
  question, r is undefined. For P4 and P5 that counts as no dependence on T and
  is reported as undefined, not as a value.
- **C4. τ in P2.** τ = minutes since the start of the Slips time window that
  contains the window's end, with Slips time windows taken as aligned to the
  first record of the stream it was fed: τ = T mod 60.
- **C5. Kitsune decay checked (§6).** `AfterImage.py`, `processDecay`:
  `factor = math.pow(2, (-self.Lambda * timeDiff))`, on the packet timestamps
  passed in. The slowest λ = 0.01 has a 100 s half-life; the registered 10-minute
  lookback stands. No lookback amendment is made.
- **C6. Slips pilot.** The image digest is pinned by a pilot run on a sample
  bundled inside the Slips image, not on registered data, used only to confirm
  the alerts.json field mapping and extract the ThreatLevel map from the pinned
  source into `threat_map.json`.
- **C7. No ground truth reaches a detector.** In the .binetflow files given to
  Slips, the Label column is replaced by `flow=Unknown`. The random forest reads
  only the nine registered fields.
- **C8. Environment.** Kitsune-py (2018) uses `np.Inf`, which NumPy 2 removed; it
  runs unmodified in a virtual environment with `numpy<2`, plus Cython and scapy,
  which its imports require.
- **C9. Window identity.** Before any statistic is read, the kit's TRUE-mode
  windows are checked to match Chiron's positive-control windows exactly
  (window end, labeled flows, botnet flows); a mismatch stops the analysis.

## A2 (2026-10-15, before any detector was run): a weakness in P4 and P5, recorded, not repaired

Testing the kit on synthetic flows showed that P4 and P5, as registered, can
fail for a reason other than replay age: benign windows (botnet fraction < 0.5)
may still carry botnet flows, and if that share drifts over the capture, a
detector with no temporal state correlates with T through window content. The
predictions stand as registered. Two exploratory statistics (§8) are added to
separate the causes: r(score, T) over benign windows that contain no botnet
flow, and the partial correlation r(score, T | botnet fraction). If P4 or P5
fails, both are reported next to it.
