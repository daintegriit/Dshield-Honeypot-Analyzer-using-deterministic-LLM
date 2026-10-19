# Paper 2, Change 2 — burst expectation against available history

Status: LOCKED at the commit that adds this file. Change 2 has not been run on
any data before that commit. Changes after the lock go in
`CHANGE2_AMENDMENTS.md` and may not alter a prediction or a criterion.

## Change
The denial-of-service component's expected last-5-minute share of the trailing
hour changes from the constant 0.083 to min(5, T)/min(60, T) while T < 60, where
T is minutes since the first event in scope; for T >= 60 the constant 0.083 is
kept, so no window ending an hour or more after its stream starts can change.
Nothing else changes. Flag `DOS_EXPECT_AVAILABLE=1`; unset, the core is the
positive-control core (`code/change2/copilotCore.js`, built on the frozen backend
sha 91f4ad86…).

## Runs (`code/change2/run_change2.sh`)
CTU-13 s1, s2, s6, s8, s9; true time, lookback scoped per scenario.
- Control: flag unset, deployed and ablated, 1-minute windows (10 runs).
- Change 2: flag set, deployed and ablated, 1- and 5-minute windows (20 runs).
Reference: the positive-control runs of Paper 1 (`poscontrol_20261014/runs`).

## Criteria (`code/change2/change2_eval.py`)
- **Control.** Every control run's riskScore equals the positive-control run's
  in every window. If not, stop: nothing below is read.
- **C2-P1 (by construction).** In every Change 2 run, every window ending ≥ 60
  minutes after its stream starts has the same riskScore as the positive
  control (max |diff| = 0). If this fails, the change is not the change
  described, and C2-P2 and C2-P3 are not read.
- **C2-P2.** Deployed 1-minute runs; benign windows with traffic ending < 60
  minutes after stream start. The 95% Fisher interval of r(DoS score, T)
  includes 0 on at least 4 of 5 scenarios. A DoS score constant over those
  windows (r undefined) counts as not tracking T. Baseline before the change,
  computed from the positive control before this lock: r between −0.80 and
  −0.92 on all five.
- **C2-P3 (reported, not judged).** r(risk, botnet fraction) on admissible
  windows before and after. By C2-P1 it cannot change, so the true-time
  inversions on s1 and s6 are not fixed by Change 2.

A failure is reported as a result.
