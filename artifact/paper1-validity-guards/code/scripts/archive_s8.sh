#!/usr/bin/env bash
#
# archive_s8.sh
# ---------------------------------------------------------------------------
# Freeze the CTU-13 scenario 8 evaluation under copilotCore v4.1.
#
# This is the FPR test (92% benign traffic) AND the first positive result in
# the project: the C2 detector tracks hand-labeled C&C ground truth at
# rho = 0.845 (15-min windows), and becomes the dominant classification for the
# first time across any scenario.
#
set -euo pipefail

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/research/results/s8_v41_${STAMP}"

echo "=========================================================="
echo "  ARCHIVING CTU-13 SCENARIO 8 (v4.1) — FPR test + C2 positive"
echo "=========================================================="
echo "  destination: $DEST"

mkdir -p "$DEST/eval" "$DEST/code_snapshot" "$DEST/replay"

echo ""
echo "-- evaluation JSON --"
for f in "$HOME"/backend/eval_s8_v41_w1.json \
         "$HOME"/backend/eval_s8_v41_w5.json \
         "$HOME"/backend/eval_s8_v41_w15.json; do
  [ -f "$f" ] && cp "$f" "$DEST/eval/" && echo "   ✓ $(basename "$f")  ($(du -h "$f" | cut -f1))"
done

echo ""
echo "-- code snapshot --"
for f in "$HOME/backend/services/copilotCore.js" \
         "$HOME/backend/routes/ingestRoutes.js" \
         "$HOME/backend/models/AttackModel.js" \
         "$HOME/backend/analyze_ctu13.js" \
         "$HOME/research/scripts/replay_ctu13.py"; do
  [ -f "$f" ] && cp "$f" "$DEST/code_snapshot/" && echo "   ✓ $(basename "$f")"
done

echo ""
echo "-- replay log --"
[ -f "$HOME/research/scripts/s8_clean.log" ] && \
  cp "$HOME/research/scripts/s8_clean.log" "$DEST/replay/" && echo "   ✓ s8_clean.log"

CORE_VER=$(grep -o 'copilotCore-v[0-9A-Za-z.-]*' "$HOME/backend/services/copilotCore.js" | head -1 || echo unknown)

cat > "$DEST/MANIFEST.md" << 'EOF'
# CTU-13 Scenario 8 (v4.1) — FPR Test + First Positive C2 Result

Series:
- `../baseline_20260715T041836Z/`            s1, v3.7
- `../v4_rate_independent_20260715T071429Z/` s1, v4.0
- `../s9_v41_20260715T165806Z/`              s9, v4.1
- **this**                                   s8, v4.1

## Why this run

Every prior scenario was botnet-heavy (s1: 57/43, s9: 86/14), leaving
`benign_n` at 1–15 windows — far too few to support any false-positive claim.
Scenario 8 inverts the balance: **92% normal traffic**. It is also C&C-dense
(1,074 C&C of only 6,127 botnet flows = **17.5%**) with almost no DNS noise
(69 flows), which turns out to be the decisive difference.

## Data

- 78,949 flows replayed, **0 failed**, 36.8 min, 35.78 eps

| ctu_subclass | count  |
|--------------|--------|
| normal       | 72,822 |
| other        |  4,977 |
| **c2**       | **1,074** |
| dns          |     69 |
| ad           |      4 |
| download     |      2 |
| icmp         |      1 |

## Result 1 — the C2 detector works, and scales with window size

| window | ρ(c2score, c2_flows) | ρ(risk, botnet_frac) | mean c2score (C&C present) | c2 dominant |
|--------|----------------------|----------------------|----------------------------|-------------|
| 1 min  | **0.615** | 0.353 | 15.44 | 0 |
| 5 min  | **0.798** | 0.655 | 31.97 | 0 |
| 15 min | **0.845** | **0.864** | 44.57 | **3** |

**ρ = 0.845** against hand-labeled C&C ground truth. Correlation strengthens
monotonically with window size — exactly what periodicity-based beaconing
detection should do, since inter-arrival regularity requires temporal span to
become visible.

At 15 min, `c2` became the **dominant classification for the first time in the
project** (3 windows), producing a `c2` column in the attack-type table that
had never appeared across s1 or s9. The final window:

```
flows=32,165  c2=800 flows | c2score=75 | risk=62 | state=high | dom=c2
```

The system detected command-and-control.

### Specificity — only the C2 scorer responds

Comparing C&C-heavy windows (c2 ≥ 20 flows, n=19) vs C&C-light (c2 < 5, n=7),
1-min windows:

| classifier   | c2-heavy | c2-light | delta |
|--------------|----------|----------|-------|
| **c2**       | **21.84** | **7.14** | **+14.70** (3x) |
| scan         | 73.37 | 70.05 | +3.32 |
| dos          | 55.35 | 58.45 | −3.10 |
| web_probe    |  8.38 |  6.92 | +1.46 |
| brute_force  |  0.97 |  0.00 | +0.97 |

Only `c2Score` moves. The other four are flat within noise. This is
specificity, not merely correlation.

## Result 2 — the boundary condition

| scenario | C&C as % of botnet | DNS flows | ρ(c2score, c2) |
|----------|--------------------|-----------|----------------|
| s9 | 1.6% (2,973 / 184,987) | 107,786 | **−0.03** |
| s1 | 0.8% (341 / 40,961)    |  29,197 | +0.14 |
| **s8** | **17.5%** (1,074 / 6,127) | **69** | **+0.845** |

**The C2 detector works when C&C is a meaningful fraction of malicious traffic
and is not masked by high-volume DNS flooding.** It fails when C&C is <2% and
buried under ~100k DNS flows. This is a specific, falsifiable boundary — not a
blanket claim.

## Result 3 — FPR, and why the binary metrics are degenerate here

`malicious_n = 0` at every window size. Scenario 8's botnet never exceeds ~18%
of any window, so the truth rule (botnet_fraction ≥ 0.5) labels **every window
benign**. Consequences:

- The FPR test is clean but uninformative at 1/5 min: `FP=0`, `FPR=0.000`,
  `specificity=1.000` — because v4.1 fires on almost nothing.
- At 15 min: `FP=6`, `FPR=0.261`, `balanced_accuracy=0.370`.

**Those 6 "false positives" are suspect.** They are windows the 0.5 rule calls
benign that nevertheless contain 200–800 labeled C&C flows. They may be correct
detections mislabelled by a truth threshold that does not fit this scenario's
distribution. **The correlation (ρ = 0.845), not the confusion matrix, is the
defensible result for scenario 8.**

This is a limitation of the window-composition truth rule, not of the detector:
a fixed botnet-fraction threshold is inappropriate when the botnet is a small
but behaviourally significant minority of traffic.

## Result 4 — threshold sweep suggests a real operating point

| truth thr | best risk thr | P | R | F1 | FPR |
|-----------|---------------|---|---|-----|-----|
| ≥0.05 (5m)  | 45 | 0.750 | 0.833 | 0.789 | 0.333 |
| ≥0.05 (15m) | 50 | **1.000** | 0.846 | **0.917** | **0.000** |
| ≥0.10 (15m) | 50 | 0.727 | 1.000 | 0.842 | 0.200 |

At 15 min with `risk ≥ 50` and truth ≥ 0.05: **P=1.000, R=0.846, F1=0.917,
FPR=0.000**. Unlike the earlier scenarios, this is *not* the constant-"Attack"
artifact — FPR is genuinely 0 while recall is 0.846. This is the first
non-degenerate operating point observed in the project.

## Metric artifact — still present at low thresholds

`truth≥0.01 / risk≥10` gives F1 = 1.000 with FPR = 1.000 (1-min: 0.985/1.000).
The same detector reports "perfect" or "useless" depending on which metric is
quoted. Reporting P/R/F1 without FPR and TN remains actively misleading.

## What this establishes

1. The C2 component is a **working detector** under identifiable conditions
   (ρ = 0.845; 3x score separation; specific — no other classifier responds).
2. Its failure mode is **masking by high-volume DNS**, not a defect in the
   periodicity logic.
3. Detection quality **scales with window size**, consistent with the
   beaconing mechanism.
4. The window-composition truth rule (botnet_fraction ≥ 0.5) is **unsuitable**
   for scenarios where the botnet is a small minority; a C&C-density-based
   truth rule would be more appropriate.

## Next

- **Scenario 2** (673 C&C) and **13** (536 C&C) — locate where the boundary
  sits. Turns "works sometimes" into "works above X% C&C density" — a curve.
- **Scenario 1 under v4.1** — isolates the dosScore fix from the family change.
- Consider a **C&C-density truth rule** alongside botnet_fraction.
- `dosScore`'s concentration terms are anti-correlated (−47.9 on s9) and drown
  `scanScore` (+15.7) inside `strongestSignal = max(...)`. Removing them is the
  next principled fix.

## Files

- `eval/` — per-window records incl. `rateIndependentFeatures`
- `code_snapshot/` — exact v4.1 code that produced these numbers
- `replay/s8_clean.log` — 78,949 sent, 0 failed
EOF

echo ""
echo "-- manifest --"
echo "   ✓ MANIFEST.md  (core: $CORE_VER)"

chmod -R a-w "$DEST" 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  ✅ SCENARIO 8 ARCHIVED (read-only)"
echo "=========================================================="
du -sh "$DEST"
find "$DEST" -type f | sed "s|$DEST|  .|"
echo ""
echo "  Series:"
echo "    s1 v3.7 : ~/research/results/baseline_*"
echo "    s1 v4.0 : ~/research/results/v4_rate_independent_*"
echo "    s9 v4.1 : ~/research/results/s9_v41_*"
echo "    s8 v4.1 : $DEST   <-- first positive C2 result"
echo "=========================================================="
