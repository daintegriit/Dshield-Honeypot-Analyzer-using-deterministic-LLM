#!/usr/bin/env bash
#
# archive_s9.sh
# ---------------------------------------------------------------------------
# Freeze the CTU-13 scenario 9 evaluation under copilotCore v4.1.
#
# This is the REPLICATION: a second malware family, 9x more labeled C&C flows,
# and the dosScore saturation fix. It tests whether the scenario-1 findings
# hold, and whether the C2 detector works when given enough C&C to measure.
#
set -euo pipefail

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/research/results/s9_v41_${STAMP}"

echo "=========================================================="
echo "  ARCHIVING CTU-13 SCENARIO 9 (v4.1) — replication + C2 test"
echo "=========================================================="
echo "  destination: $DEST"

mkdir -p "$DEST/eval" "$DEST/code_snapshot" "$DEST/replay"

echo ""
echo "-- evaluation JSON --"
for f in "$HOME"/backend/eval_s9_v41_w1.json \
         "$HOME"/backend/eval_s9_v41_w5.json \
         "$HOME"/backend/eval_s9_v41_w15.json; do
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
[ -f "$HOME/research/scripts/s9_clean.log" ] && \
  cp "$HOME/research/scripts/s9_clean.log" "$DEST/replay/" && echo "   ✓ s9_clean.log"

CORE_VER=$(grep -o 'copilotCore-v[0-9A-Za-z.-]*' "$HOME/backend/services/copilotCore.js" | head -1 || echo unknown)

cat > "$DEST/MANIFEST.md" << 'EOF'
# CTU-13 Scenario 9 (v4.1) — Replication + C2 Test

Companion to:
- `../baseline_20260715T041836Z/` — scenario 1, copilotCore v3.7
- `../v4_rate_independent_20260715T071429Z/` — scenario 1, copilotCore v4.0

## Why this run

Scenario 1 left two questions open:

1. **Do the findings replicate?** One scenario, one family (Neris, DNS/spam
   dominant) is not a result.
2. **Does the C2 detector work?** Scenario 1 had only 341 labeled C&C flows and
   a saturated `dosScore` that won 100% of type votes, so `c2` could never be
   dominant. The apparent C2 signal (9.81 present vs 0.00 absent) rested on
   6-7 clean windows.

Scenario 9 provides **2,973 labeled C&C flows (9x scenario 1)** and runs under
**v4.1**, which makes `dosScore` rate-independent so other classes can compete.

**Caveat — two variables changed at once:** malware family AND the dosScore fix.
Attributing any difference to one or the other requires re-running scenario 1
under v4.1.

## Data

- CTU-13 scenario 9, replayed 214,954 labeled flows, **0 failed**, 99.6 min, 35.98 eps
- Class balance: **86% botnet / 14% normal** (vs 57/43 in scenario 1)

| ctu_subclass | count   |
|--------------|---------|
| dns          | 107,786 |
| spam         |  42,121 |
| normal       |  29,967 |
| other        |  25,724 |
| ad           |   6,218 |
| **c2**       | **2,973** |
| download     |     150 |
| icmp         |      15 |

## Result 1 — the dosScore fix worked; the type vote unblocked

Scenario 1 (v3.7 and v4.0) produced a single-column attack-type table: `dos`
won **100%** of windows at every window size, because
`min(60, log10(n5m+1)*20)` saturates at ~1,000 events.

Scenario 9 under v4.1 (1-min windows):

```
         │ dos │ scan │
  normal │  7  │      │
  dns    │  1  │  92  │
```

`scan` wins **92 of 93 malicious windows**; `dos` takes **7 of 7 benign** ones.
The type vote now discriminates. At 15 min the table collapses to `scan` only
(82 botnet / 4 normal).

**Honest reading:** the detector says `scan` where the truth label is `dns`. It
*correlates* with maliciousness but does not *identify* the behaviour. Neris's
DNS flooding across many resolvers is arguably scan-like, so the mislabel is
defensible — but it is a mislabel.

## Result 2 — the C2 signal did NOT replicate

| metric | scenario 1 (341 C&C) | scenario 9 (2,973 C&C) |
|---|---|---|
| mean c2score, C&C present  | 9.81 | **2.45** (1m) / 7.82 (5m) / 14.24 (15m) |
| mean c2score, C&C absent   | **0.00** | **9.17** (1m) / 10.00 (5m) / n/a (15m) |
| ρ(c2score, c2_flows)       | +0.136 | **−0.030** (1m) / +0.114 (5m) / +0.332 (15m) |
| c2_dominant_when_present   | 0 | **0** |

**At 1-minute resolution the C2 score is LOWER when C&C is present (2.45) than
when it is absent (9.17), with ρ = −0.03.** With nine times more labeled C&C
data, the scenario-1 signal inverted.

Conclusion: the scenario-1 C2 result (9.81 vs 0.00, "zero false fires") was
**noise on 6-7 clean windows**, not a detector that works. It did not survive
replication. `c2` was never the dominant class in any window of either scenario.

The only positive C2 correlation appears at 15 min (ρ = +0.33) — but there are
**zero** C&C-free windows at that resolution, so there is no contrast class and
the number cannot be interpreted as detection.

## Result 3 — the detector never fires at all

| window | TP | FP | TN | FN | recall | specificity | bal. acc |
|--------|----|----|----|----|--------|-------------|----------|
| 1 min  | 0 | 0 | 7 | 93 | 0.000 | 1.000 | **0.500** |
| 5 min  | 0 | 0 | 6 | 90 | 0.000 | 1.000 | **0.500** |
| 15 min | 0 | 0 | 1 | 85 | 0.000 | 1.000 | **0.500** |

Zero `high`/`critical` states across **282 windows**. Risk sits at 25–36
throughout. Perfect specificity, zero recall — the mirror image of v3.7's
perfect recall, zero specificity.

### The arc across three detector versions

| version | behaviour | FPR | recall | bal. acc |
|---------|-----------|-----|--------|----------|
| v3.7 | fires on everything | 1.000 | 1.000 | 0.50 |
| v4.0 | fires rarely | 0.067 | 0.053 | 0.49 |
| v4.1 | **never fires** | 0.000 | 0.000 | 0.50 |

Each change moved the operating threshold. **None added information.** Balanced
accuracy is pinned at chance across two malware families, three detector
versions, six window configurations, and 286,302 labeled flows.

## Result 4 — risk separation remains at noise

| window | malicious mean | benign mean | margin | ρ(risk, botnet_frac) |
|--------|----------------|-------------|--------|----------------------|
| 1 min  | 28.78 | 34.71 | **−5.93** | **−0.301** |
| 5 min  | 30.24 | 27.33 | +2.91 | +0.133 |
| 15 min | 31.75 | 27.00 | +4.75 | +0.093 |

Sign flips with window size. At 1 min the margin is *negative* and ρ = −0.30 —
benign windows score higher than malicious. Note `benign_n` is 7 / 6 / **1**:
scenario 9 is 86% botnet, so there is very little benign contrast. **Scenario 8
(72,821 normal flows) is required for a meaningful FPR claim.**

## Metric artifact — reconfirmed

The sweep again reports **F1 = 1.000 with FPR = 1.000** at low truth thresholds
(and F1 = 0.994 at truth ≥ 0.5, 15 min). Meanwhile the deployed operating point
has **recall = 0.000**. The same detector scores "perfect" and "useless"
depending only on which metric is reported. This is now observed across two
scenarios and three detector versions.

## What this establishes

1. Flow-statistical features (`SRC/DST/SPT/DPT/PROTO/BYTES` aggregates) do not
   separate botnet from normal traffic on CTU-13 scenarios 1 or 9.
2. The apparent C2 signal in scenario 1 was noise; it inverted under replication
   with 9x the data.
3. Fixing saturation makes the type classifier discriminate (`scan` on 92/93
   malicious windows) even while the *risk score* remains at chance — the two
   are decoupled.
4. P/R/F1 without FPR/TN is actively misleading on imbalanced window data.

## Next

- **Scenario 8** (6,127 botnet / **72,821 normal**, 1,074 C&C) — the FPR test.
  Scenario 9's `benign_n = 1..7` cannot support a false-positive claim.
- **Scenario 1 under v4.1** — isolates the dosScore fix from the family change.
- **Scenario 13** (40,003 / 31,931, 536 C&C) — balanced control.
- Then: DNS-semantic features (query-name entropy, NXDOMAIN ratio), which
  require extracting `QUERY`/`QTYPE` at parse time. Currently discarded.

## Files

- `eval/` — per-window records incl. `rateIndependentFeatures`
- `code_snapshot/` — the exact v4.1 code that produced these numbers
- `replay/s9_clean.log` — 214,954 sent, 0 failed
EOF

echo ""
echo "-- manifest --"
echo "   ✓ MANIFEST.md  (core: $CORE_VER)"

chmod -R a-w "$DEST" 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  ✅ SCENARIO 9 ARCHIVED (read-only)"
echo "=========================================================="
du -sh "$DEST"
find "$DEST" -type f | sed "s|$DEST|  .|"
echo ""
echo "  Series so far:"
echo "    s1 v3.7  : ~/research/results/baseline_*"
echo "    s1 v4.0  : ~/research/results/v4_rate_independent_*"
echo "    s9 v4.1  : $DEST"
echo "=========================================================="
