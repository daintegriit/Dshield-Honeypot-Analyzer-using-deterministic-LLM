#!/usr/bin/env bash
#
# archive_baseline.sh
# ---------------------------------------------------------------------------
# Freeze the CTU-13 baseline evaluation ("BEFORE" state) with full provenance,
# so it can be compared against results after the detector is redesigned.
#
# WHY: the moment copilotCore.js is modified, these numbers cannot be
# regenerated without reverting the code AND re-running a 33-minute replay.
# They are the control condition for the entire before/after result.
#
# Usage:  bash archive_baseline.sh
#
set -euo pipefail

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/research/results/baseline_${STAMP}"

echo "=========================================================="
echo "  ARCHIVING CTU-13 BASELINE (pre-fix control condition)"
echo "=========================================================="
echo "  destination: $DEST"

mkdir -p "$DEST/eval"
mkdir -p "$DEST/code_snapshot"
mkdir -p "$DEST/replay"

# ---- 1. Evaluation results (the numbers) ----
echo ""
echo "-- evaluation JSON --"
for f in "$HOME"/backend/ctu13_eval_ctu13-s1_*.json \
         "$HOME"/backend/eval_s1_w5.json \
         "$HOME"/backend/eval_s1_w15.json; do
  if [ -f "$f" ]; then
    cp "$f" "$DEST/eval/"
    echo "   ✓ $(basename "$f")  ($(du -h "$f" | cut -f1))"
  fi
done

# ---- 2. Code snapshot (what produced the numbers) ----
# Without this the results are unreproducible: the scoring constants ARE the
# experiment.
echo ""
echo "-- code snapshot --"
for f in "$HOME/backend/services/copilotCore.js" \
         "$HOME/backend/routes/ingestRoutes.js" \
         "$HOME/backend/models/AttackModel.js" \
         "$HOME/backend/analyze_ctu13.js" \
         "$HOME/research/scripts/replay_ctu13.py"; do
  if [ -f "$f" ]; then
    cp "$f" "$DEST/code_snapshot/"
    echo "   ✓ $(basename "$f")"
  fi
done

# ---- 3. Replay log (proof of how the data got there) ----
echo ""
echo "-- replay log --"
if [ -f "$HOME/research/scripts/ctu13_s1_run.log" ]; then
  cp "$HOME/research/scripts/ctu13_s1_run.log" "$DEST/replay/"
  echo "   ✓ ctu13_s1_run.log"
fi

# ---- 4. Provenance manifest ----
CORE_VER=$(grep -o 'copilotCore-v[0-9.]*' "$HOME/backend/services/copilotCore.js" | head -1 || echo "unknown")

cat > "$DEST/MANIFEST.md" << EOF
# CTU-13 Baseline Evaluation — Control Condition

**Archived:** ${STAMP}
**Core version at time of run:** \`${CORE_VER}\`

## What this is

The measured performance of the Chiron deterministic detector against CTU-13
hand-labeled ground truth, **before** any redesign. This is the control
condition for the before/after comparison.

## Dataset

- **Source:** CTU-13 (Stratosphere Lab, CVUT Prague), scenario 1 (Neris botnet)
- **Capture:** 2011-08-10, 09:46:59 – 15:54:07 (6h07m of real traffic)
- **Replayed:** 71,348 labeled flows (Background excluded), 0 failed
- **Replay duration:** 33.0 min wall clock (~4x temporal compression)
- **Effective rate:** 36.08 events/sec (constant)

### Ground truth composition (per-flow, hand-labeled by Stratosphere)

| class    | count  |
|----------|--------|
| normal   | 30,387 |
| dns      | 29,197 |
| spam     |  8,167 |
| other    |  2,427 |
| ad       |    811 |
| c2       |    341 |
| download |     16 |
| icmp     |      2 |

Botnet total: 40,961 · Normal total: 30,387 (≈57/43 split)

## Method

Each evaluation window was scored by the **production** \`buildCopilotCore()\`
via its \`windowEnd\` parameter — no reimplementation, no divergence between
what was measured and what runs live. Ground truth per window was computed from
the \`ctu_class\` / \`ctu_subclass\` fields carried on every ingested document.

Truth definition: a window is *malicious* iff botnet_fraction >= 0.5 of its
labeled flows. Background flows are excluded from truth (CTU treats them as
unlabeled/uncertain).

## Headline results

| window | malicious mean risk | benign mean risk | separation margin | ρ(risk, botnet_frac) | FPR | balanced acc |
|--------|--------------------|------------------|-------------------|----------------------|-----|--------------|
|  1 min | 86.37              | 85.00            | **+1.37**         | +0.080               | 1.0 | 0.50         |
|  5 min | 86.72              | 89.00            | **−2.28**         | −0.212               | 1.0 | 0.50         |
| 15 min | 84.78              | 85.00            | **−0.22**         | −0.205               | 1.0 | 0.50         |

**The detector does not discriminate.** Balanced accuracy = 0.50 (chance) at
every window size. FPR = 1.0: it fired on every single window, producing zero
true negatives. At 5 and 15 minutes the separation margin is *negative* — benign
windows scored marginally higher than malicious ones.

### Why (mechanism)

\`volumeComponent\` saturates at its cap (60/100) in every window because the
replay sends at a constant ~36 eps:

\`\`\`
volumeAbs = clamp(max(attacksLast1Min * 2, attacksLast5Min / 2), 0, 60) = 60
\`\`\`

\`dosScore = min(60, log10(n+1)*20)\` likewise saturates, so it wins \`pickTop()\`
in 100% of windows (\`dominantAttack = "dos"\` always). The risk score is
therefore a near-constant that measures **the replay's send rate**, not the
traffic's character.

### The one component that worked

| window | mean c2score when C&C present | when absent | n(absent) |
|--------|-------------------------------|-------------|-----------|
|  1 min | 9.81                          | **0.00**    | 6         |
|  5 min | 16.03                         | n/a         | 0         |
| 15 min | 7.89                          | n/a         | 0         |

At 1-minute resolution the C2 component **never fired falsely** across 6
C&C-free windows. It is the only scorer built on rate-independent features
(\`dominantFlowRatio\`, \`periodicityCv\`, \`portDiversity\`) — ratios and shapes
rather than counts. Signal peaks at 5 min and decays by 15 min, consistent with
periodicity evidence diluting in over-wide windows.

### Metric artifact worth noting

The threshold sweep reports F1 up to **1.000** at low truth thresholds. This is
an artifact: when nearly every window is labeled malicious, a
constant-"Attack" detector achieves perfect recall and near-perfect precision.
**High F1 with FPR = 1.0 and TN = 0 is the signature of a detector that always
says yes.** Any evaluation reporting only F1/precision/recall would have scored
this detector as excellent.

## Implications for the redesign

1. Remove volume from the risk score, or normalize it against a learned
   baseline rate. It is a load metric, not a threat metric.
2. Exclude \`impact\` from \`pickTop()\` — a severity aggregate should not compete
   in a behavioural type classifier.
3. Rebuild scoring on rate-independent, distributional features (entropy,
   flow concentration, periodicity, peer fan-out, byte-size distribution).
4. Re-run this exact evaluation and compare against this archive.

## Files

- \`eval/\` — full per-window records, threshold sweeps, correlations
- \`code_snapshot/\` — the exact scoring code that produced these numbers
- \`replay/\` — the replay log proving how the data was ingested

## Reproduce

\`\`\`bash
# restore the snapshot scoring code, then:
python3 replay_ctu13.py --scenario 1
node analyze_ctu13.js --pcap ctu13-s1 --window 1
node analyze_ctu13.js --pcap ctu13-s1 --window 5
node analyze_ctu13.js --pcap ctu13-s1 --window 15
\`\`\`
EOF

echo ""
echo "-- manifest --"
echo "   ✓ MANIFEST.md"

# ---- 5. Lock it ----
chmod -R a-w "$DEST" 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  ✅ BASELINE ARCHIVED (read-only)"
echo "=========================================================="
du -sh "$DEST"
find "$DEST" -type f | sed "s|$DEST|  .|"
echo ""
echo "  This is your control condition. Do NOT modify."
echo "  After redesigning the detector, re-run the same"
echo "  evaluation and compare against these numbers."
echo "=========================================================="
