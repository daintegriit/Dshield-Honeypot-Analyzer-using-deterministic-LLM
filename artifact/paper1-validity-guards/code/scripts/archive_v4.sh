#!/usr/bin/env bash
#
# archive_v4.sh
# ---------------------------------------------------------------------------
# Freeze the v4.0 (rate-independent) evaluation — the "AFTER" condition — with
# full provenance, alongside a direct comparison to the archived v3.7 baseline.
#
# The two archives together constitute a controlled experiment:
#   same data (deterministic replay, 71,348 flows, 0 failed, both runs)
#   same method (identical analyzer, identical window sizes)
#   one variable changed (copilotCore v3.7 -> v4.0)
#
set -euo pipefail

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/research/results/v4_rate_independent_${STAMP}"

echo "=========================================================="
echo "  ARCHIVING v4.0 RATE-INDEPENDENT RESULTS (after condition)"
echo "=========================================================="
echo "  destination: $DEST"

mkdir -p "$DEST/eval" "$DEST/code_snapshot" "$DEST/replay"

echo ""
echo "-- evaluation JSON --"
for f in "$HOME"/backend/eval_v4_w1.json \
         "$HOME"/backend/eval_v4_w5.json \
         "$HOME"/backend/eval_v4_w15.json; do
  if [ -f "$f" ]; then
    cp "$f" "$DEST/eval/"
    echo "   ✓ $(basename "$f")  ($(du -h "$f" | cut -f1))"
  fi
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
if [ -f "$HOME/research/scripts/ctu13_s1_run_v4.log" ]; then
  cp "$HOME/research/scripts/ctu13_s1_run_v4.log" "$DEST/replay/"
  echo "   ✓ ctu13_s1_run_v4.log"
fi

CORE_VER=$(grep -o 'copilotCore-v[0-9A-Za-z.-]*' "$HOME/backend/services/copilotCore.js" | head -1 || echo unknown)

cat > "$DEST/MANIFEST.md" << 'EOF'
# v4.0 Rate-Independent Detector — "AFTER" Condition

Paired with: `../baseline_20260715T041836Z/` (the v3.7 "BEFORE" condition).

## The experiment

| | value |
|---|---|
| Dataset | CTU-13 scenario 1 (Neris), 71,348 hand-labeled flows |
| Replay (baseline) | 71,348 sent, 0 failed, 33.0 min, 36.08 eps |
| Replay (v4.0)     | 71,348 sent, 0 failed, 33.0 min, 36.01 eps |
| Method | identical analyzer, identical windows (1/5/15 min) |
| Variable changed | copilotCore v3.7 → v4.0 only |

The replay converter is deterministic (Background excluded, no sampling), so
both runs ingested byte-identical input. This is a controlled comparison.

## What v4.0 changed (and why)

1. **Volume removed from risk.** `volumeAbs = clamp(max(n1m*2, n5m/2), 0, 60)`
   saturated at its cap for any `attacksLast1Min >= 30`, making the score a
   near-constant that measured event *rate*, not threat.
2. **Counts → ratios.** `severityComponent` became `criticalRatio*25`;
   `behaviorComponent` became `authRatio*20`.
3. **Previously-unused signals wired in.** `portEntropy` and `sourceEntropy`
   were computed since v3.x and never entered the risk score. Added as
   `entropyComponent` (normalised by `log2(10)`) and `concentrationComponent`
   (inverted, normalised by `log2(50)`).
4. **`impact` excluded from the type vote.** It is a severity aggregate, not a
   behaviour; it should not be eligible as "dominant attack type".
5. **`couplingBonus` retargeted** — it previously required `volumeComponent>45`,
   which was always true, so it fired on behaviour alone.

Weights were derived from each feature's theoretical range (entropy ceilings
are `log2(k)`; ratios are already 0..1), **not fitted to the evaluation set**.

## Results: BEFORE vs AFTER

### Separation margin (mean risk on malicious windows − benign windows)

| window | v3.7 | v4.0 |
|--------|------|------|
| 1 min  | +1.37 | **−0.25** |
| 5 min  | −2.28 | **−6.80** |
| 15 min | −0.22 | **−0.68** |

### Correlation ρ(riskScore, botnet_fraction)

| window | v3.7 | v4.0 |
|--------|------|------|
| 1 min  | +0.080 | **−0.059** |
| 5 min  | −0.212 | **−0.419** |
| 15 min | −0.205 | **−0.336** |

### Deployed operating point (state ∈ {high,critical}, truth thr 0.5)

| window | version | TP | FP | TN | FN | FPR | recall | bal. acc |
|--------|---------|----|----|----|----|-----|--------|----------|
| 1 min  | v3.7 | 19 | 14 | **0** | 0  | 1.000 | 1.000 | 0.500 |
| 1 min  | v4.0 | 1  | 1  | **14** | 18 | 0.067 | 0.053 | 0.493 |
| 5 min  | v3.7 | 18 | 11 | **0** | 0  | 1.000 | 1.000 | 0.500 |
| 5 min  | v4.0 | 3  | 4  | **7**  | 16 | 0.364 | 0.158 | **0.397** |
| 15 min | v3.7 | 18 | 1  | **0** | 0  | 1.000 | 1.000 | 0.500 |
| 15 min | v4.0 | 1  | 0  | **1**  | 18 | 0.000 | 0.053 | 0.526 |

### Risk score behaviour

- **v3.7:** `risk = 85` in *every* window at *every* window size. A constant.
- **v4.0:** varies (38–63 observed). The saturation is genuinely gone.

## Findings

**1. The mechanical fix worked.** The score is no longer constant, and the
detector gained the ability to *not* fire: true negatives went from **0 → 14**
(1 min), FPR from **1.000 → 0.067**. v3.7 was structurally incapable of saying
"this is normal".

**2. It did not improve discrimination.** Balanced accuracy stayed at chance
(0.493 / 0.397 / 0.526 vs 0.500 across the board). The failure mode simply
*inverted*: v3.7 had FN=0/FP=14 (fires on everything); v4.0 has FN=18/FP=1
(fires on almost nothing). Recall collapsed 1.000 → 0.053. No information was
added — the operating threshold moved.

**3. The new features are ANTI-correlated with ground truth.** At 5 min,
ρ = **−0.42** and benign windows score *higher* than malicious ones
(52.91 vs 46.11), giving balanced accuracy **0.397 — below chance**.

### Mechanism

71% of Neris's traffic is DNS (29,197 of 40,961 botnet flows) directed at the
CVUT resolver. Normal CVUT users also issue DNS to the same resolver. At flow
level these are near-identical: same destination port, same protocol, similar
peer structure, similar flow sizes.

`concentrationComponent` inverted `sourceEntropy` on the hypothesis that
*focused peers ⇒ targeted behaviour*. The data falsified it: the botnet's
one-host-to-one-resolver DNS looks concentrated, while normal users browsing
the wider internet look diffuse — so the feature systematically scored normal
browsing *above* botnet activity.

**Conclusion:** flow-level port/peer statistics cannot separate DNS-based
botnet traffic from normal traffic, because the discriminating information is
not present in the retained fields (`SRC/DST/SPT/DPT/PROTO/BYTES`).
Discrimination requires protocol semantics — DNS query-name entropy (DGA
signature), NXDOMAIN ratio, distinct-names-per-second — which the parser
currently discards at ingest.

### The one component that tracks ground truth

`c2Score` remains the only scorer that responds to labels rather than rate:

| window | mean c2score, C&C present | C&C absent | n(absent) |
|--------|---------------------------|------------|-----------|
| 1 min  | 9.81  | **0.00** | 7 |
| 5 min  | 16.83 | n/a      | 0 |
| 15 min | 10.75 | n/a      | 0 |

Zero false fires across all C&C-free windows. It is built on ratios and shapes
(`dominantFlowRatio`, `periodicityCv`, `portDiversity`) rather than counts.
Correlation remains weak (ρ ≈ 0.14 at 1 min) and it never becomes the dominant
class — see the known issue below.

## Known issues (carried forward)

1. **`dosScore` still saturates.** Volume was removed from the risk *sum* but
   not from the type *classifier*: `dosScore = min(60, log10(n5m+1)*20) + ...`
   still wins `pickTop()` in 100% of windows, so `dominantAttack = "dos"`
   everywhere and the attack-type table is uninformative. Fix before running
   further scenarios.
2. **Metric artifact.** The threshold sweep reports F1 up to 1.000 at low truth
   thresholds *while FPR = 1.000 and TN = 0*. High F1 with FPR=1 is the
   signature of a constant-"Attack" detector. Any evaluation reporting only
   P/R/F1 would score this detector as excellent.
3. Single scenario, single family. Neris is DNS/spam-dominant; these findings
   may not generalise. Scenarios 9 (2,973 C&C), 8 (72,821 normal) and 13
   (balanced) are the natural next characterisations.

## Files

- `eval/` — full per-window records incl. `rateIndependentFeatures` diagnostics
- `code_snapshot/` — the exact v4.0 scoring code that produced these numbers
- `replay/` — replay log (71,348 sent, 0 failed)
EOF

echo ""
echo "-- manifest --"
echo "   ✓ MANIFEST.md  (core version at run time: $CORE_VER)"

chmod -R a-w "$DEST" 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  ✅ v4.0 ARCHIVED (read-only)"
echo "=========================================================="
du -sh "$DEST"
find "$DEST" -type f | sed "s|$DEST|  .|"
echo ""
echo "  Controlled pair:"
echo "    BEFORE : ~/research/results/baseline_*"
echo "    AFTER  : $DEST"
echo "=========================================================="
