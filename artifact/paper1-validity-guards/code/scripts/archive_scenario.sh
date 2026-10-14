#!/usr/bin/env bash
#
# archive_scenario.sh
# ---------------------------------------------------------------------------
# Generic archiver for a CTU-13 scenario evaluation.
#
#   Usage:  bash archive_scenario.sh <scenario_number> [note]
#   e.g.    bash archive_scenario.sh 2
#           bash archive_scenario.sh 6 "slowed replay, 10 eps"
#
# Freezes, read-only, with full provenance:
#   - the eval JSONs for that scenario
#   - a snapshot of the exact scoring code that produced them
#   - the replay log
#   - a manifest with the headline numbers extracted from the JSON
#
# Expects files named:
#   ~/backend/eval_s<N>_v41_w{1,5,15}.json     (from analyze_ctu13.js --out ...)
#   ~/research/scripts/s<N>_clean.log          (from the replay)
#
set -euo pipefail

if [ $# -lt 1 ]; then
  echo "usage: bash archive_scenario.sh <scenario_number> [note]"
  exit 1
fi

S="$1"
NOTE="${2:-}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/research/results/s${S}_v42_${STAMP}"

echo "=========================================================="
echo "  ARCHIVING CTU-13 SCENARIO ${S}"
echo "=========================================================="
echo "  destination: $DEST"
[ -n "$NOTE" ] && echo "  note:        $NOTE"

mkdir -p "$DEST/eval" "$DEST/code_snapshot" "$DEST/replay"

# ---- eval JSONs ----
echo ""
echo "-- evaluation JSON --"
FOUND=0
for f in "$HOME"/backend/eval_s${S}_v42_w*.json; do
  if [ -f "$f" ]; then
    cp "$f" "$DEST/eval/"
    echo "   ✓ $(basename "$f")  ($(du -h "$f" | cut -f1))"
    FOUND=$((FOUND+1))
  fi
done
if [ "$FOUND" -eq 0 ]; then
  echo "   ✗ no eval_s${S}_v42_w*.json found in ~/backend — nothing to archive"
  rm -rf "$DEST"
  exit 1
fi

# ---- code snapshot ----
echo ""
echo "-- code snapshot --"
for f in "$HOME/backend/services/copilotCore.js" \
         "$HOME/backend/routes/ingestRoutes.js" \
         "$HOME/backend/models/AttackModel.js" \
         "$HOME/backend/analyze_ctu13.js" \
         "$HOME/research/scripts/replay_ctu13.py"; do
  [ -f "$f" ] && cp "$f" "$DEST/code_snapshot/" && echo "   ✓ $(basename "$f")"
done

# ---- replay log ----
echo ""
echo "-- replay log --"
for lg in "$HOME/research/scripts/s${S}_clean.log" "$HOME/research/scripts/s${S}.log"; do
  [ -f "$lg" ] && cp "$lg" "$DEST/replay/" && echo "   ✓ $(basename "$lg")" && break
done

CORE_VER=$(grep -o 'copilotCore-v[0-9A-Za-z.-]*' "$HOME/backend/services/copilotCore.js" | head -1 || echo unknown)

# ---- manifest: pull the real numbers out of the JSONs ----
python3 - "$DEST" "$S" "$STAMP" "$CORE_VER" "$NOTE" << 'PYEOF'
import json, os, sys, glob

dest, scen, stamp, core_ver, note = sys.argv[1:6]

rows = []
census = {}
span = None
for f in sorted(glob.glob(os.path.join(dest, "eval", "*.json"))):
    d = json.load(open(f))
    w = d["config"]["window_minutes"]
    census = d.get("subclass_census", census) or census
    span = d.get("ingest_span", span)
    sep = d.get("separation", {})
    cor = d.get("correlation", {})
    dep = d.get("deployed_operating_point", {})
    c2 = d.get("c2_evaluation", {})
    rows.append({
        "window": w,
        "n_windows": d.get("windows_scored"),
        "mal_n": sep.get("malicious_n"),
        "ben_n": sep.get("benign_n"),
        "margin": sep.get("separation_margin"),
        "rho_risk": cor.get("risk_vs_botnet_fraction"),
        "rho_c2": cor.get("c2score_vs_c2_flows"),
        "c2_present": c2.get("mean_c2score_when_c2_present"),
        "c2_absent": c2.get("mean_c2score_when_absent"),
        "c2_dom": c2.get("c2_dominant_when_present"),
        "TP": dep.get("TP"), "FP": dep.get("FP"),
        "TN": dep.get("TN"), "FN": dep.get("FN"),
        "fpr": dep.get("fpr"), "recall": dep.get("recall"),
        "bal": dep.get("balanced_accuracy"),
    })
rows.sort(key=lambda r: r["window"])

bot = sum(v for k, v in census.items() if k not in ("normal", "background", None))
c2n = census.get("c2", 0)
density = (100.0 * c2n / bot) if bot else 0.0
dns = census.get("dns", 0)

def fmt(v, nd=3):
    if v is None: return "n/a"
    if isinstance(v, float): return f"{v:.{nd}f}"
    return str(v)

L = []
L.append(f"# CTU-13 Scenario {scen} — Evaluation Archive")
L.append("")
L.append(f"**Archived:** {stamp}  ")
L.append(f"**Core version:** `{core_ver}`")
if note:
    L.append(f"**Note:** {note}")
L.append("")
if span:
    L.append(f"**Ingest span:** {span['from']} → {span['to']}  ({span['minutes']} min)")
    L.append("")

L.append("## Ground truth census")
L.append("")
L.append("| ctu_subclass | count |")
L.append("|---|---|")
for k, v in sorted(census.items(), key=lambda x: -x[1]):
    L.append(f"| {k} | {v:,} |")
L.append("")
L.append(f"- botnet total: **{bot:,}**")
L.append(f"- C&C flows: **{c2n:,}**")
L.append(f"- **C&C density: {density:.1f}%** of botnet traffic")
L.append(f"- DNS flows: {dns:,}")
L.append("")

L.append("## Results by window size")
L.append("")
L.append("| window | n | mal | ben | margin | ρ(risk,bot) | ρ(c2,c2flows) | c2 present | c2 absent | c2 dom |")
L.append("|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    L.append(
        f"| {r['window']} min | {r['n_windows']} | {r['mal_n']} | {r['ben_n']} | "
        f"{fmt(r['margin'],2)} | {fmt(r['rho_risk'])} | **{fmt(r['rho_c2'])}** | "
        f"{fmt(r['c2_present'],2)} | {fmt(r['c2_absent'],2)} | {r['c2_dom']} |"
    )
L.append("")

L.append("## Deployed operating point (state ∈ {high,critical}, truth ≥ 0.5)")
L.append("")
L.append("| window | TP | FP | TN | FN | FPR | recall | bal. acc |")
L.append("|---|---|---|---|---|---|---|---|")
for r in rows:
    L.append(
        f"| {r['window']} min | {r['TP']} | {r['FP']} | {r['TN']} | {r['FN']} | "
        f"{fmt(r['fpr'])} | {fmt(r['recall'])} | {fmt(r['bal'])} |"
    )
L.append("")

# validity guard
L.append("## Validity notes")
L.append("")
warned = False
if span:
    smin = span["minutes"]
    for r in rows:
        if r["window"] * 3 > smin:
            L.append(
                f"- ⚠️ **{r['window']}-min windows are NOT valid here**: the replay span is only "
                f"{smin:.1f} min, giving {r['n_windows']} window(s). A window size should be "
                f"≤ 1/3 of the replay span. Metrics at this window size are degenerate and "
                f"must not be reported."
            )
            warned = True
for r in rows:
    if r["ben_n"] == 0:
        L.append(
            f"- ⚠️ {r['window']}-min: **benign_n = 0** — the truth rule "
            f"(botnet_fraction ≥ 0.5) labels every window malicious. Separation margin and "
            f"FPR are undefined/uninformative at this window size."
        )
        warned = True
    elif r["mal_n"] == 0:
        L.append(
            f"- ⚠️ {r['window']}-min: **malicious_n = 0** — the botnet never reaches 50% of a "
            f"window. Binary metrics are degenerate; the correlation is the usable result."
        )
        warned = True
if not warned:
    L.append("- No degeneracy detected at the reported window sizes.")
L.append("")
L.append("- The threshold sweep reports F1 ≈ 1.0 at low truth thresholds **while FPR = 1.0**.")
L.append("  That is the signature of a constant-\"Attack\" detector, not performance.")
L.append("  Always read FPR and TN alongside P/R/F1.")
L.append("")

L.append("## Files")
L.append("")
L.append("- `eval/` — per-window records, threshold sweeps, correlations")
L.append("- `code_snapshot/` — the exact scoring code that produced these numbers")
L.append("- `replay/` — replay log")

open(os.path.join(dest, "MANIFEST.md"), "w").write("\n".join(L) + "\n")
print("   ✓ MANIFEST.md")
PYEOF

chmod -R a-w "$DEST" 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  ✅ SCENARIO ${S} ARCHIVED (read-only)"
echo "=========================================================="
du -sh "$DEST"
echo ""
echo "  All archives:"
ls -1d "$HOME"/research/results/*/ 2>/dev/null | sed 's|.*/results/|    |'
echo "=========================================================="
