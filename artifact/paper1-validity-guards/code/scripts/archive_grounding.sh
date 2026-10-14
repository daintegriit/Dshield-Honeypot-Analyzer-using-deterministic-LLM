#!/usr/bin/env bash
#
# archive_grounding.sh
# ---------------------------------------------------------------------------
# Freeze a Copilot grounding evaluation with full provenance.
#
#   Usage:  bash archive_grounding.sh [note]
#
# Captures every grounding_*.json in ~/backend, snapshots the prompt/provider/
# checker code that produced them, and generates a manifest with the metrics
# extracted from the JSON (not hand-typed).
#
set -euo pipefail

NOTE="${1:-}"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
DEST="$HOME/research/results/grounding_${STAMP}"

echo "=========================================================="
echo "  ARCHIVING COPILOT GROUNDING EVALUATION"
echo "=========================================================="
echo "  destination: $DEST"
[ -n "$NOTE" ] && echo "  note:        $NOTE"

mkdir -p "$DEST/eval" "$DEST/code_snapshot"

echo ""
echo "-- grounding runs --"
FOUND=0
for f in "$HOME"/backend/grounding_*.json; do
  if [ -f "$f" ]; then
    cp "$f" "$DEST/eval/"
    echo "   ✓ $(basename "$f")  ($(du -h "$f" | cut -f1))"
    FOUND=$((FOUND+1))
  fi
done
if [ "$FOUND" -eq 0 ]; then
  echo "   ✗ no grounding_*.json found in ~/backend"
  rm -rf "$DEST"
  exit 1
fi

echo ""
echo "-- code snapshot --"
# The prompt IS the experiment here — without it the numbers are unreproducible.
for f in "$HOME/backend/services/copilotReasoner.js" \
         "$HOME/backend/services/llmProviders/localOllamaProvider.js" \
         "$HOME/backend/services/behaviorSummary.js" \
         "$HOME/backend/services/copilotCore.js" \
         "$HOME/backend/controllers/copilotController.js" \
         "$HOME/backend/check_grounding.js"; do
  [ -f "$f" ] && cp "$f" "$DEST/code_snapshot/" && echo "   ✓ $(basename "$f")"
done

# LLM config matters as much as the code
if [ -f "$HOME/backend/.env" ]; then
  grep -E "^OLLAMA_" "$HOME/backend/.env" > "$DEST/code_snapshot/ollama.env" 2>/dev/null || true
  echo "   ✓ ollama.env (OLLAMA_* settings only)"
fi

CORE_VER=$(grep -o 'copilotCore-v[0-9A-Za-z.-]*' "$HOME/backend/services/copilotCore.js" | head -1 || echo unknown)

python3 - "$DEST" "$STAMP" "$CORE_VER" "$NOTE" << 'PYEOF'
import json, os, sys, glob

dest, stamp, core_ver, note = sys.argv[1:5]

runs = []
for f in sorted(glob.glob(os.path.join(dest, "eval", "*.json"))):
    d = json.load(open(f))
    t = d.get("totals", {})
    cited = t.get("cited", 0) or 1
    n = d.get("config", {}).get("n", 0)
    runs.append({
        "file": os.path.basename(f),
        "n": n,
        "succeeded": n - t.get("failed", 0),
        "failed": t.get("failed", 0),
        "cited": t.get("cited", 0),
        "nonzero": t.get("nonzero", 0),
        "zero": t.get("zero", 0),
        "prose": t.get("prose", 0),
        "unresolved": t.get("unresolved", 0),
        "malformedButReal": t.get("malformedButReal", 0),
        "grounding": d.get("groundingRate"),
        "fabrication": d.get("fabricationRate"),
        "schema": d.get("schemaCompliance"),
        "gt": d.get("groundTruth", {}),
        "byField": d.get("byField", {}),
        "failures": d.get("failures", []),
    })

def pct(v):
    return "n/a" if v is None else f"{100*v:.1f}%"

L = []
L.append("# Copilot Grounding Evaluation")
L.append("")
L.append(f"**Archived:** {stamp}  ")
L.append(f"**Core version:** `{core_ver}`")
if note:
    L.append(f"**Note:** {note}")
L.append("")
L.append("## What this measures")
L.append("")
L.append("The reasoner asks the model to attach an `evidence` array of FIELD NAMES")
L.append("to each finding. The checker resolves every cited path against the exact")
L.append("`{core, behavior}` situation report that was fed to the model:")
L.append("")
L.append("- **RESOLVED_NONZERO** — field exists and carries a value")
L.append("- **RESOLVED_ZERO** — field exists but is 0/null/empty (cited while contributing nothing)")
L.append("- **PROSE_NOT_FIELD** — a sentence where a field name belongs")
L.append("- **UNRESOLVED** — no such field: the honest fabrication measure")
L.append("")
L.append("Each run scores N generations against an **identical** situation report,")
L.append("so all variation is the model's, not the data's.")
L.append("")

L.append("## Results")
L.append("")
L.append("| run | n | ok | cited | grounding | fabrication | schema | malformed |")
L.append("|---|---|---|---|---|---|---|---|")
for r in runs:
    L.append(
        f"| {r['file']} | {r['n']} | {r['succeeded']}/{r['n']} | {r['cited']} | "
        f"**{pct(r['grounding'])}** | **{pct(r['fabrication'])}** | {pct(r['schema'])} | "
        f"{r['malformedButReal']} |"
    )
L.append("")

if runs and runs[0].get("gt"):
    gt = runs[-1]["gt"]
    L.append("## Ground truth (situation report scored against)")
    L.append("")
    L.append(f"- riskScore: **{gt.get('risk')}**, state: `{gt.get('state')}`")
    L.append("")
    L.append("| riskComponent | value |")
    L.append("|---|---|")
    for k, v in (gt.get("riskComponents") or {}).items():
        flag = "  ← contributes nothing" if v == 0 else ""
        L.append(f"| {k} | {v}{flag} |")
    L.append("")
    L.append("| attackTypeScore | value |")
    L.append("|---|---|")
    for k, v in (gt.get("attackTypeScores") or {}).items():
        L.append(f"| {k} | {v} |")
    L.append("")

# failures across runs
anyfail = [f for r in runs for f in r.get("failures", [])]
if anyfail:
    L.append("## Generation failures")
    L.append("")
    kinds = {}
    for f in anyfail:
        kinds[f.get("kind", "other")] = kinds.get(f.get("kind", "other"), 0) + 1
    for k, v in sorted(kinds.items(), key=lambda x: -x[1]):
        L.append(f"- `{k}`: {v}")
    L.append("")
    for f in anyfail[:6]:
        L.append(f"- gen {f.get('i')}: {f.get('message')}")
        if f.get("parseError"):
            L.append(f"  - `{f['parseError']}`")
    L.append("")

# most-cited fields from the final run
if runs and runs[-1].get("byField"):
    L.append("## Most-cited fields (final run)")
    L.append("")
    L.append("| field | n | resolved | zero | unresolved |")
    L.append("|---|---|---|---|---|")
    for f, s in sorted(runs[-1]["byField"].items(), key=lambda x: -x[1]["n"])[:15]:
        L.append(f"| `{f}` | {s['n']} | {s['nonzero']} | {s['zero']} | {s['unresolved']} |")
    L.append("")

L.append("## Limitations (read before citing any number above)")
L.append("")
L.append("1. **Strict existence, not semantic support.** A citation can resolve to a")
L.append("   real non-zero value that does not support the claim. Observed:")
L.append("   `burstRatio5mOverHour = 0.083` cited as evidence of high-volume activity —")
L.append("   but 0.083 is exactly the uniform-traffic baseline (5min/60min), i.e. the")
L.append("   value meaning NO burst occurred. This passes the check and should not.")
L.append("   **Semantic grounding is unmeasured.**")
L.append("")
L.append("2. **Single situation report.** Every generation scores the same input.")
L.append("   This isolates model variance but says nothing about behaviour across")
L.append("   different traffic conditions.")
L.append("")
L.append("3. **Constrained decoding changes output character.** Enabling")
L.append("   `format: \"json\"` eliminated malformed-JSON failures but also reduced")
L.append("   citation count and field diversity — output became more formulaic.")
L.append("   Improved numbers and narrower behaviour are the same change.")
L.append("")
L.append("4. **One model, one temperature.** llama3.1:8b at the configured settings.")
L.append("   No claim about other models is supported.")
L.append("")
L.append("## Files")
L.append("")
L.append("- `eval/` — per-citation records for every generation")
L.append("- `code_snapshot/` — the prompt, provider, checker and core that produced these")
L.append("- `code_snapshot/ollama.env` — model and decoding settings")

open(os.path.join(dest, "MANIFEST.md"), "w").write("\n".join(L) + "\n")
print("   ✓ MANIFEST.md")
PYEOF

chmod -R a-w "$DEST" 2>/dev/null || true

echo ""
echo "=========================================================="
echo "  ✅ GROUNDING EVALUATION ARCHIVED (read-only)"
echo "=========================================================="
du -sh "$DEST"
echo ""
echo "  All archives:"
ls -1d "$HOME"/research/results/*/ 2>/dev/null | sed 's|.*/results/|    |'
echo "=========================================================="
