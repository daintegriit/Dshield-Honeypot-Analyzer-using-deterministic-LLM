#!/usr/bin/env bash
# Positive control for Paper 1: score CTU-13 on true event time, with the
# detector's lookback scoped to each scenario, then run planted scorers of known
# quality through the same guard audit.
#
# Runs from a COPY of ~/backend. The live backend and its pm2 process are not
# touched. Usage, from the folder this script was unpacked into:
#   bash run_poscontrol.sh            all steps
#   bash run_poscontrol.sh check      steps 0-2 only (no long scoring)
set -u
KIT="$(cd "$(dirname "$0")" && pwd)"
OUT=~/research/results/poscontrol_20261014
BK=$OUT/backend
mkdir -p "$OUT/runs" "$OUT/planted"
LOG="$OUT/run.log"
say() { echo "$@" | tee -a "$LOG"; }

DEP="env -u RISK_NORMALISE -u RISK_PROFILE -u C2_MIN_EVENTS -u C2_MIN_FLOW_COUNT -u C2_MIN_SPAN_SEC -u C2_BONUS_MIN_SCORE -u SCORE_TIME_FIELD -u CORE_SCOPE_PCAP"
ABL="env -u SCORE_TIME_FIELD -u CORE_SCOPE_PCAP RISK_PROFILE=netflow RISK_NORMALISE=1 C2_MIN_EVENTS=0 C2_MIN_FLOW_COUNT=0 C2_MIN_SPAN_SEC=0 C2_BONUS_MIN_SCORE=0"

# ---- 0. build from the FROZEN paper backend, never from the live one ----
SRC=~/research/frozen_paper1_backend_20261008
EXPECT=91f4ad86f28a804482cbc61e8a72b22fbe35160506d64098ba137f67d448bd84
HAVE=$(sha256sum "$SRC/services/copilotCore.js" | cut -d' ' -f1)
say "frozen core sha256=$HAVE expected=$EXPECT"
if [ "$HAVE" != "$EXPECT" ]; then
  say "STOP: the frozen backend's copilotCore.js is not the version the paper evaluated."
  exit 1
fi
if [ ! -d "$BK" ]; then
  cp -a "$SRC" "$BK"
fi
[ -e "$BK/node_modules" ] || ln -s ~/backend/node_modules "$BK/node_modules"
[ -e "$BK/.env" ] || cp ~/backend/.env "$BK/.env"
cp "$KIT/copilotCore.js" "$BK/services/copilotCore.js"
cp "$KIT/analyze_ctu13.js" "$BK/analyze_ctu13.js"
cd "$BK"

# ---- 1. no-op check: patched code with no flags must reproduce v4.3 ----
say "== step 1: patched code, default flags, s2 1-min (expect 0/0/7/48, max 54)"
$DEP node analyze_ctu13.js --pcap ctu13-s2 --window 1 --step 1 --out "$OUT/runs/noop_s2_w1.json" > "$OUT/noop.log" 2>&1
python3 -I - "$OUT/runs/noop_s2_w1.json" <<'EOF' | tee -a "$LOG"
import json,sys
d=json.load(open(sys.argv[1])); o=d['deployed_operating_point']; o=o.get('would_have_been',o) if 'TP' not in o else o
print('noop', '%s/%s/%s/%s'%(o['TP'],o['FP'],o['TN'],o['FN']), 'max', max(w['riskScore'] for w in d['windows']))
EOF

# ---- 2. event_time must exist on the CTU-13 documents ----
say "== step 2: event_time coverage and span per scenario"
cat > "$OUT/evcheck.js" <<'EOF'
require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("./models/AttackModel");
(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  for (const s of [1, 2, 6, 8, 9]) {
    const p = `ctu13-s${s}`;
    const n = await Attack.countDocuments({ replay_pcap: p });
    const e = await Attack.countDocuments({ replay_pcap: p, event_time: { $ne: null } });
    const a = await Attack.findOne({ replay_pcap: p, event_time: { $ne: null } }).sort({ event_time: 1 }).select({ event_time: 1 }).lean();
    const b = await Attack.findOne({ replay_pcap: p, event_time: { $ne: null } }).sort({ event_time: -1 }).select({ event_time: 1 }).lean();
    const span = a && b ? ((b.event_time - a.event_time) / 3600000).toFixed(2) : "n/a";
    console.log(`${p} docs=${n} with_event_time=${e} first=${a && a.event_time.toISOString()} last=${b && b.event_time.toISOString()} span_h=${span}`);
  }
  await mongoose.disconnect();
})();
EOF
cp "$OUT/evcheck.js" "$BK/evcheck.js"
node evcheck.js | tee -a "$LOG"

if [ "${1:-}" = "check" ]; then
  say "check mode: stopping before the long scoring runs."
  exit 0
fi

# ---- 3. the detector on true event time, lookback scoped per scenario ----
say "== step 3: detector, event_time, scoped (deployed and ablated, 1-min and 5-min)"
for s in 1 2 6 8 9; do
  for arm in dep abl; do
    if [ $arm = dep ]; then E="$DEP"; else E="$ABL"; fi
    for w in 1 5; do
      f="$OUT/runs/s${s}_evt_${arm}_w${w}s1.json"
      [ -s "$f" ] && { say "skip existing $f"; continue; }
      say "scoring s$s $arm w$w $(date -u +%H:%M:%S)"
      $E node analyze_ctu13.js --pcap ctu13-s$s --window $w --step 1 --time-field event_time --scope-pcap --out "$f" > "$OUT/runs/s${s}_evt_${arm}_w${w}s1.log" 2>&1
    done
  done
done

# ---- 4. planted scorers on the deployed one-minute windows ----
say "== step 4: planted scorers"
for s in 1 2 6 8 9; do
  python3 -I "$KIT/planted.py" "$OUT/runs/s${s}_evt_dep_w1s1.json" "$OUT/planted"
done

# ---- 5. guard audit and admissible-window summary ----
say "== step 5: guard audit (12 conditions) and summary"
python3 -I ~/research/scripts/guard_audit.py --csv "$OUT"/runs/s*_evt_*.json "$OUT"/planted/*.json > "$OUT/audit.csv"
python3 -I "$KIT/summarize.py" "$OUT"/runs/s*_evt_*.json "$OUT"/planted/*.json > "$OUT/summary.tsv"
cut -d, -f1,5,6 "$OUT/audit.csv" | tee -a "$LOG"
cat "$OUT/summary.tsv" | tee -a "$LOG"
say "done $(date -u)"
