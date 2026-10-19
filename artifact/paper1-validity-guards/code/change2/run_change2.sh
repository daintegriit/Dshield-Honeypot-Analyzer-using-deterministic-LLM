#!/usr/bin/env bash
# Paper 2, Change 2: DoS burst expectation against available history.
# Builds from the FROZEN paper backend (never the live one), applies the
# positive-control core plus the Change 2 flag, and runs:
#   control  flag unset, deployed and ablated, 1-min, s1 s2 s6 s8 s9 (must equal the positive control)
#   change2  flag set,   deployed and ablated, 1- and 5-min, s1 s2 s6 s8 s9
# Long: run under nohup. Usage: nohup bash run_change2.sh > ~/change2.log 2>&1 &
set -uo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
OUT=~/research/results/change2_20261019
BK=$OUT/backend
mkdir -p "$OUT/runs"
say() { echo "$(date -u +%H:%M:%S) $*" | tee -a "$OUT/run.log"; }
DEP="env -u RISK_NORMALISE -u RISK_PROFILE -u C2_MIN_EVENTS -u C2_MIN_FLOW_COUNT -u C2_MIN_SPAN_SEC -u C2_BONUS_MIN_SCORE"
ABL="env RISK_PROFILE=netflow RISK_NORMALISE=1 C2_MIN_EVENTS=0 C2_MIN_FLOW_COUNT=0 C2_MIN_SPAN_SEC=0 C2_BONUS_MIN_SCORE=0"
SRC=~/research/frozen_paper1_backend_20261008
EXPECT=91f4ad86f28a804482cbc61e8a72b22fbe35160506d64098ba137f67d448bd84
HAVE=$(sha256sum "$SRC/services/copilotCore.js" | cut -d' ' -f1)
[ "$HAVE" = "$EXPECT" ] || { say "STOP: frozen core is not the paper's version"; exit 1; }
[ -d "$BK" ] || cp -a "$SRC" "$BK"
chmod -R u+w "$BK"
[ -e "$BK/node_modules" ] || ln -s ~/backend/node_modules "$BK/node_modules"
[ -e "$BK/.env" ] || cp ~/backend/.env "$BK/.env"
cp "$KIT/copilotCore.js" "$BK/services/copilotCore.js"
cp "$KIT/analyze_ctu13.js" "$BK/analyze_ctu13.js"
say "core sha256 $(sha256sum "$BK/services/copilotCore.js" | cut -d' ' -f1)"
cd "$BK"
run() {  # name flagenv armenv scenario width
  local f="$OUT/runs/$1.json"
  [ -s "$f" ] && { say "skip $1"; return; }
  say "start $1"
  env $2 $3 SCORE_TIME_FIELD=event_time node analyze_ctu13.js --pcap ctu13-s$4 --window $5 --step 1 \
      --time-field event_time --scope-pcap --out "$f" > "$OUT/runs/$1.log" 2>&1 || say "FAILED $1 (see log)"
}
for s in 1 2 6 8 9; do
  run "ctrl_s${s}_dep_w1" "-u DOS_EXPECT_AVAILABLE" "$DEP" $s 1
  run "ctrl_s${s}_abl_w1" "-u DOS_EXPECT_AVAILABLE" "$ABL" $s 1
done
for s in 1 2 6 8 9; do for w in 1 5; do
  run "c2_s${s}_dep_w${w}" "DOS_EXPECT_AVAILABLE=1" "$DEP" $s $w
  run "c2_s${s}_abl_w${w}" "DOS_EXPECT_AVAILABLE=1" "$ABL" $s $w
done; done
say "all runs finished; evaluate with: python3 -I $KIT/change2_eval.py $OUT/runs ~/research/results/poscontrol_20261014/runs"
