#!/usr/bin/env bash
# run_all.sh -- third-party detector test (registration THIRD_PARTY_DETECTORS_REGISTRATION.md).
# Run on the EC2 box, step by step:
#   bash run_all.sh setup       install tools, clone Kitsune, pin versions
#   bash run_all.sh inputs      export replayed flows, build TRUE/ARRIVAL inputs, check the join
#   bash run_all.sh windows     check the kit's windows are Chiron's windows (stops on mismatch)
#   bash run_all.sh rf          D3 random forest
#   bash run_all.sh slips-pilot D1 pilot on Slips' bundled sample (format check only)
#   bash run_all.sh slips       D1 on the registered inputs (long)
#   bash run_all.sh kitsune     D2 (set PCAP, BOUNDARY, INFECTED, C2 below first)
#   bash run_all.sh audit       guards + statistics + predictions
set -euo pipefail
KIT="$(cd "$(dirname "$0")" && pwd)"
OUT=~/research/results/thirdparty_20261015
POS=~/research/results/poscontrol_20261014        # Chiron TRUE-time runs + backend copy
BK=$POS/backend                                     # has .env, node_modules, models/
REPLAY_DIR=${REPLAY_DIR:-$(cd "$KIT/../scripts" && pwd)}   # the repo's replay_ctu13.py
CTU=${CTU:-$(dirname "$(find ~ -type d -name CTU-13-Dataset 2>/dev/null | head -1)")/CTU-13-Dataset}
GUARD=${GUARD:-$(cd "$KIT/../scripts" && pwd)/guard_audit.py}   # the repo's 12-condition audit
SC="1 2 6 8 9"
# D2 inputs (from the Paper 2 boundary derivation); fill these in before `kitsune`
PCAP=${PCAP:-}
BOUNDARY=${BOUNDARY:-}
INFECTED=${INFECTED:-}
C2=${C2:-}
mkdir -p "$OUT"; LOG=$OUT/run.log
say() { echo "$@" | tee -a "$LOG"; }
step=${1:-}
case "$step" in
setup)
  sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq tshark docker.io python3-venv >/dev/null
  python3 -m venv "$OUT/venv"
  "$OUT/venv/bin/pip" install -q "numpy<2" scipy scikit-learn cython scapy requests
  [ -d "$OUT/Kitsune-py" ] || git clone -q https://github.com/ymirsky/Kitsune-py.git "$OUT/Kitsune-py"
  {
    echo "kitsune commit $(git -C "$OUT/Kitsune-py" rev-parse HEAD)"
    "$OUT/venv/bin/python" -c "import numpy,scipy,sklearn;print('numpy',numpy.__version__,'scipy',scipy.__version__,'sklearn',sklearn.__version__)"
    echo "guard_audit sha256 $(sha256sum "$GUARD" | cut -d' ' -f1)"
    echo "replay_ctu13.py $REPLAY_DIR  ctu13 $CTU"
  } | tee "$OUT/VERSIONS.txt"
  say "setup done. If docker needs it: sudo usermod -aG docker \$USER, then log out and back in."
  ;;
inputs)
  cp "$KIT/export_flows.js" "$BK/export_flows.js"
  (cd "$BK" && node export_flows.js "$OUT/export" $SC) | tee -a "$LOG"
  "$OUT/venv/bin/python" -I "$KIT/build_inputs.py" "$REPLAY_DIR" "$CTU" "$OUT/export" "$OUT/inputs" $SC | tee "$OUT/join.log"
  cat "$OUT/join.log" >> "$LOG"
  for s in $SC; do
    [ -s "$OUT/inputs/flows_s$s.tsv" ] && [ -s "$OUT/inputs/s${s}_TRUE.binetflow" ] && [ -s "$OUT/inputs/s${s}_ARRIVAL.binetflow" ] \
      || { say "STOP: inputs for s$s were not built"; exit 1; }
  done
  if grep -q WARNING "$OUT/join.log"; then say "STOP: the join is not exact."; exit 1; fi
  [ "$(grep -c 'rows unmatched 0  docs unmatched 0' "$OUT/join.log")" = "$(echo $SC | wc -w)" ] \
    || { say "STOP: the join did not report exact on every scenario"; exit 1; }
  say "join exact on every scenario"
  ;;
windows)
  "$OUT/venv/bin/python" -I "$KIT/rf.py" "$OUT/inputs" "$OUT/rf" $SC >/dev/null
  "$OUT/venv/bin/python" -I "$KIT/make_rf_runs.py" "$OUT/inputs" "$OUT/rf" "$OUT/runs" $SC >/dev/null
  ok=1
  for s in $SC; do for w in 1 5; do
    "$OUT/venv/bin/python" -I "$KIT/check_windows.py" "$OUT/runs/D3/s$s/TRUE/w$w.json" "$POS/runs/s${s}_evt_dep_w${w}s1.json" | tee -a "$LOG" || ok=0
  done; done
  [ $ok = 1 ] && say "windows identical to Chiron's on true time" || { say "STOP: windows differ from Chiron's"; exit 1; }
  ;;
rf)
  "$OUT/venv/bin/python" -I "$KIT/rf.py" "$OUT/inputs" "$OUT/rf" $SC | tee -a "$LOG"
  "$OUT/venv/bin/python" -I "$KIT/make_rf_runs.py" "$OUT/inputs" "$OUT/rf" "$OUT/runs" $SC | tee -a "$LOG"
  ;;
slips-pilot)
  bash "$KIT/run_slips.sh" pilot "$OUT/slips" | tee -a "$LOG"
  say "Send the pilot output (above) back before running 'slips': the parser's field mapping is checked against it."
  ;;
slips)
  bash "$KIT/run_slips.sh" run "$OUT/inputs" "$OUT/slips" $SC | tee -a "$LOG"
  [ -s "$OUT/slips/threat_map.json" ] || { say "STOP: write $OUT/slips/threat_map.json from the pinned ThreatLevel map first"; exit 1; }
  for s in $SC; do for m in TRUE ARRIVAL; do
    python3 -I "$KIT/slips_parse.py" "$OUT/slips/s${s}_${m}" "$OUT/slips/threat_map.json" > "$OUT/slips/evidence_s${s}_${m}.tsv"
  done; done
  "$OUT/venv/bin/python" -I "$KIT/make_slips_runs.py" "$OUT/inputs" "$OUT/slips" "$OUT/runs" $SC | tee -a "$LOG"
  ;;
kitsune)
  [ -n "$PCAP" ] && [ -n "$BOUNDARY" ] && [ -n "$INFECTED" ] && [ -n "$C2" ] || { echo "set PCAP BOUNDARY INFECTED C2"; exit 1; }
  "$OUT/venv/bin/python" -I "$KIT/kitsune_run.py" "$OUT/Kitsune-py" "$PCAP" "$BOUNDARY" "$INFECTED" "$C2" "$OUT/kitsune" | tee -a "$LOG"
  mkdir -p "$OUT/runs/D2/mixed1/TRUE" && cp "$OUT/kitsune/runs/"*.json "$OUT/runs/D2/mixed1/TRUE/"
  ;;
audit)
  "$OUT/venv/bin/python" -I "$KIT/guard_param.py" "$GUARD" "$OUT/guards.tsv" $(find "$OUT/runs" -name '*.json' | sort) > /dev/null
  "$OUT/venv/bin/python" -I "$KIT/stats.py" "$OUT/runs" "$OUT/guards.tsv" "$OUT/results" | tee -a "$LOG"
  say "results in $OUT/results (SUMMARY.tsv, PREDICTIONS.txt) and $OUT/guards.tsv"
  ;;
*) sed -n 2,12p "$0" ;;
esac
