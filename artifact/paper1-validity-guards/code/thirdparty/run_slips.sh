#!/usr/bin/env bash
# run_slips.sh -- D1. Pin the image, record versions and the threat-level map,
# pilot on Slips' own bundled sample (not registered data) to check the output
# format, then run the registered inputs. Usage:
#   bash run_slips.sh pilot  <out dir>
#   bash run_slips.sh run    <inputs dir> <out dir> 1 2 6 8 9
set -eu
IMG=stratosphereips/slips:latest
mode=$1; shift
pin() {
  docker pull "$IMG" >/dev/null
  DIG=$(docker inspect --format '{{index .RepoDigests 0}}' "$IMG")
  echo "$DIG"
}
case "$mode" in
pilot)
  OUT=$1; mkdir -p "$OUT"
  DIG=$(pin)
  {
    echo "slips image $DIG"
    docker run --rm "$DIG" bash -c 'cd /StratosphereLinuxIPS 2>/dev/null || true; cat VERSION 2>/dev/null; git rev-parse HEAD 2>/dev/null; grep -n -A8 "class ThreatLevel" -r slips_files 2>/dev/null | head -20; grep -n -E "time_window_width|evidence_detection_threshold|risk_accumulated_threat_level" config/slips.yaml'
  } | tee "$OUT/VERSIONS_slips.txt"
  docker run --rm "$DIG" bash -c 'cd /StratosphereLinuxIPS && python3 -c "
import json
from slips_files.core.structures.evidence import ThreatLevel
print(json.dumps({t.name.lower(): float(t.value) for t in ThreatLevel}))"' > "$OUT/threat_map.json" || echo "could not import ThreatLevel; write threat_map.json by hand from the grep above"
  echo "threat map: $(cat "$OUT/threat_map.json" 2>/dev/null)" | tee -a "$OUT/VERSIONS_slips.txt"
  docker run --rm "$DIG" bash -c 'cd /StratosphereLinuxIPS; ls dataset | grep -i binetflow' | tee "$OUT/pilot_candidates.txt"
  S=$(head -1 "$OUT/pilot_candidates.txt")
  docker run --rm -v "$OUT":/out "$DIG" bash -c "cd /StratosphereLinuxIPS && ./slips.py -f dataset/$S -o /out/pilot" > "$OUT/pilot.log" 2>&1 || true
  ls -la "$OUT/pilot" | tee -a "$OUT/pilot.log"
  python3 -I "$(dirname "$0")/slips_parse.py" --inspect "$OUT/pilot"
  ;;
run)
  IN=$1; OUT=$2; shift 2
  DIG=$(grep '^slips image' "$OUT/VERSIONS_slips.txt" | awk '{print $3}')
  [ -n "$DIG" ] || { echo "run the pilot first: it pins the image digest"; exit 1; }
  for s in "$@"; do for m in TRUE ARRIVAL; do
    d="$OUT/s${s}_${m}"
    [ -s "$d/alerts.json" ] && { echo "skip $d"; continue; }
    echo "slips s$s $m $(date -u +%H:%M:%S)"
    docker run --rm -v "$IN":/in:ro -v "$OUT":/out "$DIG" bash -c "cd /StratosphereLinuxIPS && ./slips.py -f /in/s${s}_${m}.binetflow -o /out/s${s}_${m}" > "$OUT/s${s}_${m}.log" 2>&1 || echo "  slips exited non-zero, see $OUT/s${s}_${m}.log"
  done; done
  ;;
esac
