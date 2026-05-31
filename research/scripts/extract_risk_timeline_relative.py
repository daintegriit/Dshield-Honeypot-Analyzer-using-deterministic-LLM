import json
import sys
import os
from datetime import datetime


# -------------------------
# SAFE TIMESTAMP PARSER
# -------------------------
def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


# -------------------------
# MAIN EXTRACTION LOGIC
# -------------------------
def extract_risk_relative(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    # Handle both formats
    if isinstance(data, list):
        results = data
        start_time = parse_ts(results[0].get("timestamp")) if results else None
    else:
        results = data.get("results", [])
        start_time = parse_ts(data.get("captureStartedAt"))

        # Fallback if missing
        if not start_time and results:
            start_time = parse_ts(results[0].get("timestamp"))

    if not results or not start_time:
        print(f"⚠️ Skipping (no valid data): {file_path}")
        return []

    timeline = []

    for r in results:
        ts = parse_ts(r.get("timestamp"))
        if not ts:
            continue

        minutes_since_start = (ts - start_time).total_seconds() / 60.0

        timeline.append({
            "t_min": round(minutes_since_start, 3),
            "riskScore": r.get("riskScore", 0),
            "state": r.get("endState"),
            "phase": r.get("phase")
        })

    timeline.sort(key=lambda x: x["t_min"])

    return timeline


# -------------------------
# MAIN
# -------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_risk_timeline_relative.py <file>")
        return

    file_path = sys.argv[1]
    timeline = extract_risk_relative(file_path)

    if not timeline:
        return

    # -------------------------
    # OUTPUT → research/extract/risk_relative/
    # -------------------------
    base_dir = os.path.dirname(file_path)
    research_dir = os.path.dirname(base_dir)

    extract_dir = os.path.join(research_dir, "extract", "risk_relative")
    os.makedirs(extract_dir, exist_ok=True)

    filename = os.path.basename(file_path).replace(".json", "_risk_relative.json")
    out_path = os.path.join(extract_dir, filename)

    with open(out_path, "w") as f:
        json.dump(timeline, f, indent=2)

    print(f"✅ Relative risk timeline saved → {out_path}")


# -------------------------
# ENTRY
# -------------------------
if __name__ == "__main__":
    main()