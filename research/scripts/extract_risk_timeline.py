import json
import sys
import os


# --------------------------------------------------
# CONFIG
# --------------------------------------------------
BASE_OUTPUT = "../extract/risk"


# --------------------------------------------------
# CORE EXTRACTION
# --------------------------------------------------
def extract_risk(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    results = data.get("results", [])

    timeline = []

    for r in results:
        timeline.append({
            "timestamp": r.get("timestamp"),
            "riskScore": r.get("riskScore"),
            "state": r.get("endState"),
            "phase": r.get("phase")
        })

    return timeline


# --------------------------------------------------
# OUTPUT HELPERS
# --------------------------------------------------
def ensure_dirs():
    os.makedirs(BASE_OUTPUT, exist_ok=True)


def build_output_path(file_path):
    filename = os.path.basename(file_path).replace(".json", "_risk.json")
    return os.path.join(BASE_OUTPUT, filename)


# --------------------------------------------------
# MAIN
# --------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print("Usage: python extract_risk_timeline.py <file>")
        return

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return

    timeline = extract_risk(file_path)

    ensure_dirs()

    out_path = build_output_path(file_path)

    with open(out_path, "w") as f:
        json.dump(timeline, f, indent=2)

    print(f"✅ Risk timeline saved → {out_path}")


# --------------------------------------------------
# ENTRY
# --------------------------------------------------
if __name__ == "__main__":
    main()