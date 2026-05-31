import os
import json
import matplotlib.pyplot as plt
from datetime import datetime

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
RISK_DIR = "../extract/risk"
OUTPUT_DIR = "../extract/charts/risk"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# --------------------------------------------------
# HELPERS
# --------------------------------------------------
def parse_time(ts):
    try:
        return datetime.fromisoformat(ts.replace("Z", ""))
    except:
        return None


# --------------------------------------------------
# RISK CHART
# --------------------------------------------------
def plot_risk(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    times = []
    scores = []
    phases = []

    for d in data:
        t = parse_time(d.get("timestamp"))
        if not t:
            continue

        times.append(t)
        scores.append(d.get("riskScore", 0))
        phases.append(d.get("phase"))

    if not times:
        print(f"⚠️ No valid data in {file_path}")
        return

    plt.figure(figsize=(12, 5))
    plt.plot(times, scores)

    plt.title("Risk Score Over Time")
    plt.xlabel("Time")
    plt.ylabel("Risk Score")

    # Phase shading (better than lines)
    for i in range(len(times)):
        if phases[i] == "attack":
            plt.axvline(times[i], linestyle="--", alpha=0.1)

    filename = os.path.basename(file_path).replace("_risk.json", "_risk.png")
    out_path = os.path.join(OUTPUT_DIR, filename)

    plt.savefig(out_path)
    plt.close()

    print(f"📈 Saved → {out_path}")


# --------------------------------------------------
# MAIN
# --------------------------------------------------
def run_all():
    for file in os.listdir(RISK_DIR):
        if file.endswith("_risk.json"):
            plot_risk(os.path.join(RISK_DIR, file))


if __name__ == "__main__":
    run_all()