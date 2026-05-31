import json
import sys
import os
import matplotlib.pyplot as plt


# --------------------------------------------------
# PLOT FUNCTION
# --------------------------------------------------
def plot_relative(file_path):
    with open(file_path, "r") as f:
        data = json.load(f)

    if not data:
        print(f"⚠️ Empty data: {file_path}")
        return

    # Ensure sorted (safety)
    data = sorted(data, key=lambda x: x.get("t_min", 0))

    t = []
    risk = []
    phases = []

    for x in data:
        if "t_min" not in x:
            continue

        t.append(x["t_min"])
        risk.append(x.get("riskScore", 0))
        phases.append(x.get("phase"))

    if not t:
        print(f"⚠️ No valid timeline data: {file_path}")
        return

    # --------------------------------------------------
    # PLOT
    # --------------------------------------------------
    plt.figure(figsize=(12, 5))
    plt.plot(t, risk, linewidth=2)

    plt.xlabel("Time Since Run Start (minutes)")
    plt.ylabel("Risk Score")
    plt.title("Risk Score Over Time (Relative)")
    plt.grid(alpha=0.3)

    # --------------------------------------------------
    # OPTIONAL: PHASE MARKERS (VERY IMPORTANT)
    # --------------------------------------------------
    attack_start = None
    cooldown_start = None

    for i in range(len(phases)):
        if phases[i] == "attack" and attack_start is None:
            attack_start = t[i]
        if phases[i] == "cooldown" and cooldown_start is None:
            cooldown_start = t[i]

    if attack_start is not None:
        plt.axvline(x=attack_start, linestyle="--", alpha=0.7)
    if cooldown_start is not None:
        plt.axvline(x=cooldown_start, linestyle="--", alpha=0.7)

    # --------------------------------------------------
    # OUTPUT → research/extract/charts/risk_relative/
    # --------------------------------------------------
    base_dir = os.path.dirname(file_path)                 # extract/risk_relative
    extract_dir = os.path.dirname(base_dir)               # extract
    charts_dir = os.path.join(extract_dir, "charts", "risk_relative")

    os.makedirs(charts_dir, exist_ok=True)

    filename = os.path.basename(file_path).replace(".json", ".png")
    out_path = os.path.join(charts_dir, filename)

    plt.savefig(out_path, bbox_inches="tight")
    plt.close()

    print(f"📊 Saved → {out_path}")


# --------------------------------------------------
# ENTRY
# --------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_risk_relative_chart.py <file>")
        sys.exit(1)

    plot_relative(sys.argv[1])