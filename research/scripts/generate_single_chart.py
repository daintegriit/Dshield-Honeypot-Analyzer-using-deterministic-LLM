import json
import os
from datetime import datetime

import matplotlib.pyplot as plt


# ==================================================
# MODE
# ==================================================

CHART_NAME = None
# ==================================================
# PATHS
# ==================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_DIR = os.path.join(BASE_DIR, "../runsforpaper")
OUTPUT_DIR = os.path.join(BASE_DIR, "../extract/charts/risk_attack_aligned_single")

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==================================================
# HELPERS
# ==================================================
def parse_ts(ts):
    if not ts:
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def get_risk(row):
    if isinstance(row.get("core"), dict):
        risk = row["core"].get("riskScore0to100")
        if risk is not None:
            return risk
    return row.get("riskScore", 0)


# 🔥 CLEAN TITLE GENERATOR
def format_title(name):
    name_lower = name.lower()

    # ----------------------------------------
    # WannaCry
    # ----------------------------------------
    if "wannacry" in name_lower:
        if "successful" in name_lower:
            return "WannaCry (Successful)"
        if "failed" in name_lower:
            return "WannaCry (Failed)"
        return "WannaCry"

    # ----------------------------------------
    # TrickBot
    # ----------------------------------------
    if "trickbot" in name_lower:
        return "TrickBot"

    # ----------------------------------------
    # Emotet
    # ----------------------------------------
    if "emotet" in name_lower:
        return "Emotet"

    # ----------------------------------------
    # MITM
    # ----------------------------------------
    if "mitm" in name_lower:
        return "MITM Attack"

    # ----------------------------------------
    # 🔥 NotPetya (handle typo too)
    # ----------------------------------------
    if "notpetya" in name_lower or "notpeya" in name_lower:
        return "NotPetya"

    # ----------------------------------------
    # Sality
    # ----------------------------------------
    if "sality" in name_lower:
        return "Sality"

    # ----------------------------------------
    # CCleaner
    # ----------------------------------------
    if "ccleaner" in name_lower:
        return "CCleaner Malware"

    # ----------------------------------------
    # Ramnit
    # ----------------------------------------
    if "ramnit" in name_lower:
        return "Ramnit"

    # ----------------------------------------
    # Cobalt
    # ----------------------------------------
    if "cobalt" in name_lower:
        return "Cobalt Strike"

    # ----------------------------------------
    # Crypto miner
    # ----------------------------------------
    if "miner" in name_lower or "bitcoin" in name_lower:
        return "Cryptominer"

    # ----------------------------------------
    # FIXED CASE
    # ----------------------------------------
    if "fixed" in name_lower:
        return "win12 fixed"

    # ----------------------------------------
    # fallback
    # ----------------------------------------
    return "Unknown Attack"

# ==================================================
# MAIN CHART
# ==================================================
def generate_chart(chart_name):
    json_path = os.path.join(INPUT_DIR, chart_name)

    if not os.path.exists(json_path):
        raise FileNotFoundError(f"Missing file: {json_path}")

    with open(json_path, "r") as f:
        data = json.load(f)

    attack_start = parse_ts(data.get("attackStartEffective"))
    injection_start = parse_ts(data.get("injectionStart"))
    injection_end = parse_ts(data.get("injectionEnd"))

    if not attack_start:
        raise ValueError("Missing attackStartEffective")

    if not injection_start:
        injection_start = attack_start

    if not injection_end:
        raise ValueError("Missing injectionEnd")

    results = data.get("results", [])

    t_vals = []
    risk_vals = []

    for row in results:
        ts = parse_ts(row.get("timestamp"))
        if not ts:
            continue

        t_min = (ts - attack_start).total_seconds() / 60.0
        t_vals.append(t_min)
        risk_vals.append(get_risk(row))

    if not t_vals:
        raise ValueError("No valid result timestamps found")

    injection_start_min = (injection_start - attack_start).total_seconds() / 60.0
    injection_end_min = (injection_end - attack_start).total_seconds() / 60.0

    # ==================================================
    # PLOT
    # ==================================================
    plt.figure(figsize=(12, 5))

    plt.step(t_vals, risk_vals, where='post', linewidth=2.2)

    plt.axvspan(min(t_vals), injection_start_min, color="gray", alpha=0.08)
    plt.axvspan(injection_start_min, injection_end_min, color="red", alpha=0.10)
    plt.axvspan(injection_end_min, max(t_vals), color="blue", alpha=0.08)

    plt.axvline(injection_start_min, linestyle="--", linewidth=1)
    plt.axvline(injection_end_min, linestyle="--", linewidth=1)

    y_max = max(risk_vals) if max(risk_vals) > 0 else 100

    plt.text(min(t_vals) + 5, y_max * 0.85, "Baseline", fontsize=9)
    plt.text(
        (injection_start_min + injection_end_min) / 2,
        y_max * 0.95,
        "Injection",
        fontsize=9,
        ha="center",
    )
    plt.text(injection_end_min + 5, y_max * 0.85, "Cooldown", fontsize=9)

    title = format_title(chart_name)
    plt.title(f"{title} — Risk Score Over Time (Attack-Aligned)")

    plt.xlabel("Time Relative to Attack Start (minutes)")
    plt.ylabel("Risk Score")
    plt.grid(alpha=0.3)
    plt.tight_layout()

    # ==================================================
    # SAVE
    # ==================================================
    out_name = chart_name.replace(".json", "_attack_aligned.png")
    out_path = os.path.join(OUTPUT_DIR, out_name)

    plt.savefig(out_path, dpi=300, bbox_inches="tight")
    plt.close()

    print(f"✅ Chart saved → {out_path}")
    print(f"Injection start min: {injection_start_min:.3f}")
    print(f"Injection end min: {injection_end_min:.3f}")


# ==================================================
# RUN MODES
# ==================================================
def run_all():
    files = os.listdir(INPUT_DIR)

    for f in files:
        if not f.endswith(".json"):
            continue

        try:
            generate_chart(f)
        except Exception as e:
            print(f"❌ Failed: {f} → {e}")


# ==================================================
# ENTRY
# ==================================================
if __name__ == "__main__":

    if CHART_NAME:
        generate_chart(CHART_NAME)

    else:
        run_all()