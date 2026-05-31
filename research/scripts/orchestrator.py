#!/usr/bin/env python3
"""
FULL EXPERIMENT ORCHESTRATOR (PRODUCTION-GRADE)

- Auto-detects PCAPs
- Validates Zeek logs exist and are usable
- Runs CLEAN / MIXED / BOTH (configurable)
- Passes PCAP_NAME → Node → Python replay
- Verifies ingestion into MongoDB
- Verifies enrichment pipeline state
- Provides structured logging + diagnostics
"""

import subprocess
import os
import time
import sys
from datetime import datetime

# ---------------- CONFIG ----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

PCAP_DIR = os.path.join(BASE_DIR, "../pcaps")
ZEEK_LOG_DIR = os.path.join(PCAP_DIR, "zeek_logs")

NODE_SCRIPT = "run_full_experiment.js"
REPLAY_SCRIPT = "replay_pcap_events.py"

BASE_ENV = os.environ.copy()

SLEEP_BETWEEN_RUNS = 5  # seconds

# ---------------- HELPERS ----------------

def now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")


def log(msg):
    print(f"[{now()}] {msg}")


# ---------------- MODE CONTROL ----------------

def get_run_mode():
    # Priority: CLI arg → ENV → fallback
    if len(sys.argv) > 1:
        return sys.argv[1].lower()

    return os.environ.get("GLOBAL_RUN_MODE", "").lower()


def prompt_run_mode():
    print("\nSelect Run Mode:")
    print("1) Clean only")
    print("2) Mixed only")
    print("3) Both")

    choice = input("Enter choice (1/2/3): ").strip()

    if choice == "1":
        return "clean"
    elif choice == "2":
        return "mixed"
    elif choice == "3":
        return "both"
    else:
        print("Invalid choice, defaulting to BOTH")
        return "both"


# ---------------- PCAP DISCOVERY ----------------

def get_all_pcaps():
    pcaps = []

    if not os.path.exists(PCAP_DIR):
        raise FileNotFoundError(f"❌ PCAP_DIR not found: {PCAP_DIR}")

    for file in os.listdir(PCAP_DIR):
        if file.endswith(".pcap"):
            pcaps.append(file.replace(".pcap", ""))

    return sorted(pcaps)


# ---------------- VALIDATION ----------------

def validate_pcap_environment(pcap):
    zeek_path = os.path.join(ZEEK_LOG_DIR, pcap)

    if not os.path.exists(zeek_path):
        log(f"❌ Missing Zeek logs for: {pcap}")
        log(f"   Expected: {zeek_path}")
        return False

    files = os.listdir(zeek_path)
    log_files = [f for f in files if f.endswith(".log")]

    if not log_files:
        log(f"❌ No Zeek .log files found for: {pcap}")
        return False

    log(f"✅ Zeek logs ready ({len(log_files)} files): {pcap}")
    return True


# ---------------- PIPELINE VERIFICATION ----------------

def run_mongo_eval(js_code):
    try:
        result = subprocess.check_output(
            ["mongosh", "--quiet", "--eval", js_code],
            text=True
        )
        return result.strip()
    except Exception as e:
        return f"ERROR: {e}"


def verify_ingestion():
    log("🔎 Checking ingestion...")

    result = run_mongo_eval("db.attacks.countDocuments({})")

    try:
        count = int(result)
    except:
        log(f"⚠️ Failed to parse Mongo result: {result}")
        return

    log(f"📊 Total attacks: {count}")

    if count == 0:
        log("❌ NO DATA INGESTED — PIPELINE BROKEN")
    else:
        log("✅ Ingestion working")


def verify_pipeline_health():
    log("🔎 Checking pipeline health...")

    js = """
    printjson({
        total: db.attacks.countDocuments({}),
        enriched: db.attacks.countDocuments({ needs_enrichment: false }),
        pending: db.attacks.countDocuments({ needs_enrichment: true })
    })
    """

    result = run_mongo_eval(js)
    print(result)


# ---------------- EXPERIMENT RUNNER ----------------

def run_experiment(pcap, mode):
    log("=" * 70)
    log(f"🚀 STARTING EXPERIMENT")
    log(f"   PCAP: {pcap}")
    log(f"   MODE: {mode}")
    log("=" * 70)

    env = BASE_ENV.copy()

    env["PCAP_NAME"] = pcap
    env["RUN_MODE"] = mode
    env["REPLAY_SCRIPT"] = REPLAY_SCRIPT
    env["DISABLE_DSHIELD"] = "1" if mode == "clean" else "0"

    try:
        subprocess.run(
            ["node", NODE_SCRIPT],
            cwd=BASE_DIR,
            env=env,
            check=True
        )

        log(f"✅ SUCCESS: {pcap} | {mode}")

    except subprocess.CalledProcessError as e:
        log(f"❌ FAILED: {pcap} | {mode}")
        log(f"Error: {e}")
        return

    verify_ingestion()
    verify_pipeline_health()

    log("-" * 70)
    time.sleep(SLEEP_BETWEEN_RUNS)


# ---------------- MAIN ----------------

def main():
    log("📂 EXPERIMENT ORCHESTRATOR START")

    run_mode = get_run_mode()

    if run_mode not in ["clean", "mixed", "both"]:
        run_mode = prompt_run_mode()

    log(f"🔧 RUN MODE: {run_mode.upper()}")

    pcaps = get_all_pcaps()

    if not pcaps:
        log("❌ No PCAPs found.")
        return

    log("📂 Found PCAPs:")
    for p in pcaps:
        log(f" - {p}")

    log("🔁 Starting batch experiments...")

    for pcap in pcaps:

        if not validate_pcap_environment(pcap):
            log(f"⚠️ Skipping {pcap}")
            continue

        if run_mode == "clean":
            run_experiment(pcap, "clean")

        elif run_mode == "mixed":
            run_experiment(pcap, "mixed")

        elif run_mode == "both":
            run_experiment(pcap, "clean")
            run_experiment(pcap, "mixed")

    log("🎉 ALL EXPERIMENTS COMPLETE")


# ---------------- ENTRY ----------------

if __name__ == "__main__":
    main()