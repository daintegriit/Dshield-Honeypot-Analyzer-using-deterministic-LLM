#!/usr/bin/env python3
"""
FULL EXPERIMENT ORCHESTRATOR (PRODUCTION-GRADE)

- Auto-detects PCAPs
- Validates Zeek logs exist and are usable
- Runs CLEAN / MIXED / BOTH (configurable)
- Passes PCAP_NAME + per-pcap INFECTION_OFFSET_SECONDS → Node → Python replay
- Batch-safe: WRITE_CSV off by default, large captures skippable
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

# ---------------- INFECTION OFFSETS ----------------
# Seconds from the FIRST packet in each capture to the infection moment
# (source-capture time; the replay scales it to replay-time automatically).
# Fill these from each capture's Stratosphere README timeline.
# 0 = treat the whole capture as attack (no benign pre-infection window).
INFECTION_OFFSETS = {
    # Seconds from capture start to infection.
    #
    # DERIVATION
    # ----------
    # Three sources, in decreasing order of trust:
    #
    #   derived  first connection from the README's stated infected host to an
    #            external address, taken as the minimum timestamp over the whole
    #            conn.log (Zeek writes records at connection CLOSE, so the file
    #            is not time-ordered and a head-of-file reading is wrong).
    #            Local, multicast and DNS destinations excluded.
    #   pkt      "Date of last packet in tcpdump before infection" from the
    #            README, given in capture-relative time. Present in four READMEs.
    #   wall     (infected - started) from the README timeline. Hand-written
    #            operator notes.
    #
    # derived exceeds wall by 11-73 s wherever both exist, consistently and in
    # one direction: the operator's execution timestamp precedes the malware's
    # first network activity. derived is used because it is measured from the
    # capture itself and is independent of anything the detector computes.
    #
    # Ground truth is therefore: pre-infection = t < offset, post = t >= offset.

    # --- derived from first external contact (8) ---
    "2017-06-24_win10emotet_271-1":                    459,  # 458.6 -> 82.165.142.107:443
                                                             #   then :8080 beacon rotation
                                                             #   across 10 hosts, cycle
                                                             #   repeats at 1055 s
                                                             #   (pkt n/a, wall 430)
    "2017-06-24_win6trickbot_267-1":                   424,  # 423.6 -> 50.19.97.123:80
                                                             #   then periodic :443
                                                             #   (pkt n/a, wall 351)
    "2017-07-11_capture-win2wannacryfailed_283-1":     297,  # 297.3 -> mass :445 across
                                                             #   dozens of external hosts
                                                             #   (pkt n/a, wall 268)
    "2017-07-11_capture-win2wannacrysuccessful_284-1": 437,  # 437.3 -> mass :445
                                                             #   (pkt n/a, wall 419)
    "2018-04-03_win6_ramnit343-1":                     306,  # 306.1 -> 91.220.62.30:443
                                                             #   (pkt 287, wall 295)
    "2018-04-03_win11cobalt_345-1":                    241,  # 241.2 -> 95.46.8.65:443
                                                             #   (pkt 219, wall 247)
    "2018-04-03_win12_fixed_346-1":                    302,  # 301.5 -> 37.187.54.76:443
                                                             #   (pkt 274, wall 285)
    "2018-04-04_win16bitcoinminer_347-1":              493,  # 492.9 -> 5.187.7.235:3333
                                                             #   (pkt 465, wall 413)

    # --- README wall clock is wrong; derived value used (1) ---
    "2017-11-23_win16sality_319-1":                    376,  # 376.4 -> 81.169.145.74:80.
                                                             # That host appears verbatim
                                                             # in the README's own mitmdump
                                                             # output as the first fetch.
                                                             # README timeline says 58 s,
                                                             # off by ~6x. Treated as a
                                                             # typo in the source.

    # --- wall clock only, not independently verified (1) ---
    "2017-12-18_win2ccleaner_320-1":                    97,  # first external contact is
                                                             # 195.113.232.73:80 at 12.5 s,
                                                             # which is CVUT address space
                                                             # (benign startup), so the
                                                             # derivation does not isolate
                                                             # infection here. wall 97 kept
                                                             # unverified.
}

# Captures excluded: Zeek extraction produced too few records to derive or
# evaluate anything.
#   2017-07-03_capture-win13mitm_281-1   conn.log 27 lines
#   2017-07-13_capture-win2NotPeya_298-1 conn.log 835 lines
UNUSABLE_CAPTURES = {
    "2017-07-03_capture-win13mitm_281-1",
    "2017-07-13_capture-win2NotPeya_298-1",
}

# Captures skipped in the default batch.
SKIP_PCAPS = set(
    filter(
        None,
        os.environ.get(
            "SKIP_PCAPS",
            # Excluded by default because Zeek extraction produced too few
            # records to derive an infection point or evaluate anything
            # (281-1: 27 conn.log lines, 298-1: 835). Sality 319-1 is NOT
            # excluded by default any more -- it was skipped for size
            # (2.2 GB), which is a resource decision, not a data one. Set
            # SKIP_PCAPS explicitly to drop it for a given batch.
            "2017-07-03_capture-win13mitm_281-1,"
            "2017-07-13_capture-win2NotPeya_298-1",
        ).split(","),
    )
)

# CSV artifact writing in the replay. Default OFF for batch (disk safety).
WRITE_CSV = os.environ.get("WRITE_CSV", "0")

# ---------------- HELPERS ----------------

def now():
    return datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%SZ")


def log(msg):
    print(f"[{now()}] {msg}")


# ---------------- MODE CONTROL ----------------

def get_run_mode():
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
            text=True,
        )
        return result.strip()
    except Exception as e:
        return f"ERROR: {e}"


def verify_ingestion():
    log("🔎 Checking ingestion (replay-tagged docs)...")
    result = run_mongo_eval('db.attacks.countDocuments({ source: "replay" })')
    try:
        count = int(result)
    except Exception:
        log(f"⚠️ Failed to parse Mongo result: {result}")
        return
    log(f"📊 Total replay-tagged attacks: {count}")
    if count == 0:
        log("❌ NO REPLAY DATA INGESTED — PIPELINE OR TAGGING BROKEN")
    else:
        log("✅ Replay ingestion working")


def verify_pipeline_health():
    log("🔎 Checking pipeline health...")
    js = """
    printjson({
        total: db.attacks.countDocuments({}),
        replay: db.attacks.countDocuments({ source: "replay" }),
        honeypot: db.attacks.countDocuments({ source: "honeypot" }),
        withEventTime: db.attacks.countDocuments({ event_time: { $ne: null } })
    })
    """
    result = run_mongo_eval(js)
    print(result)


# ---------------- EXPERIMENT RUNNER ----------------

def run_experiment(pcap, mode):
    offset = INFECTION_OFFSETS.get(pcap, 0)

    log("=" * 70)
    log("🚀 STARTING EXPERIMENT")
    log(f"   PCAP:   {pcap}")
    log(f"   MODE:   {mode}")
    log(f"   OFFSET: {offset}s (source-time infection offset)")
    log(f"   CSV:    {WRITE_CSV}")
    log("=" * 70)

    env = BASE_ENV.copy()
    env["PCAP_NAME"] = pcap
    env["RUN_MODE"] = mode
    env["REPLAY_SCRIPT"] = REPLAY_SCRIPT
    env["INFECTION_OFFSET_SECONDS"] = str(offset)
    env["WRITE_CSV"] = WRITE_CSV
    # SOURCE_SCOPE defaults to "replay" in the harness (isolation).

    try:
        subprocess.run(
            ["node", NODE_SCRIPT],
            cwd=BASE_DIR,
            env=env,
            check=True,
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
    log(f"⏭️  SKIP_PCAPS: {', '.join(sorted(SKIP_PCAPS)) or '(none)'}")
    log(f"📝 WRITE_CSV: {WRITE_CSV}")

    pcaps = get_all_pcaps()
    if not pcaps:
        log("❌ No PCAPs found.")
        return

    log("📂 Found PCAPs:")
    for p in pcaps:
        log(f" - {p}")

    log("🔁 Starting batch experiments...")

    for pcap in pcaps:
        if pcap in SKIP_PCAPS:
            log(f"⏭️  Skipping {pcap} (excluded — run separately)")
            continue

        if not validate_pcap_environment(pcap):
            log(f"⚠️ Skipping {pcap} (no zeek logs)")
            continue

        if pcap not in INFECTION_OFFSETS:
            log(f"⚠️ No infection offset defined for {pcap} — defaulting to 0 "
                f"(whole capture treated as attack). Add it to INFECTION_OFFSETS.")

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
