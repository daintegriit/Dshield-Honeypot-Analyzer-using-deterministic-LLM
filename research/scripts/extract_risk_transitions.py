#!/usr/bin/env python3

import json
import sys
import os

from datetime import datetime


# --------------------------------------------------
# CONFIG
# --------------------------------------------------

SCRIPT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

# INPUT EXPERIMENT JSONS
BASE_INPUT = os.path.join(
    SCRIPT_DIR,
    "../runsforpaper"
)

# OUTPUT DIRECTORY
BASE_OUTPUT = os.path.join(
    SCRIPT_DIR,
    "../extract/risk_transitions"
)

# --------------------------------------------------
# RISK TRANSITION CONFIG
# --------------------------------------------------

# Store ALL movements
MIN_RISK_DELTA = 0

# Ignore extremely rapid oscillations
MIN_DURATION_SEC = 5

# Major threshold bands
RISK_THRESHOLDS = {

    "stable": 25,

    "elevated": 50,

    "high": 75,

    "critical": 90
}


# --------------------------------------------------
# SAFE TIMESTAMP PARSER
# --------------------------------------------------

def parse_ts(ts):

    if not ts:
        return None

    try:

        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )

    except Exception:

        return None


# --------------------------------------------------
# SAFE RISK EXTRACTION
# --------------------------------------------------

def extract_risk(record):

    risk = None

    # Core format
    if (
        isinstance(
            record.get("core"),
            dict
        )
    ):

        risk = record["core"].get(
            "riskScore0to100"
        )

    # Flat format
    if risk is None:

        risk = record.get(
            "riskScore0to100"
        )

    if risk is None:

        risk = record.get(
            "riskScore"
        )

    # Final fallback
    if risk is None:

        risk = 0

    try:

        return float(risk)

    except:

        return 0.0


# --------------------------------------------------
# RISK BAND CLASSIFICATION
# --------------------------------------------------

def classify_risk_band(risk):

    if risk >= RISK_THRESHOLDS["critical"]:
        return "critical"

    if risk >= RISK_THRESHOLDS["high"]:
        return "high"

    if risk >= RISK_THRESHOLDS["elevated"]:
        return "elevated"

    return "stable"


# --------------------------------------------------
# THRESHOLD CROSS DETECTION
# --------------------------------------------------

def detect_threshold_crossing(
    prev_risk,
    current_risk
):

    prev_band = classify_risk_band(
        prev_risk
    )

    current_band = classify_risk_band(
        current_risk
    )

    if prev_band != current_band:

        return {
            "thresholdCrossed": True,
            "fromBand": prev_band,
            "toBand": current_band
        }

    return {
        "thresholdCrossed": False,
        "fromBand": prev_band,
        "toBand": current_band
    }


# --------------------------------------------------
# VALID EXPERIMENT FILES
# --------------------------------------------------

def is_valid_experiment_file(filepath):

    filename = os.path.basename(
        filepath
    )

    skip_tags = [

        "_risk",

        "_relative",

        "_attack_aligned",

        "_transitions",

        "_risk_transitions"
    ]

    if any(
        tag in filename
        for tag in skip_tags
    ):
        return False

    if not filename.endswith(".json"):
        return False

    try:

        with open(filepath, "r") as f:

            data = json.load(f)

        return (
            isinstance(data, dict)
            and "results" in data
        )

    except:

        return False


# --------------------------------------------------
# CORE EXTRACTION
# --------------------------------------------------

def extract_risk_transitions(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    results = data.get(
        "results",
        []
    )

    if not results:
        return []

    # --------------------------------------------------
    # ATTACK ALIGNMENT
    # --------------------------------------------------

    attack_start_raw = (

        data.get(
            "attackStartEffective"
        )

        or

        data.get(
            "injectionStart"
        )
    )

    attack_start = parse_ts(
        attack_start_raw
    )

    # --------------------------------------------------
    # WINDOW CONFIG
    # --------------------------------------------------

    poll_interval_ms = (
        data.get(
            "pollIntervalMs"
        ) or 60000
    )

    window_minutes = (
        poll_interval_ms / 60000.0
    )

    # --------------------------------------------------
    # SORT CHRONOLOGICALLY
    # --------------------------------------------------

    results = sorted(

        results,

        key=lambda r: (
            r.get(
                "timestamp",
                ""
            )
        )
    )

    transitions = []

    prev_risk = None
    prev_ts = None

    # --------------------------------------------------
    # PROCESS ALL WINDOWS
    # --------------------------------------------------

    for idx, r in enumerate(results):

        ts_raw = r.get(
            "timestamp"
        )

        ts = parse_ts(
            ts_raw
        )

        if not ts:
            continue

        current_risk = extract_risk(r)

        phase = r.get(
            "phase"
        )

        state = r.get(
            "endState"
        )

        # --------------------------------------------------
        # TRUE ATTACK TIME
        # --------------------------------------------------

        attack_min = None

        if attack_start:

            attack_min = round(

                (
                    ts - attack_start
                ).total_seconds() / 60.0,

                2
            )

        # --------------------------------------------------
        # WINDOW INDEX
        # --------------------------------------------------

        window_index = idx

        observation_minute = round(
            window_index *
            window_minutes,
            3
        )

        # --------------------------------------------------
        # INITIALIZE
        # --------------------------------------------------

        if prev_risk is None:

            prev_risk = current_risk
            prev_ts = ts

            continue

        # --------------------------------------------------
        # DELTA
        # --------------------------------------------------

        delta = round(
            current_risk - prev_risk,
            2
        )

        abs_delta = abs(delta)

        # --------------------------------------------------
        # DURATION
        # --------------------------------------------------

        duration_sec = None

        if prev_ts:

            duration_sec = round(

                (
                    ts - prev_ts
                ).total_seconds(),

                2
            )

        # --------------------------------------------------
        # IGNORE RAPID OSCILLATIONS
        # --------------------------------------------------

        if (

            duration_sec is not None

            and

            duration_sec < MIN_DURATION_SEC
        ):

            continue

        # --------------------------------------------------
        # IGNORE IDENTICAL VALUES
        # --------------------------------------------------

        if abs_delta < MIN_RISK_DELTA:

            prev_risk = current_risk
            prev_ts = ts

            continue

        # --------------------------------------------------
        # DIRECTION
        # --------------------------------------------------

        direction = (
            "increase"
            if delta > 0
            else "decrease"
        )

        # --------------------------------------------------
        # THRESHOLD ANALYSIS
        # --------------------------------------------------

        threshold_info = (
            detect_threshold_crossing(
                prev_risk,
                current_risk
            )
        )

        # --------------------------------------------------
        # SAVE
        # --------------------------------------------------

        transitions.append({

            # ==========================================
            # TIME
            # ==========================================

            "timestamp":
                ts_raw,

            "attackMinute":
                attack_min,

            "windowIndex":
                window_index,

            "observationMinute":
                observation_minute,

            # ==========================================
            # RISK
            # ==========================================

            "fromRisk":
                round(prev_risk, 2),

            "toRisk":
                round(current_risk, 2),

            "deltaRisk":
                round(delta, 2),

            "absoluteDelta":
                round(abs_delta, 2),

            # ==========================================
            # DIRECTION
            # ==========================================

            "direction":
                direction,

            # ==========================================
            # THRESHOLD EVENTS
            # ==========================================

            "thresholdCrossed":
                threshold_info[
                    "thresholdCrossed"
                ],

            "fromBand":
                threshold_info[
                    "fromBand"
                ],

            "toBand":
                threshold_info[
                    "toBand"
                ],

            # ==========================================
            # CONTEXT
            # ==========================================

            "phase":
                phase,

            "state":
                state,

            "durationSincePreviousSec":
                duration_sec

        })

        prev_risk = current_risk
        prev_ts = ts

    return transitions


# --------------------------------------------------
# OUTPUT HELPERS
# --------------------------------------------------

def ensure_dirs():

    os.makedirs(
        BASE_OUTPUT,
        exist_ok=True
    )


def build_output_path(file_path):

    filename = (
        os.path.basename(file_path)
        .replace(
            ".json",
            "_risk_transitions.json"
        )
    )

    return os.path.join(
        BASE_OUTPUT,
        filename
    )


# --------------------------------------------------
# PROCESS FILE
# --------------------------------------------------

def process_file(file_path):

    print(
        f"\n📊 Processing: {os.path.basename(file_path)}"
    )

    transitions = extract_risk_transitions(
        file_path
    )

    out_path = build_output_path(
        file_path
    )

    with open(out_path, "w") as f:

        json.dump(
            transitions,
            f,
            indent=2
        )

    threshold_count = len([

        t for t in transitions

        if t.get(
            "thresholdCrossed"
        )
    ])

    print(
        f"🔥 Saved → {out_path}"
    )

    print(
        f"📈 Total risk transitions: {len(transitions)}"
    )

    print(
        f"🚨 Threshold crossings: {threshold_count}"
    )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    ensure_dirs()

    # --------------------------------------------------
    # SINGLE FILE MODE
    # --------------------------------------------------

    if len(sys.argv) > 1:

        file_path = sys.argv[1]

        if not os.path.exists(file_path):

            print(
                f"❌ File not found: {file_path}"
            )

            return

        process_file(file_path)

        return

    # --------------------------------------------------
    # BULK MODE
    # --------------------------------------------------

    if not os.path.exists(BASE_INPUT):

        print(
            f"❌ Missing input directory: {BASE_INPUT}"
        )

        return

    files = sorted(
        os.listdir(BASE_INPUT)
    )

    processed = 0

    for file in files:

        full_path = os.path.join(
            BASE_INPUT,
            file
        )

        if not is_valid_experiment_file(
            full_path
        ):
            continue

        process_file(full_path)

        processed += 1

    print("\n" + "=" * 60)

    print(
        f"✅ DONE — Processed {processed} experiment files"
    )

    print("=" * 60)


# --------------------------------------------------
# ENTRY
# --------------------------------------------------

if __name__ == "__main__":

    main()