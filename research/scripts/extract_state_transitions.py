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

# OUTPUT
BASE_OUTPUT = os.path.join(
    SCRIPT_DIR,
    "../extract/transitions"
)

# Ignore noisy rapid oscillations
MIN_STATE_DURATION_SEC = 5


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
# NORMALIZE STATES
# --------------------------------------------------

def normalize_state(state):

    if not state:
        return "unknown"

    return str(state).strip().lower()


# --------------------------------------------------
# SAFE RISK EXTRACTION
# --------------------------------------------------

def extract_risk_score(record):

    risk_score = None

    # Preferred modern structure
    if isinstance(
        record.get("core"),
        dict
    ):

        risk_score = (
            record["core"].get(
                "riskScore0to100"
            )
        )

    # Legacy direct field
    if risk_score is None:

        risk_score = record.get(
            "riskScore0to100"
        )

    # Older fallback
    if risk_score is None:

        risk_score = record.get(
            "riskScore"
        )

    # Ultimate safety fallback
    if risk_score is None:

        risk_score = 0

    return float(risk_score)


# --------------------------------------------------
# VALID EXPERIMENT FILES
# --------------------------------------------------

def is_valid_experiment_file(filepath):

    filename = os.path.basename(
        filepath
    )

    # Skip derived files
    skip_tags = [

        "_risk",

        "_relative",

        "_attack_aligned",

        "_transitions"
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

def extract_transitions(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    results = data.get(
        "results",
        []
    )

    if not results:
        return []

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

    prev_state = None
    prev_ts = None

    # --------------------------------------------------
    # PROCESS WINDOWS
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

        # --------------------------------------------------
        # CURRENT STATE
        # --------------------------------------------------

        state = normalize_state(
            r.get("endState")
        )

        phase = r.get("phase")

        # --------------------------------------------------
        # SAFE RISK EXTRACTION
        # --------------------------------------------------

        risk_score = extract_risk_score(
            r
        )

        # --------------------------------------------------
        # OBSERVATION TIMELINE
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

        if prev_state is None:

            prev_state = state
            prev_ts = ts

            # ==============================================
            # IMPORTANT:
            # SAVE INITIAL BASELINE STATE
            # ==============================================

            transitions.append({

                "timestamp":
                    ts_raw,

                "windowIndex":
                    window_index,

                "observationMinute":
                    observation_minute,

                "from":
                    state,

                "to":
                    state,

                "phase":
                    phase,

                "riskScore0to100":
                    risk_score,

                "durationInPreviousStateSec":
                    0

            })

            continue

        # --------------------------------------------------
        # DETECT TRANSITION
        # --------------------------------------------------

        if state != prev_state:

            duration_sec = None

            if prev_ts:

                duration_sec = round(

                    (
                        ts - prev_ts
                    ).total_seconds(),

                    2
                )

            # --------------------------------------------------
            # FILTER NOISY FLIPS
            # --------------------------------------------------

            if (

                duration_sec is not None

                and

                duration_sec < MIN_STATE_DURATION_SEC
            ):

                continue

            # --------------------------------------------------
            # SAVE TRANSITION
            # --------------------------------------------------

            transitions.append({

                "timestamp":
                    ts_raw,

                "windowIndex":
                    window_index,

                "observationMinute":
                    observation_minute,

                "from":
                    prev_state,

                "to":
                    state,

                "phase":
                    phase,

                "riskScore0to100":
                    risk_score,

                "durationInPreviousStateSec":
                    duration_sec

            })

            prev_state = state
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
            "_transitions.json"
        )
    )

    return os.path.join(
        BASE_OUTPUT,
        filename
    )


# --------------------------------------------------
# PROCESS SINGLE FILE
# --------------------------------------------------

def process_file(file_path):

    print(
        f"\n📊 Processing: {os.path.basename(file_path)}"
    )

    transitions = extract_transitions(
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

    print(
        f"✅ Saved → {out_path}"
    )

    print(
        f"📈 Total transitions: {len(transitions)}"
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