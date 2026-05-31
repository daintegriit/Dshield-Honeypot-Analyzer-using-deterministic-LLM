import json
import sys
import os
from datetime import datetime


# ==================================================
# SAFE TIMESTAMP PARSER
# ==================================================

def parse_ts(ts):

    if not ts:
        return None

    try:

        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )

    except Exception:

        return None


# ==================================================
# SAFE RISK EXTRACTION
# ==================================================

def extract_risk(record):

    risk = None

    # ----------------------------------------------
    # core.riskScore0to100
    # ----------------------------------------------

    if (
        "core" in record and
        isinstance(record["core"], dict)
    ):

        risk = record["core"].get(
            "riskScore0to100"
        )

    # ----------------------------------------------
    # fallback
    # ----------------------------------------------

    if risk is None:
        risk = record.get("riskScore")

    # ----------------------------------------------
    # default
    # ----------------------------------------------

    if risk is None:
        risk = 0

    return risk


# ==================================================
# FALLBACK ATTACK START
# ==================================================

def find_attack_start_fallback(results):

    for r in results:

        if not isinstance(r, dict):
            continue

        phase = r.get("phase")

        if phase in (
            "attack",
            "injection"
        ):

            ts = parse_ts(
                r.get("timestamp")
            )

            if ts:
                return ts

    return None


# ==================================================
# MAIN EXTRACTION
# ==================================================

def extract_custom_timeline(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    # ==================================================
    # VALIDATION
    # ==================================================

    if not isinstance(data, dict):

        print(
            f"⚠️ Invalid experiment file: {file_path}"
        )

        return None

    results = data.get("results", [])

    if not results:

        print(
            f"⚠️ Empty results: {file_path}"
        )

        return None

    # ==================================================
    # TIMING
    # ==================================================

    attack_start_ts = parse_ts(
        data.get("attackStartEffective")
    )

    injection_start_ts = parse_ts(
        data.get("injectionStart")
    )

    injection_end_ts = parse_ts(
        data.get("injectionEnd")
    )

    if not attack_start_ts:

        attack_start_ts = (
            find_attack_start_fallback(
                results
            )
        )

    if not attack_start_ts:

        print(
            f"⚠️ No attack start found: {file_path}"
        )

        return None

    # ==================================================
    # ALIGNMENT
    # ==================================================

    if not injection_start_ts:

        injection_start_ts = (
            attack_start_ts
        )

    # ==================================================
    # POLLING CONFIG
    # ==================================================

    poll_interval_ms = (
        data.get(
            "pollIntervalMs"
        ) or 60000
    )

    window_minutes = (
        poll_interval_ms / 60000.0
    )

    # ==================================================
    # TIMELINE
    # ==================================================

    timeline = []

    for r in results:

        if not isinstance(r, dict):
            continue

        ts = parse_ts(
            r.get("timestamp")
        )

        if not ts:
            continue

        # ==============================================
        # TRUE CONTINUOUS TIME
        # ==============================================

        t_attack_min = (
            ts - attack_start_ts
        ).total_seconds() / 60.0

        # ==============================================
        # INTEGER MINUTE BUCKET
        # ==============================================

        minute_index = int(
            round(t_attack_min)
        )

        # ==============================================
        # TIMELINE ENTRY
        # ==============================================

        timeline.append({

            # ------------------------------------------
            # PRIMARY X-AXIS
            # ------------------------------------------

            "minute_index":
                minute_index,

            # ------------------------------------------
            # TRUE TIME
            # ------------------------------------------

            "t_attack_min":
                round(
                    t_attack_min,
                    3
                ),

            # ------------------------------------------
            # RISK
            # ------------------------------------------

            "riskScore":
                extract_risk(r),

            # ------------------------------------------
            # STATE
            # ------------------------------------------

            "phase":
                r.get("phase"),

            "truth":
                r.get("truth"),

            "experimentPredicted":
                r.get(
                    "experimentPredicted"
                ),

            "rawPredicted":
                r.get(
                    "rawPredicted"
                ),

            # ------------------------------------------
            # TIMESTAMP
            # ------------------------------------------

            "timestamp":
                r.get("timestamp"),
        })

    # ==================================================
    # SORT
    # ==================================================

    timeline = sorted(
        timeline,
        key=lambda x: x["minute_index"]
    )

    # ==================================================
    # ATTACK WINDOW
    # ==================================================

    injection_start_min = (
        injection_start_ts -
        attack_start_ts
    ).total_seconds() / 60.0

    injection_end_min = None

    if injection_end_ts:

        injection_end_min = (
            injection_end_ts -
            attack_start_ts
        ).total_seconds() / 60.0

    # ==================================================
    # OUTPUT
    # ==================================================

    output = {

        "metadata": {

            # ------------------------------------------
            # FILE
            # ------------------------------------------

            "source_file":
                os.path.basename(
                    file_path
                ),

            "runId":
                data.get("runId"),

            # ------------------------------------------
            # TIMING
            # ------------------------------------------

            "attackStartEffective":
                data.get(
                    "attackStartEffective"
                ),

            "injectionStart":
                data.get(
                    "injectionStart"
                ),

            "injectionEnd":
                data.get(
                    "injectionEnd"
                ),

            # ------------------------------------------
            # EXPERIMENT
            # ------------------------------------------

            "truthMode":
                data.get("truthMode"),

            "baselineSeconds":
                data.get(
                    "baselineSeconds"
                ),

            "preCooldownSeconds":
                data.get(
                    "preCooldownSeconds"
                ),

            "cooldownSeconds":
                data.get(
                    "cooldownSeconds"
                ),

            "pollIntervalMs":
                poll_interval_ms,

            # ------------------------------------------
            # AXIS MODEL
            # ------------------------------------------

            "window_minutes":
                window_minutes,

            "x_axis":
                "minute_index",

            "x_axis_description":
                "Integer minute buckets aligned to attack start",

            # ------------------------------------------
            # ATTACK ALIGNMENT
            # ------------------------------------------

            "attack_start_min":
                0,

            "injection_start_min":
                round(
                    injection_start_min,
                    3
                ),

            "injection_end_min":
                round(
                    injection_end_min,
                    3
                )
                if injection_end_min
                is not None
                else None,

            # ------------------------------------------
            # COUNTS
            # ------------------------------------------

            "total_points":
                len(timeline),
        },

        "timeline":
            timeline,
    }

    return output


# ==================================================
# SAVE OUTPUT
# ==================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python extract_risk_custom.py <experiment_json>"
        )

        return

    file_path = sys.argv[1]

    output = extract_custom_timeline(
        file_path
    )

    if not output:
        return

    # ==================================================
    # OUTPUT DIRECTORY
    # ==================================================

    script_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    extract_root = os.path.join(
        script_dir,
        "../extract"
    )

    out_dir = os.path.join(
        extract_root,
        "risk_custom"
    )

    os.makedirs(
        out_dir,
        exist_ok=True
    )

    # ==================================================
    # OUTPUT FILE
    # ==================================================

    filename = (
        os.path.basename(file_path)
        .replace(
            ".json",
            "_risk_custom.json"
        )
    )

    out_path = os.path.join(
        out_dir,
        filename
    )

    with open(out_path, "w") as f:

        json.dump(
            output,
            f,
            indent=2
        )

    print(
        f"🔥 Custom risk timeline saved → {out_path}"
    )


# ==================================================
# ENTRY
# ==================================================

if __name__ == "__main__":

    main()