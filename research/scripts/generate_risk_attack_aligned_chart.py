import json
import sys
import os
from datetime import datetime


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
# RISK EXTRACTION
# --------------------------------------------------

def extract_risk(record):

    risk = None

    # --------------------------------------------------
    # PRIMARY LOCATION
    # --------------------------------------------------

    if isinstance(
        record.get("core"),
        dict
    ):

        risk = record["core"].get(
            "riskScore0to100"
        )

    # --------------------------------------------------
    # FALLBACK
    # --------------------------------------------------

    if risk is None:

        risk = record.get(
            "riskScore"
        )

    # --------------------------------------------------
    # FINAL SAFETY
    # --------------------------------------------------

    if risk is None:

        risk = 0

    return float(risk)


# --------------------------------------------------
# FALLBACK ATTACK START
# --------------------------------------------------

def find_attack_start_fallback(results):

    for r in results:

        if not isinstance(r, dict):
            continue

        phase = (
            r.get("phase") or ""
        ).lower()

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


# --------------------------------------------------
# MAIN EXTRACTION
# --------------------------------------------------

def extract_attack_aligned(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    # --------------------------------------------------
    # SAFETY
    # --------------------------------------------------

    if not isinstance(data, dict):

        print(
            f"⚠️ Expected experiment JSON object: {file_path}"
        )

        return None

    results = data.get(
        "results",
        []
    )

    if not results:

        print(
            f"⚠️ Empty results: {file_path}"
        )

        return None

    # --------------------------------------------------
    # TIMESTAMPS
    # --------------------------------------------------

    attack_start_ts = parse_ts(
        data.get(
            "attackStartEffective"
        )
    )

    injection_start_ts = parse_ts(
        data.get(
            "injectionStart"
        )
    )

    injection_end_ts = parse_ts(
        data.get(
            "injectionEnd"
        )
    )

    # --------------------------------------------------
    # FALLBACKS
    # --------------------------------------------------

    if not attack_start_ts:

        attack_start_ts = (
            find_attack_start_fallback(
                results
            )
        )

    if not attack_start_ts:

        print(
            f"⚠️ Missing attack start: {file_path}"
        )

        return None

    if not injection_start_ts:

        injection_start_ts = (
            attack_start_ts
        )

    if not injection_end_ts:

        injection_end_ts = parse_ts(
            results[-1].get(
                "timestamp"
            )
        )

    # --------------------------------------------------
    # POLL INTERVAL
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
    # TOTAL EVALUATIONS
    # --------------------------------------------------

    total_evaluations = len(results)

    # --------------------------------------------------
    # BUILD TIMELINE
    # --------------------------------------------------

    timeline = []

    for idx, r in enumerate(results):

        if not isinstance(r, dict):
            continue

        ts_raw = r.get(
            "timestamp"
        )

        ts = parse_ts(
            ts_raw
        )

        if not ts:
            continue

        # --------------------------------------------------
        # TRUE ATTACK RELATIVE TIME
        # --------------------------------------------------

        t_attack_min = round(

            (
                ts - attack_start_ts
            ).total_seconds() / 60.0,

            3
        )

        # --------------------------------------------------
        # WINDOW POSITION
        # --------------------------------------------------

        observation_minute = round(
            idx * window_minutes,
            3
        )

        # --------------------------------------------------
        # RISK
        # --------------------------------------------------

        risk_score = extract_risk(r)

        # --------------------------------------------------
        # APPEND
        # --------------------------------------------------

        timeline.append({

            # ==========================================
            # PRIMARY AXIS
            # ==========================================

            "window_index":
                idx,

            "observation_minute":
                observation_minute,

            # ==========================================
            # TRUE REPLAY TIME
            # ==========================================

            "t_attack_min":
                t_attack_min,

            # ==========================================
            # RISK
            # ==========================================

            "riskScore":
                risk_score,

            # ==========================================
            # LABELS
            # ==========================================

            "phase":
                r.get("phase"),

            "timestamp":
                ts_raw,

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

            "state":
                r.get(
                    "endState"
                ),

            "riskLevel":
                r.get(
                    "riskLevel"
                )
        })

    # --------------------------------------------------
    # SORT TIMELINE
    # --------------------------------------------------

    timeline = sorted(

        timeline,

        key=lambda x: x.get(
            "window_index",
            0
        )
    )

    # --------------------------------------------------
    # PHASE BOUNDARIES
    # --------------------------------------------------

    injection_start_min = round(

        (
            injection_start_ts
            - attack_start_ts
        ).total_seconds() / 60.0,

        3
    )

    injection_end_min = round(

        (
            injection_end_ts
            - attack_start_ts
        ).total_seconds() / 60.0,

        3
    )

    # --------------------------------------------------
    # WINDOW-BASED ALIGNMENT
    # --------------------------------------------------

    injection_start_window = round(
        injection_start_min /
        window_minutes,
        3
    )

    injection_end_window = round(
        injection_end_min /
        window_minutes,
        3
    )

    # --------------------------------------------------
    # GLOBAL AXIS FIX
    # --------------------------------------------------

    global_x_max = max(
        0,
        total_evaluations - 1
    )

    # --------------------------------------------------
    # OUTPUT STRUCTURE
    # --------------------------------------------------

    result = {

        "metadata": {

            # ------------------------------------------
            # SOURCE
            # ------------------------------------------

            "source_file":
                os.path.basename(
                    file_path
                ),

            "runId":
                data.get("runId"),

            "truthMode":
                data.get(
                    "truthMode"
                ),

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
            # EXPERIMENT WINDOWS
            # ------------------------------------------

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
            # WINDOW MODEL
            # ------------------------------------------

            "window_minutes":
                window_minutes,

            "x_axis_meaning":
                "1-minute observation windows",

            # ------------------------------------------
            # ATTACK ALIGNMENT
            # ------------------------------------------

            "attack_start_min":
                0.0,

            "injection_start_min":
                injection_start_min,

            "injection_end_min":
                injection_end_min,

            # ------------------------------------------
            # WINDOW ALIGNMENT
            # ------------------------------------------

            "injection_start_window":
                injection_start_window,

            "injection_end_window":
                injection_end_window,

            # ------------------------------------------
            # COUNTS
            # ------------------------------------------

            "total_points":
                len(timeline),

            "total_evaluations":
                total_evaluations,

            # ------------------------------------------
            # GLOBAL AXIS LOCK
            # ------------------------------------------

            "global_x_max":
                global_x_max
        },

        "timeline":
            timeline
    }

    return result


# --------------------------------------------------
# SAVE OUTPUT
# --------------------------------------------------

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python extract_risk_timeline_attack_aligned.py <experiment_json>"
        )

        return

    file_path = sys.argv[1]

    result = extract_attack_aligned(
        file_path
    )

    if not result:
        return

    # --------------------------------------------------
    # OUTPUT DIR
    # --------------------------------------------------

    script_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    extract_root = os.path.join(
        script_dir,
        "../extract"
    )

    out_dir = os.path.join(
        extract_root,
        "risk_attack_aligned"
    )

    os.makedirs(
        out_dir,
        exist_ok=True
    )

    # --------------------------------------------------
    # OUTPUT FILE
    # --------------------------------------------------

    filename = (
        os.path.basename(file_path)
        .replace(
            ".json",
            "_attack_aligned.json"
        )
    )

    out_path = os.path.join(
        out_dir,
        filename
    )

    # --------------------------------------------------
    # SAVE
    # --------------------------------------------------

    with open(out_path, "w") as f:

        json.dump(
            result,
            f,
            indent=2
        )

    print(
        f"🔥 Attack-aligned timeline saved → {out_path}"
    )

    print(
        f"📊 Total evaluations: {result['metadata']['total_evaluations']}"
    )

    print(
        f"📏 Global X max: {result['metadata']['global_x_max']}"
    )


# --------------------------------------------------
# ENTRY
# --------------------------------------------------

if __name__ == "__main__":

    main()