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

    if (
        "core" in record and
        isinstance(record["core"], dict)
    ):

        risk = record["core"].get(
            "riskScore0to100"
        )

    if risk is None:
        risk = record.get("riskScore")

    if risk is None:
        risk = 0

    return float(risk)


# ==================================================
# FALLBACK ATTACK START
# ==================================================

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


# ==================================================
# MAIN EXTRACTION
# ==================================================

def extract_attack_aligned(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    # --------------------------------------------------
    # EXPECT EXPERIMENT JSON OBJECT
    # --------------------------------------------------

    if isinstance(data, dict):

        results = data.get(
            "results",
            []
        )

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

        poll_interval_ms = (
            data.get(
                "pollIntervalMs"
            ) or 60000
        )

    elif isinstance(data, list):

        # legacy fallback

        results = data

        attack_start_ts = None
        injection_start_ts = None
        injection_end_ts = None

        poll_interval_ms = 60000

    else:

        print(
            f"⚠️ Unknown JSON format: {file_path}"
        )

        return None

    if not results:

        print(
            f"⚠️ Empty results: {file_path}"
        )

        return None

    # --------------------------------------------------
    # TRUE ATTACK START
    # --------------------------------------------------

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

    # --------------------------------------------------
    # ALIGNMENT FIX
    # --------------------------------------------------

    if not injection_start_ts:

        injection_start_ts = (
            attack_start_ts
        )

    # ==================================================
    # WINDOW CONFIG
    # ==================================================

    window_minutes = (
        poll_interval_ms / 60000.0
    )

    # ==================================================
    # HARD LIMIT
    # ==================================================

    total_evaluations = len(results)

    # ==================================================
    # BUILD TIMELINE
    # ==================================================

    timeline = []

    for idx, r in enumerate(results):

        if not isinstance(r, dict):
            continue

        ts = parse_ts(
            r.get("timestamp")
        )

        if not ts:
            continue

        # ----------------------------------------------
        # TRUE REPLAY TIME
        # ----------------------------------------------

        t_attack_min = (
            ts - attack_start_ts
        ).total_seconds() / 60.0

        # ----------------------------------------------
        # WINDOW INDEX
        # ----------------------------------------------

        window_index = idx

        # ----------------------------------------------
        # HARD CLAMP
        # prevents fake 220/230 windows
        # ----------------------------------------------

        if window_index >= total_evaluations:
            continue

        # ----------------------------------------------
        # OBSERVATION WINDOW
        # ----------------------------------------------

        observation_minute = (
            window_index *
            window_minutes
        )

        timeline.append({

            # ==========================================
            # PRIMARY X AXIS
            # ==========================================

            "window_index":
                window_index,

            "observation_minute":
                round(
                    observation_minute,
                    3
                ),

            # ==========================================
            # TRUE REPLAY TIME
            # ==========================================

            "t_attack_min":
                round(
                    t_attack_min,
                    3
                ),

            # ==========================================
            # RISK
            # ==========================================

            "riskScore":
                extract_risk(r),

            # ==========================================
            # PHASE / LABELS
            # ==========================================

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

            # ==========================================
            # TIMESTAMP
            # ==========================================

            "timestamp":
                r.get("timestamp"),
        })

    # ==================================================
    # SORT BY WINDOW INDEX
    # ==================================================

    timeline = sorted(
        timeline,
        key=lambda x: x["window_index"]
    )

    # ==================================================
    # METADATA
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
    # WINDOW BOUNDARIES
    # ==================================================

    injection_start_window = (
        injection_start_min /
        window_minutes
    )

    injection_end_window = None

    if injection_end_min is not None:

        injection_end_window = (
            injection_end_min /
            window_minutes
        )

    # ==================================================
    # GLOBAL AXIS MAX
    # ==================================================

    global_x_max = max(
        0,
        total_evaluations - 1
    )

    # ==================================================
    # OUTPUT
    # ==================================================

    output = {

        "metadata": {

            # ==========================================
            # FILE
            # ==========================================

            "source_file":
                os.path.basename(
                    file_path
                ),

            "runId":
                data.get("runId")
                if isinstance(data, dict)
                else None,

            # ==========================================
            # TIMING
            # ==========================================

            "attackStartEffective":
                data.get(
                    "attackStartEffective"
                )
                if isinstance(data, dict)
                else None,

            "injectionStart":
                data.get(
                    "injectionStart"
                )
                if isinstance(data, dict)
                else None,

            "injectionEnd":
                data.get(
                    "injectionEnd"
                )
                if isinstance(data, dict)
                else None,

            "truthMode":
                data.get(
                    "truthMode"
                )
                if isinstance(data, dict)
                else None,

            # ==========================================
            # EXPERIMENT SETTINGS
            # ==========================================

            "baselineSeconds":
                data.get(
                    "baselineSeconds"
                )
                if isinstance(data, dict)
                else None,

            "preCooldownSeconds":
                data.get(
                    "preCooldownSeconds"
                )
                if isinstance(data, dict)
                else None,

            "cooldownSeconds":
                data.get(
                    "cooldownSeconds"
                )
                if isinstance(data, dict)
                else None,

            "pollIntervalMs":
                poll_interval_ms,

            # ==========================================
            # WINDOW MODEL
            # ==========================================

            "window_minutes":
                window_minutes,

            "x_axis_meaning":
                "1-minute observation windows",

            # ==========================================
            # ATTACK ALIGNMENT
            # ==========================================

            "attack_start_min":
                0.0,

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

            # ==========================================
            # WINDOW ALIGNMENT
            # ==========================================

            "injection_start_window":
                round(
                    injection_start_window,
                    3
                ),

            "injection_end_window":
                round(
                    injection_end_window,
                    3
                )
                if injection_end_window
                is not None
                else None,

            # ==========================================
            # COUNTS
            # ==========================================

            "total_points":
                len(timeline),

            "total_evaluations":
                total_evaluations,

            # ==========================================
            # GLOBAL AXIS LOCK
            # ==========================================

            "global_x_max":
                global_x_max,
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
            "Usage: python extract_risk_timeline_attack_aligned.py <file>"
        )

        return

    file_path = sys.argv[1]

    output = extract_attack_aligned(
        file_path
    )

    if not output:
        return

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

    with open(out_path, "w") as f:

        json.dump(
            output,
            f,
            indent=2
        )

    print(
        f"🔥 Attack-aligned timeline saved → {out_path}"
    )

    print(
        f"📊 Total evaluations: {len(output['timeline'])}"
    )

    print(
        f"📏 Global X max: {output['metadata']['global_x_max']}"
    )


# ==================================================
# ENTRY
# ==================================================

if __name__ == "__main__":

    main()