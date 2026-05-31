#!/usr/bin/env python3

import json
import pandas as pd

from datetime import datetime
from pathlib import Path

# ============================================================
# CONFIG
# ============================================================

RUNS_DIR = Path(
    "../research/runsforpaper"
)

OUTPUT_DIR = Path(
    "./metrics_output"
)

OUTPUT_DIR.mkdir(
    exist_ok=True
)

# ============================================================
# HELPERS
# ============================================================

def parse_ts(ts):

    if not ts:
        return None

    try:
        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )

    except:
        return None


def overlaps(
    a_start,
    a_end,
    b_start,
    b_end
):

    if (
        not a_start
        or not a_end
        or not b_start
        or not b_end
    ):
        return False

    return (
        a_start < b_end
        and
        a_end > b_start
    )


def safe_div(a, b):

    if b == 0:
        return 0.0

    return a / b


# ============================================================
# FIND JSON FILES
# ============================================================

json_files = sorted(
    RUNS_DIR.glob("*.json")
)

print("\n================================================")
print("FOUND EXPERIMENT FILES")
print("================================================\n")

for jf in json_files:
    print(jf.name)

# ============================================================
# GLOBAL SUMMARY
# ============================================================

aggregate_rows = []

# ============================================================
# LOOP THROUGH FILES
# ============================================================

for experiment_json in json_files:

    print("\n================================================")
    print(f"PROCESSING: {experiment_json.name}")
    print("================================================\n")

    # ========================================================
    # LOAD JSON
    # ========================================================

    try:

        with open(
            experiment_json,
            "r"
        ) as f:

            experiment = json.load(f)

    except Exception as e:

        print(
            f"FAILED TO LOAD: {e}"
        )

        continue

    # ========================================================
    # METADATA
    # ========================================================

    injection_start = parse_ts(
        experiment.get(
            "injectionStart"
        )
    )

    injection_end = parse_ts(
        experiment.get(
            "injectionEnd"
        )
    )

    cooldown_start = parse_ts(
        experiment.get(
            "cooldownStart"
        )
    )

    cooldown_end = parse_ts(
        experiment.get(
            "cooldownEnd"
        )
    )

    # ========================================================
    # RESULTS
    # ========================================================

    windows = experiment.get(
        "results",
        []
    )

    if not windows:

        print(
            "NO RESULTS FOUND"
        )

        continue

    # ========================================================
    # PER-FILE STORAGE
    # ========================================================

    rows = []

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    window_id = 1

    # ========================================================
    # PROCESS WINDOWS
    # ========================================================

    for w in windows:

        start_ts = parse_ts(
            w.get("windowStart")
            or w.get("start")
            or w.get("timestamp")
        )

        end_ts = parse_ts(
            w.get("windowEnd")
            or w.get("end")
        )

        if not start_ts:
            continue

        if not end_ts:
            end_ts = start_ts

        # ====================================================
        # PHASE
        # ====================================================

        phase = "baseline"

        if overlaps(
            start_ts,
            end_ts,
            injection_start,
            injection_end
        ):

            phase = "injection"

        elif overlaps(
            start_ts,
            end_ts,
            cooldown_start,
            cooldown_end
        ):

            phase = "cooldown"

        # ====================================================
        # EXPECTED STATE
        # ====================================================

        expected_attack = (
            phase == "injection"
        )

        expected_state = (
            "critical"
            if expected_attack
            else "stable"
        )

        # ====================================================
        # OBSERVED
        # ====================================================

        observed_state = (
            str(
                w.get("state", "")
            )
            .strip()
            .lower()
        )

        risk_score = (
            w.get("riskScore0to100")
            or w.get("risk")
            or 0
        )

        dominant_attack = (
            w.get("dominantAttack")
            or "none"
        )

        confidence = (
            w.get("attackConfidence")
            or "unknown"
        )

        detected_attack = (
            w.get(
                "attackDetected",
                False
            )
            is True
        )

        # ====================================================
        # FALLBACK DETECTION
        # ====================================================

        if not detected_attack:

            detected_attack = (
                observed_state
                in [
                    "high",
                    "critical"
                ]
            )

        # ====================================================
        # CONFUSION MATRIX
        # ====================================================

        if expected_attack and detected_attack:
            tp += 1

        elif (
            not expected_attack
            and detected_attack
        ):
            fp += 1

        elif (
            expected_attack
            and not detected_attack
        ):
            fn += 1

        else:
            tn += 1

        # ====================================================
        # SAVE ROW
        # ====================================================

        rows.append({

            "windowId":
                window_id,

            "windowStart":
                start_ts.isoformat(),

            "windowEnd":
                end_ts.isoformat(),

            "phase":
                phase,

            "expectedState":
                expected_state,

            "observedState":
                observed_state,

            "riskScore":
                risk_score,

            "attackDetected":
                detected_attack,

            "dominantAttack":
                dominant_attack,

            "confidence":
                confidence
        })

        window_id += 1

    # ========================================================
    # DATAFRAME
    # ========================================================

    df = pd.DataFrame(rows)

    # ========================================================
    # METRICS
    # ========================================================

    precision = safe_div(
        tp,
        tp + fp
    )

    recall = safe_div(
        tp,
        tp + fn
    )

    accuracy = safe_div(
        tp + tn,
        tp + tn + fp + fn
    )

    specificity = safe_div(
        tn,
        tn + fp
    )

    f1 = safe_div(
        2 * precision * recall,
        precision + recall
    )

    balanced_accuracy = (
        recall + specificity
    ) / 2

    # ========================================================
    # SUMMARY
    # ========================================================

    summary = {

        "experiment":
            experiment_json.name,

        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,

        "precision":
            round(precision, 4),

        "recall":
            round(recall, 4),

        "specificity":
            round(specificity, 4),

        "accuracy":
            round(accuracy, 4),

        "balancedAccuracy":
            round(
                balanced_accuracy,
                4
            ),

        "f1":
            round(f1, 4),

        "totalWindows":
            len(df)
    }

    aggregate_rows.append(
        summary
    )

    # ========================================================
    # OUTPUT PATHS
    # ========================================================

    base_name = (
        experiment_json.stem
    )

    csv_path = (
        OUTPUT_DIR /
        f"{base_name}_window_metrics.csv"
    )

    summary_path = (
        OUTPUT_DIR /
        f"{base_name}_evaluation_summary.json"
    )

    confusion_path = (
        OUTPUT_DIR /
        f"{base_name}_confusion_matrix.json"
    )

    # ========================================================
    # SAVE CSV
    # ========================================================

    df.to_csv(
        csv_path,
        index=False
    )

    # ========================================================
    # SAVE SUMMARY
    # ========================================================

    with open(
        summary_path,
        "w"
    ) as f:

        json.dump(
            summary,
            f,
            indent=2
        )

    # ========================================================
    # SAVE CONFUSION
    # ========================================================

    confusion = {

        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn
    }

    with open(
        confusion_path,
        "w"
    ) as f:

        json.dump(
            confusion,
            f,
            indent=2
        )

    print(
        f"SAVED: {base_name}"
    )

# ============================================================
# AGGREGATE CSV
# ============================================================

aggregate_df = pd.DataFrame(
    aggregate_rows
)

aggregate_csv = (
    OUTPUT_DIR /
    "aggregate_summary.csv"
)

aggregate_df.to_csv(
    aggregate_csv,
    index=False
)

# ============================================================
# FINAL
# ============================================================

print("\n================================================")
print("COMPLETE")
print("================================================\n")

print(
    f"Processed: {len(aggregate_df)} experiments"
)

print(
    f"Aggregate Summary: {aggregate_csv}"
)

print()