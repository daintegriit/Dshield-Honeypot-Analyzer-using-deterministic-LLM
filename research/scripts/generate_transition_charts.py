#!/usr/bin/env python3

import os
import json

from datetime import datetime

import matplotlib.pyplot as plt

from matplotlib.ticker import MultipleLocator


# --------------------------------------------------
# CONFIG
# --------------------------------------------------

TRANSITION_DIR = "../extract/transitions"

OUTPUT_DIR = "../extract/charts/transitions"

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)

# --------------------------------------------------
# GLOBAL AXIS LOCK
# FORCE CONSISTENCY ACROSS ALL EXPERIMENTS
# --------------------------------------------------

GLOBAL_X_MAX = 210

# --------------------------------------------------
# GLOBAL PHASE WINDOWS
# --------------------------------------------------

GLOBAL_BASELINE_END = 60
GLOBAL_INJECTION_END = 150
GLOBAL_COOLDOWN_END = 210

# --------------------------------------------------
# GLOBAL FIGURE SIZE
# STANDARDIZED ACROSS ALL PAPER CHARTS
# --------------------------------------------------

FIG_WIDTH = 20
FIG_HEIGHT = 7


# --------------------------------------------------
# STATE MAP
# --------------------------------------------------

STATE_MAP = {

    "stable": 0,

    "elevated": 1,

    "high": 2,

    "critical": 3
}


# --------------------------------------------------
# STATE COLORS
# --------------------------------------------------

STATE_COLORS = {

    "stable": "green",

    "elevated": "gold",

    "high": "orange",

    "critical": "red"
}


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def parse_time(ts):

    if not ts:
        return None

    try:

        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )

    except:

        return None


# --------------------------------------------------
# TRANSITION CHART
# --------------------------------------------------

def plot_transitions(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    if not data:

        print(
            f"⚠️ Empty transitions: {file_path}"
        )

        return

    # --------------------------------------------------
    # SORT USING OBSERVATION WINDOWS
    # --------------------------------------------------

    data = sorted(
        data,
        key=lambda x: (
            x.get(
                "observationMinute",
                0
            )
            if x.get(
                "observationMinute"
            ) is not None
            else 0
        )
    )

    # --------------------------------------------------
    # BUILD SERIES
    # --------------------------------------------------

    x = []

    y = []

    state_labels = []

    colors = []

    risks = []

    durations = []

    for d in data:

        observation_min = d.get(
            "observationMinute"
        )

        # Fallback
        if observation_min is None:

            observation_min = d.get(
                "windowIndex"
            )

        if observation_min is None:
            continue

        state = (
            d.get("to", "stable")
            .strip()
            .lower()
        )

        x.append(
            float(observation_min)
        )

        y.append(
            STATE_MAP.get(
                state,
                0
            )
        )

        state_labels.append(
            state
        )

        colors.append(
            STATE_COLORS.get(
                state,
                "gray"
            )
        )

        risks.append(
            d.get(
                "riskScore0to100",
                0
            )
        )

        durations.append(
            d.get(
                "durationInPreviousStateSec",
                0
            )
        )

    if not x:

        print(
            f"⚠️ No valid transitions in {file_path}"
        )

        return

    # --------------------------------------------------
    # ADD BASELINE ANCHOR
    # --------------------------------------------------

    if min(x) > 0:

        x.insert(
            0,
            0
        )

        y.insert(
            0,
            y[0]
        )

        state_labels.insert(
            0,
            state_labels[0]
        )

        colors.insert(
            0,
            "gray"
        )

        risks.insert(
            0,
            risks[0]
        )

        durations.insert(
            0,
            0
        )

    # --------------------------------------------------
    # FIGURE
    # --------------------------------------------------

    fig, ax = plt.subplots(
        figsize=(
            FIG_WIDTH,
            FIG_HEIGHT
        )
    )

    # --------------------------------------------------
    # PHASE SHADING
    # --------------------------------------------------

    ax.axvspan(
        0,
        GLOBAL_BASELINE_END,
        color="gray",
        alpha=0.08
    )

    ax.axvspan(
        GLOBAL_BASELINE_END,
        GLOBAL_INJECTION_END,
        color="red",
        alpha=0.05
    )

    ax.axvspan(
        GLOBAL_INJECTION_END,
        GLOBAL_COOLDOWN_END,
        color="blue",
        alpha=0.05
    )

    # --------------------------------------------------
    # STEP LINE
    # --------------------------------------------------

    ax.step(
        x,
        y,
        where="post",
        linewidth=2,
        alpha=0.75,
        color="black",
        zorder=1
    )

    # --------------------------------------------------
    # COLOR POINTS
    # --------------------------------------------------

    ax.scatter(

        x,
        y,

        c=colors,

        s=[
            max(
                40,
                (
                    r if r is not None else 0
                ) * 1.5
            )
            for r in risks
        ],

        alpha=0.95,

        edgecolors="black",

        linewidths=0.5,

        zorder=5
    )

    # --------------------------------------------------
    # SMART LABEL PLACEMENT
    # --------------------------------------------------

    previous_y = None

    for i in range(len(x)):

        y_offset = 0.08

        if previous_y is not None:

            if abs(y[i] - previous_y) < 0.25:

                y_offset = 0.18

        ax.text(

            x[i],

            y[i] + y_offset,

            f"{state_labels[i]}",

            fontsize=7,

            ha="center",

            alpha=0.90,

            bbox=dict(
                facecolor="white",
                alpha=0.75,
                edgecolor="none",
                pad=0.2
            ),

            zorder=10
        )

        previous_y = y[i]

    # --------------------------------------------------
    # IMPORTANT PHASE LINES
    # --------------------------------------------------

    ax.axvline(
        x=GLOBAL_BASELINE_END,
        linestyle="--",
        linewidth=2,
        color="red",
        alpha=0.85
    )

    ax.axvline(
        x=GLOBAL_INJECTION_END,
        linestyle="--",
        linewidth=2,
        color="blue",
        alpha=0.85
    )

    # --------------------------------------------------
    # PHASE LABELS
    # --------------------------------------------------

    ax.text(
        GLOBAL_BASELINE_END / 2,
        3.25,
        "Baseline",
        fontsize=9,
        ha="center"
    )

    ax.text(
        (
            GLOBAL_BASELINE_END
            +
            GLOBAL_INJECTION_END
        ) / 2,
        3.25,
        "Injection / Attack",
        fontsize=9,
        ha="center"
    )

    ax.text(
        (
            GLOBAL_INJECTION_END
            +
            GLOBAL_COOLDOWN_END
        ) / 2,
        3.25,
        "Cooldown",
        fontsize=9,
        ha="center"
    )

    # --------------------------------------------------
    # Y AXIS
    # --------------------------------------------------

    ax.set_yticks(
        [0, 1, 2, 3]
    )

    ax.set_yticklabels([
        "stable",
        "elevated",
        "high",
        "critical"
    ])

    # --------------------------------------------------
    # X AXIS CONTROL
    # --------------------------------------------------

    ax.xaxis.set_major_locator(
        MultipleLocator(10)
    )

    ax.xaxis.set_minor_locator(
        MultipleLocator(1)
    )

    ax.tick_params(
        axis="x",
        which="major",
        labelsize=8
    )

    ax.tick_params(
        axis="x",
        which="minor",
        length=2
    )

    # --------------------------------------------------
    # GRID
    # --------------------------------------------------

    ax.grid(
        which="major",
        alpha=0.30
    )

    ax.grid(
        which="minor",
        alpha=0.08
    )

    # --------------------------------------------------
    # TRUE GLOBAL LIMITS
    # --------------------------------------------------

    ax.set_xlim(
        0,
        GLOBAL_X_MAX
    )

    ax.set_ylim(
        -0.3,
        3.5
    )

    # --------------------------------------------------
    # REMOVE AUTO PADDING
    # --------------------------------------------------

    ax.margins(
        x=0,
        y=0
    )

    # --------------------------------------------------
    # LABELS
    # --------------------------------------------------

    filename_only = os.path.basename(
        file_path
    )

    ax.set_title(
        f"Security State Transitions\n{filename_only}",
        fontsize=14
    )

    ax.set_xlabel(
        "Experiment Timeline (1-Minute Observation Windows)",
        fontsize=11
    )

    ax.set_ylabel(
        "Security State",
        fontsize=11
    )

    # --------------------------------------------------
    # LAYOUT
    # --------------------------------------------------

    plt.tight_layout(
        pad=0.4
    )

    fig.subplots_adjust(
        top=0.92,
        bottom=0.16,
        left=0.06,
        right=0.99
    )

    # --------------------------------------------------
    # SAVE
    # --------------------------------------------------

    filename = (
        os.path.basename(file_path)
        .replace(
            "_transitions.json",
            "_transitions.png"
        )
    )

    out_path = os.path.join(
        OUTPUT_DIR,
        filename
    )

    plt.savefig(
        out_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"🔵 Saved → {out_path}"
    )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def run_all():

    if not os.path.exists(
        TRANSITION_DIR
    ):

        print(
            f"❌ Missing directory: {TRANSITION_DIR}"
        )

        return

    files = sorted(
        os.listdir(
            TRANSITION_DIR
        )
    )

    processed = 0

    for file in files:

        if file.endswith(
            "_transitions.json"
        ):

            plot_transitions(

                os.path.join(
                    TRANSITION_DIR,
                    file
                )
            )

            processed += 1

    print("\n" + "=" * 60)

    print(
        f"✅ DONE — Generated {processed} transition charts"
    )

    print("=" * 60)


# --------------------------------------------------
# ENTRY
# --------------------------------------------------

if __name__ == "__main__":

    run_all()