#!/usr/bin/env python3

import os
import json

import matplotlib.pyplot as plt

from matplotlib.ticker import MultipleLocator


# --------------------------------------------------
# CONFIG
# --------------------------------------------------

SCRIPT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

INPUT_DIR = os.path.join(
    SCRIPT_DIR,
    "../extract/risk_transitions"
)

OUTPUT_DIR = os.path.join(
    SCRIPT_DIR,
    "../extract/charts/risk_transitions"
)

os.makedirs(
    OUTPUT_DIR,
    exist_ok=True
)


# --------------------------------------------------
# GLOBAL X-AXIS
# FORCE CONSISTENCY ACROSS ALL CHARTS
# --------------------------------------------------

GLOBAL_X_MAX = 210


# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def get_color(direction):

    if direction == "increase":
        return "red"

    if direction == "decrease":
        return "green"

    return "gray"


# --------------------------------------------------
# MAIN CHART
# --------------------------------------------------

def plot_risk_transitions(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    if not data:

        print(
            f"⚠️ Empty transition file: {file_path}"
        )

        return

    # --------------------------------------------------
    # SORT
    # --------------------------------------------------

    data = sorted(
        data,
        key=lambda x: x.get(
            "attackMinute",
            0
        )
    )

    # --------------------------------------------------
    # EXTRACT ORIGINAL
    # --------------------------------------------------

    original_x = []

    y = []

    colors = []

    labels = []

    for d in data:

        attack_min = d.get(
            "attackMinute"
        )

        to_risk = d.get(
            "toRisk"
        )

        direction = d.get(
            "direction"
        )

        delta = d.get(
            "deltaRisk"
        )

        if (
            attack_min is None
            or
            to_risk is None
        ):
            continue

        original_x.append(
            float(attack_min)
        )

        y.append(
            float(to_risk)
        )

        colors.append(
            get_color(direction)
        )

        labels.append(
            f"{delta:+.0f}"
        )

    if not original_x:

        print(
            f"⚠️ No plottable transitions: {file_path}"
        )

        return

    # --------------------------------------------------
    # SHIFT TIMELINE
    # MATCH ATTACK-ALIGNED VIEW
    # --------------------------------------------------

    baseline_shift = abs(
        min(original_x)
    )

    x = [
        v + baseline_shift
        for v in original_x
    ]

    attack_start = baseline_shift

    # --------------------------------------------------
    # ADD TRUE ORIGIN ANCHOR
    # --------------------------------------------------

    if x[0] > 0:

        initial_risk = y[0]

        x.insert(
            0,
            0
        )

        y.insert(
            0,
            initial_risk
        )

        colors.insert(
            0,
            "gray"
        )

        labels.insert(
            0,
            "0"
        )

    # --------------------------------------------------
    # FIGURE
    # --------------------------------------------------

    plt.figure(
        figsize=(20, 6)
    )

    # --------------------------------------------------
    # BASELINE REGION
    # --------------------------------------------------

    plt.axvspan(
        0,
        attack_start,
        color="gray",
        alpha=0.08,
        label="Baseline"
    )

    # --------------------------------------------------
    # ATTACK REGION
    # --------------------------------------------------

    plt.axvspan(
        attack_start,
        GLOBAL_X_MAX,
        color="red",
        alpha=0.04
    )

    # --------------------------------------------------
    # MAIN TRAJECTORY
    # --------------------------------------------------

    plt.plot(
        x,
        y,
        color="black",
        linewidth=1.8,
        alpha=0.8,
        zorder=1
    )

    # --------------------------------------------------
    # SCATTER POINTS
    # --------------------------------------------------

    plt.scatter(
        x,
        y,
        c=colors,
        s=90,
        edgecolors="black",
        linewidths=0.6,
        zorder=3
    )

    # --------------------------------------------------
    # SMART LABEL PLACEMENT
    # --------------------------------------------------

    previous_y = None

    for i in range(len(x)):

        y_offset = 3

        if previous_y is not None:

            if abs(y[i] - previous_y) < 8:

                y_offset = 6

        plt.text(

            x[i],

            y[i] + y_offset,

            labels[i],

            fontsize=7,

            ha="center",

            bbox=dict(
                facecolor="white",
                alpha=0.80,
                edgecolor="none",
                pad=0.25
            ),

            zorder=10
        )

        previous_y = y[i]

    # --------------------------------------------------
    # ATTACK START LINE
    # --------------------------------------------------

    plt.axvline(
        x=attack_start,
        linestyle="--",
        linewidth=1.8,
        color="red",
        alpha=0.8,
        label="Attack Start"
    )

    # --------------------------------------------------
    # PHASE LABELS
    # --------------------------------------------------

    plt.text(
        attack_start / 2,
        98,
        "Baseline",
        fontsize=10,
        ha="center"
    )

    plt.text(
        attack_start + 10,
        98,
        "Injection / Attack Window",
        fontsize=10
    )

    # --------------------------------------------------
    # AXIS CONTROL
    # --------------------------------------------------

    ax = plt.gca()

    # --------------------------------------------------
    # X AXIS
    # --------------------------------------------------

    ax.xaxis.set_major_locator(
        MultipleLocator(10)
    )

    ax.xaxis.set_minor_locator(
        MultipleLocator(1)
    )

    # --------------------------------------------------
    # Y AXIS
    # --------------------------------------------------

    ax.yaxis.set_major_locator(
        MultipleLocator(10)
    )

    ax.yaxis.set_minor_locator(
        MultipleLocator(5)
    )

    # --------------------------------------------------
    # TICK FORMATTING
    # --------------------------------------------------

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

    ax.tick_params(
        axis="y",
        which="major",
        labelsize=8
    )

    ax.tick_params(
        axis="y",
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

    plt.xlim(
        0,
        GLOBAL_X_MAX
    )

    plt.ylim(
        0,
        105
    )

    # --------------------------------------------------
    # REMOVE AUTO PADDING
    # --------------------------------------------------

    plt.margins(
        x=0,
        y=0
    )

    # --------------------------------------------------
    # LABELS
    # --------------------------------------------------

    filename = os.path.basename(
        file_path
    )

    plt.title(
        f"Risk Score Transition Dynamics\n{filename}",
        fontsize=14
    )

    plt.xlabel(
        "Experiment Timeline (1-Minute Observation Windows)",
        fontsize=11
    )

    plt.ylabel(
        "Risk Score (0-100)",
        fontsize=11
    )

    # --------------------------------------------------
    # LEGEND
    # --------------------------------------------------

    increase_proxy = plt.Line2D(
        [0],
        [0],
        marker='o',
        color='w',
        label='Risk Increase',
        markerfacecolor='red',
        markeredgecolor='black',
        markersize=8
    )

    decrease_proxy = plt.Line2D(
        [0],
        [0],
        marker='o',
        color='w',
        label='Risk Decrease',
        markerfacecolor='green',
        markeredgecolor='black',
        markersize=8
    )

    plt.legend(
        handles=[
            increase_proxy,
            decrease_proxy
        ],
        loc="upper right",
        fontsize=8
    )

    plt.tight_layout()

    # --------------------------------------------------
    # SAVE
    # --------------------------------------------------

    out_name = filename.replace(
        ".json",
        ".png"
    )

    out_path = os.path.join(
        OUTPUT_DIR,
        out_name
    )

    plt.savefig(
        out_path,
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"🔥 Saved risk transition chart → {out_path}"
    )


# --------------------------------------------------
# RUN ALL
# --------------------------------------------------

def run_all():

    if not os.path.exists(
        INPUT_DIR
    ):

        print(
            f"❌ Missing directory: {INPUT_DIR}"
        )

        return

    files = sorted(
        os.listdir(INPUT_DIR)
    )

    processed = 0

    for file in files:

        if not file.endswith(
            "_risk_transitions.json"
        ):
            continue

        plot_risk_transitions(

            os.path.join(
                INPUT_DIR,
                file
            )
        )

        processed += 1

    print("\n" + "=" * 60)

    print(
        f"✅ DONE — Generated {processed} risk transition charts"
    )

    print("=" * 60)


# --------------------------------------------------
# ENTRY
# --------------------------------------------------

if __name__ == "__main__":

    run_all()