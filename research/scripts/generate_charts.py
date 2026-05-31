import os
import json
from matplotlib.ticker import MultipleLocator
import matplotlib.pyplot as plt
from datetime import datetime

# --------------------------------------------------
# CONFIG
# --------------------------------------------------

BASE_EXTRACT = "../extract"

RISK_DIR = os.path.join(
    BASE_EXTRACT,
    "risk"
)

RISK_REL_DIR = os.path.join(
    BASE_EXTRACT,
    "risk_relative"
)

ATTACK_ALIGN_DIR = os.path.join(
    BASE_EXTRACT,
    "risk_attack_aligned"
)

TRANSITION_DIR = os.path.join(
    BASE_EXTRACT,
    "transitions"
)

# --------------------------------------------------
# OUTPUTS
# --------------------------------------------------

CHART_BASE = os.path.join(
    BASE_EXTRACT,
    "charts"
)

RISK_OUT = os.path.join(
    CHART_BASE,
    "risk"
)

RISK_REL_OUT = os.path.join(
    CHART_BASE,
    "risk_relative"
)

ATTACK_ALIGN_OUT = os.path.join(
    CHART_BASE,
    "risk_attack_aligned"
)

TRANS_OUT = os.path.join(
    CHART_BASE,
    "transitions"
)

# --------------------------------------------------
# MAKE DIRS
# --------------------------------------------------

os.makedirs(RISK_OUT, exist_ok=True)
os.makedirs(RISK_REL_OUT, exist_ok=True)
os.makedirs(ATTACK_ALIGN_OUT, exist_ok=True)
os.makedirs(TRANS_OUT, exist_ok=True)

# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def parse_time(ts):

    try:

        return datetime.fromisoformat(
            ts.replace("Z", "+00:00")
        )

    except:

        return None


# --------------------------------------------------
# 📈 ABSOLUTE RISK
# --------------------------------------------------

def plot_risk(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    times = []
    scores = []

    for d in data:

        t = parse_time(
            d.get("timestamp")
        )

        if not t:
            continue

        times.append(t)

        scores.append(
            d.get("riskScore", 0)
        )

    if not times:
        return

    plt.figure(figsize=(12, 5))

    plt.plot(
        times,
        scores,
        linewidth=2
    )

    plt.title(
        "Risk Score Over Time (Absolute)"
    )

    plt.xlabel("Time")

    plt.ylabel("Risk Score")

    plt.grid(alpha=0.3)

    filename = os.path.basename(
        file_path
    ).replace(
        "_risk.json",
        "_risk.png"
    )

    plt.savefig(
        os.path.join(RISK_OUT, filename)
    )

    plt.close()

    print(f"📈 Risk chart → {filename}")


# --------------------------------------------------
# 🚀 RELATIVE RISK
# --------------------------------------------------

def plot_risk_relative(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    data = sorted(
        data,
        key=lambda x: x.get("t_min", 0)
    )

    t = [
        x["t_min"]
        for x in data
        if "t_min" in x
    ]

    risk = [
        x.get("riskScore", 0)
        for x in data
    ]

    if not t:
        return

    plt.figure(figsize=(12, 5))

    plt.plot(
        t,
        risk,
        linewidth=2
    )

    plt.title(
        "Risk Score Over Time (Relative)"
    )

    plt.xlabel(
        "Time Since Run Start (minutes)"
    )

    plt.ylabel("Risk Score")

    plt.grid(alpha=0.3)

    filename = os.path.basename(
        file_path
    ).replace(
        ".json",
        ".png"
    )

    plt.savefig(
        os.path.join(RISK_REL_OUT, filename)
    )

    plt.close()

    print(
        f"🚀 Relative chart → {filename}"
    )


# --------------------------------------------------
# 🔥 ATTACK-ALIGNED
# --------------------------------------------------

def plot_attack_aligned(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    # --------------------------------------------------
    # FORMAT HANDLING
    # --------------------------------------------------

    if (
        isinstance(data, dict)
        and "timeline" in data
    ):

        timeline = data["timeline"]

        metadata = data.get(
            "metadata",
            {}
        )

    else:

        timeline = data

        metadata = {}

    # --------------------------------------------------
    # SORT
    # --------------------------------------------------

    timeline = sorted(
        timeline,
        key=lambda x: x.get(
            "t_attack_min",
            0
        )
    )

    # --------------------------------------------------
    # ORIGINAL VALUES
    # --------------------------------------------------

    original_t = [

        x.get(
            "t_attack_min",
            0
        )

        for x in timeline
    ]

    risk = [

        x.get(
            "riskScore",
            0
        )

        for x in timeline
    ]

    if not original_t:
        return

    # --------------------------------------------------
    # ELITE TIMELINE NORMALIZATION
    # --------------------------------------------------

    experiment_start = min(
        original_t
    )

    t = [
        val - experiment_start
        for val in original_t
    ]

    # --------------------------------------------------
    # PHASE BOUNDARIES
    # --------------------------------------------------

    attack_start = abs(
        experiment_start
    )

    attack_end = metadata.get(
        "attack_end",
        metadata.get(
            "injection_end_min",
            max(original_t)
        )
    ) + attack_start

    # --------------------------------------------------
    # CONSISTENT GLOBAL X RANGE
    # --------------------------------------------------

    rounded_max_x = (
        (
            int(max(t) / 10) + 1
        ) * 10
    )

    # --------------------------------------------------
    # FIGURE
    # --------------------------------------------------

    plt.figure(figsize=(18, 6))

    plt.plot(
        t,
        risk,
        linewidth=2,
        label="Risk Score"
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
    # INJECTION REGION
    # --------------------------------------------------

    plt.axvspan(
        attack_start,
        attack_end,
        color="red",
        alpha=0.10,
        label="Injection"
    )

    # --------------------------------------------------
    # COOLDOWN REGION
    # --------------------------------------------------

    plt.axvspan(
        attack_end,
        rounded_max_x,
        color="blue",
        alpha=0.08,
        label="Cooldown"
    )

    # --------------------------------------------------
    # IMPORTANT LINES
    # --------------------------------------------------

    plt.axvline(
        x=attack_start,
        linestyle="--",
        linewidth=2,
        color="black"
    )

    plt.axvline(
        x=attack_end,
        linestyle="--",
        linewidth=2,
        color="black"
    )

    # --------------------------------------------------
    # LABELS
    # --------------------------------------------------

    y_max = max(risk) if risk else 100

    baseline_midpoint = (
        attack_start / 2
    )

    plt.text(
        baseline_midpoint,
        y_max * 0.92,
        "Baseline",
        fontsize=10,
        ha="center"
    )

    plt.text(
        attack_start + 5,
        y_max * 0.92,
        "Injection",
        fontsize=10
    )

    plt.text(
        attack_end + 5,
        y_max * 0.92,
        "Cooldown",
        fontsize=10
    )

    # --------------------------------------------------
    # AXIS CONTROL
    # --------------------------------------------------

    ax = plt.gca()

    # X major every 10 mins
    ax.xaxis.set_major_locator(
        MultipleLocator(10)
    )

    # X minor every 1 minute
    ax.xaxis.set_minor_locator(
        MultipleLocator(1)
    )

    # Y major every 10 risk
    ax.yaxis.set_major_locator(
        MultipleLocator(10)
    )

    # Y minor every 5 risk
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
    # TRUE ORIGIN ALIGNMENT
    # --------------------------------------------------

    ax.set_xlim(
        0,
        rounded_max_x
    )

    ax.set_ylim(
        0,
        105
    )

    plt.margins(
        x=0,
        y=0
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
    # LEGEND
    # --------------------------------------------------

    plt.legend(
        loc="upper right",
        fontsize=8
    )

    # --------------------------------------------------
    # TITLES
    # --------------------------------------------------

    pcap_name = metadata.get(
        "source_file",
        "Unknown PCAP"
    )

    plt.title(
        f"Risk Score Over Time (Attack-Aligned)\n{pcap_name}",
        fontsize=14
    )

    plt.xlabel(
        "Experiment Timeline (minutes)",
        fontsize=11
    )

    plt.ylabel(
        "Risk Score",
        fontsize=11
    )

    plt.tight_layout()

    # --------------------------------------------------
    # SAVE
    # --------------------------------------------------

    filename = os.path.basename(
        file_path
    ).replace(
        ".json",
        ".png"
    )

    plt.savefig(
        os.path.join(
            ATTACK_ALIGN_OUT,
            filename
        ),
        dpi=300,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"🔥 Attack-aligned chart → {filename}"
    )


# --------------------------------------------------
# 🔵 STATE TRANSITIONS
# --------------------------------------------------

STATE_MAP = {

    "stable": 0,

    "elevated": 1,

    "high": 2,

    "critical": 3
}

def plot_transitions(file_path):

    with open(file_path, "r") as f:

        data = json.load(f)

    times = []
    states = []

    for d in data:

        t = parse_time(
            d.get("timestamp")
        )

        if not t:
            continue

        times.append(t)

        states.append(
            STATE_MAP.get(
                d.get("to"),
                0
            )
        )

    if not times:
        return

    plt.figure(figsize=(12, 4))

    plt.step(
        times,
        states,
        where="post",
        linewidth=2
    )

    plt.yticks(
        [0,1,2,3],
        [
            "stable",
            "elevated",
            "high",
            "critical"
        ]
    )

    plt.title(
        "State Transitions Over Time"
    )

    plt.xlabel("Time")

    plt.ylabel("State")

    plt.grid(alpha=0.3)

    filename = os.path.basename(
        file_path
    ).replace(
        "_transitions.json",
        ".png"
    )

    plt.savefig(
        os.path.join(
            TRANS_OUT,
            filename
        )
    )

    plt.close()

    print(
        f"🔵 Transition chart → {filename}"
    )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def run_all():

    if os.path.exists(RISK_DIR):

        for f in os.listdir(RISK_DIR):

            if f.endswith("_risk.json"):

                plot_risk(
                    os.path.join(
                        RISK_DIR,
                        f
                    )
                )

    if os.path.exists(RISK_REL_DIR):

        for f in os.listdir(RISK_REL_DIR):

            if f.endswith("_risk_relative.json"):

                plot_risk_relative(
                    os.path.join(
                        RISK_REL_DIR,
                        f
                    )
                )

    if os.path.exists(ATTACK_ALIGN_DIR):

        for f in os.listdir(ATTACK_ALIGN_DIR):

            if f.endswith("_attack_aligned.json"):

                plot_attack_aligned(
                    os.path.join(
                        ATTACK_ALIGN_DIR,
                        f
                    )
                )

    if os.path.exists(TRANSITION_DIR):

        for f in os.listdir(TRANSITION_DIR):

            if f.endswith("_transitions.json"):

                plot_transitions(
                    os.path.join(
                        TRANSITION_DIR,
                        f
                    )
                )


# --------------------------------------------------
# ENTRY
# --------------------------------------------------

if __name__ == "__main__":

    run_all()