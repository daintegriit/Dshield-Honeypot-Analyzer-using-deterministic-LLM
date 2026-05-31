import os
import subprocess
import sys
import json

# --------------------------------------------------
# CONFIG
# --------------------------------------------------

SCRIPT_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

BASE_DIR = os.path.join(
    SCRIPT_DIR,
    "../runsforpaper4"
)

# --------------------------------------------------
# EXTRACTORS
# --------------------------------------------------

STATE_SCRIPT = os.path.join(
    SCRIPT_DIR,
    "extract_state_transitions.py"
)

RISK_SCRIPT = os.path.join(
    SCRIPT_DIR,
    "extract_risk_timeline.py"
)

RELATIVE_SCRIPT = os.path.join(
    SCRIPT_DIR,
    "extract_risk_timeline_relative.py"
)

ATTACK_SCRIPT = os.path.join(
    SCRIPT_DIR,
    "extract_risk_timeline_attack_aligned.py"
)

CUSTOM_SCRIPT = os.path.join(
    SCRIPT_DIR,
    "extract_risk_custom.py"
)

# --------------------------------------------------
# SCRIPT PIPELINE
# --------------------------------------------------

SCRIPTS = [

    STATE_SCRIPT,

    RISK_SCRIPT,

    RELATIVE_SCRIPT,

    ATTACK_SCRIPT,

    CUSTOM_SCRIPT,
]


# --------------------------------------------------
# VALIDATE SCRIPTS EXIST
# --------------------------------------------------

def validate_scripts():

    print(
        "\n🔍 Validating extractor scripts..."
    )

    for script in SCRIPTS:

        if not os.path.exists(script):

            print(
                f"❌ Missing script: {script}"
            )

            sys.exit(1)

        else:

            print(
                f"✅ Found: {os.path.basename(script)}"
            )


# --------------------------------------------------
# FILE FILTERING
# --------------------------------------------------

def is_valid_experiment_file(filepath):

    filename = os.path.basename(filepath)

    # --------------------------------------------------
    # SKIP DERIVED FILES
    # --------------------------------------------------

    skip_tags = [

        "_risk",

        "_transitions",

        "_relative",

        "_attack_aligned",

        "_risk_custom",
    ]

    if any(
        tag in filename
        for tag in skip_tags
    ):

        return False

    # --------------------------------------------------
    # MUST BE JSON
    # --------------------------------------------------

    if not filename.endswith(".json"):

        return False

    # --------------------------------------------------
    # VALIDATE STRUCTURE
    # --------------------------------------------------

    try:

        with open(filepath, "r") as f:

            data = json.load(f)

        return (
            isinstance(data, dict)
            and "results" in data
        )

    except Exception as e:

        print(
            f"⚠️ Skipping invalid JSON: "
            f"{filename} ({e})"
        )

        return False


# --------------------------------------------------
# SAFE RUNNER
# --------------------------------------------------

def run_script(script, file_path):

    script_name = os.path.basename(script)

    print(
        f"   ↳ Running {script_name}..."
    )

    try:

        result = subprocess.run(

            [
                sys.executable,
                script,
                file_path
            ],

            capture_output=True,

            text=True
        )

        # --------------------------------------------------
        # ERROR
        # --------------------------------------------------

        if result.returncode != 0:

            print(
                f"❌ Error in {script_name} "
                f"for {os.path.basename(file_path)}"
            )

            if result.stderr:

                print(
                    result.stderr.strip()
                )

        # --------------------------------------------------
        # SUCCESS
        # --------------------------------------------------

        else:

            if result.stdout.strip():

                print(
                    result.stdout.strip()
                )

            else:

                print(
                    f"   ✅ {script_name} done"
                )

    except Exception as e:

        print(
            f"❌ Failed to run "
            f"{script_name}: {e}"
        )


# --------------------------------------------------
# MAIN RUNNER
# --------------------------------------------------

def run_all():

    validate_scripts()

    # --------------------------------------------------
    # VALIDATE INPUT DIRECTORY
    # --------------------------------------------------

    if not os.path.exists(BASE_DIR):

        print(
            f"\n❌ Directory not found: "
            f"{BASE_DIR}"
        )

        return

    files = sorted(
        os.listdir(BASE_DIR)
    )

    if not files:

        print(
            "\n⚠️ No files found."
        )

        return

    processed = 0

    print(
        f"\n📂 Scanning directory: "
        f"{BASE_DIR}"
    )

    # --------------------------------------------------
    # PROCESS FILES
    # --------------------------------------------------

    for file in files:

        full_path = os.path.join(
            BASE_DIR,
            file
        )

        if not is_valid_experiment_file(
            full_path
        ):

            continue

        print(
            f"\n📊 Processing: {file}"
        )

        for script in SCRIPTS:

            run_script(
                script,
                full_path
            )

        processed += 1

    # --------------------------------------------------
    # SUMMARY
    # --------------------------------------------------

    print(
        "\n" + "=" * 60
    )

    print(
        f"✅ DONE — Processed "
        f"{processed} experiment files"
    )

    print(
        "=" * 60
    )


# --------------------------------------------------
# ENTRY
# --------------------------------------------------

if __name__ == "__main__":

    run_all()