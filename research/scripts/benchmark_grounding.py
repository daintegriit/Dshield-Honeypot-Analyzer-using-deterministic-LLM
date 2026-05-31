#!/usr/bin/env python3
import requests
import json
import time
import statistics

# =========================================================
# CONFIG
# =========================================================

BASE_URL = "http://32.195.28.224:5002"

ROUTE = "/api/charts/threat-summary"

WINDOWS = [1, 5, 15, 30, 60]

TOTAL_RUNS = 3

REQUEST_TIMEOUT = 180

# =========================================================
# THRESHOLDS
# =========================================================

STABLE_MAX = 44
ELEVATED_MIN = 45
HIGH_MIN = 60
CRITICAL_MIN = 85

# =========================================================
# HALLUCINATION TERMS
# =========================================================

HALLUCINATION_TERMS = [

    "ransomware",

    "zero-day",

    "lateral movement",

    "persistence",

    "data exfiltration",

    "credential theft",

    "nation-state",

    "apt",

    "file encryption",

    "rootkit",

    "privilege escalation",

    "payload delivery",

    "malware deployment",

    "backdoor installation"
]

# =========================================================
# BENCHMARK QUESTIONS
# =========================================================

BENCHMARK_QUESTIONS = [

    "What behavior supports the detected attack?",

    "Why was this classified as the dominant attack type?",

    "What telemetry supports the current risk score?",

    "What evidence supports escalation to the current state?",

    "What indicators suggest malicious activity?"
]

# =========================================================
# RESULTS
# =========================================================

results = []

# =========================================================
# HELPERS
# =========================================================

def safe_float(value):

    try:

        if value is None:
            return None

        return float(value)

    except:

        return None


def expected_state(risk):

    if risk is None:
        return "unknown"

    if risk >= CRITICAL_MIN:
        return "critical"

    if risk >= HIGH_MIN:
        return "high"

    if risk >= ELEVATED_MIN:
        return "elevated"

    return "stable"


def safe_get(d, path, default=None):

    current = d

    for p in path:

        if not isinstance(current, dict):
            return default

        current = current.get(p)

        if current is None:
            return default

    return current


# =========================================================
# TOKEN ESTIMATION
# =========================================================

def tokenize(text):

    if not text:
        return []

    return str(text).split()


def count_estimated_tokens(text):

    return len(tokenize(text))


# =========================================================
# HALLUCINATION DETECTION
# =========================================================

def contains_hallucination(text):

    if not text:
        return False

    lowered = str(text).lower()

    for term in HALLUCINATION_TERMS:

        if term.lower() in lowered:
            return True

    return False


# =========================================================
# EXTRACT REASONING
# =========================================================

def extract_reasoning_text(payload):

    explanation = safe_get(
        payload,
        ["reasoning", "dominantAttackExplanation"],
        []
    )

    risk_explanation = safe_get(
        payload,
        ["reasoning", "riskExplanation"],
        []
    )

    analyst_summary = safe_get(
        payload,
        ["reasoning", "analystSummary"],
        ""
    )

    parts = []

    if isinstance(explanation, list):
        parts.extend(explanation)

    if isinstance(risk_explanation, list):
        parts.extend(risk_explanation)

    if analyst_summary:
        parts.append(analyst_summary)

    return " ".join(parts)


# =========================================================
# QUESTION EVALUATION
# =========================================================

def evaluate_questions(payload):

    reasoning_text = extract_reasoning_text(
        payload
    )

    evaluations = []

    for q in BENCHMARK_QUESTIONS:

        hallucination = contains_hallucination(
            reasoning_text
        )

        token_count = count_estimated_tokens(
            reasoning_text
        )

        evaluations.append({

            "question": q,

            "response": reasoning_text,

            "estimatedResponseTokens":
                token_count,

            "hallucinationDetected":
                hallucination,

            "responseLengthChars":
                len(reasoning_text),

            "grounded":
                not hallucination
        })

    return evaluations


# =========================================================
# VALIDATION
# =========================================================

def validate_response(window, payload):

    validation = {}

    risk = safe_float(
        payload.get("riskScore0to100")
    )

    state = payload.get("state")

    replay_state = payload.get(
        "replayState"
    )

    dominant_attack = safe_get(
        payload,
        [
            "attackClassification",
            "dominantAttack",
            "type"
        ]
    )

    attack_detected = safe_get(
        payload,
        ["reasoning", "attackDetected"]
    )

    confidence = safe_get(
        payload,
        ["reasoning", "attackConfidence"]
    )

    explanation = safe_get(
        payload,
        [
            "reasoning",
            "dominantAttackExplanation"
        ],
        []
    )

    analyst_summary = safe_get(
        payload,
        ["reasoning", "analystSummary"],
        ""
    )

    # =====================================================
    # STATE GROUNDING
    # =====================================================

    expected = expected_state(risk)

    validation[
        "stateMatchesRiskThreshold"
    ] = (
        expected == state
    )

    validation[
        "expectedState"
    ] = expected

    # =====================================================
    # ATTACK DETECTION CONSISTENCY
    # =====================================================

    validation[
        "attackDetectionConsistent"
    ] = True

    if (
        risk is not None
        and
        risk < 45
        and
        attack_detected
    ):

        validation[
            "attackDetectionConsistent"
        ] = False

    # =====================================================
    # CONFIDENCE CONSISTENCY
    # =====================================================

    validation[
        "confidenceConsistent"
    ] = True

    if (
        risk is not None
        and
        confidence == "high"
        and
        risk < 45
    ):

        validation[
            "confidenceConsistent"
        ] = False

    # =====================================================
    # DOMINANT ATTACK
    # =====================================================

    validation[
        "dominantAttackValid"
    ] = dominant_attack is not None

    # =====================================================
    # REPLAY STATE
    # =====================================================

    valid_replay_states = [

        "baseline",

        "injection",

        "cooldown"
    ]

    validation[
        "validReplayState"
    ] = (
        replay_state in valid_replay_states
    )

    # =====================================================
    # EXPLANATION PRESENT
    # =====================================================

    validation[
        "explanationPresent"
    ] = (
        isinstance(explanation, list)
        and len(explanation) > 0
    )

    # =====================================================
    # TOKEN ESTIMATION
    # =====================================================

    total_reasoning = (
        " ".join(explanation)
        + " "
        + str(analyst_summary)
    )

    token_count = count_estimated_tokens(
        total_reasoning
    )

    validation[
        "estimatedReasoningTokens"
    ] = token_count

    # =====================================================
    # HALLUCINATION DETECTION
    # =====================================================

    hallucination = contains_hallucination(
        total_reasoning
    )

    validation[
        "hallucinationDetected"
    ] = hallucination

    # =====================================================
    # QUESTION EVALUATIONS
    # =====================================================

    validation[
        "questionEvaluations"
    ] = evaluate_questions(payload)

    # =====================================================
    # FINAL PASS
    # =====================================================

    validation["passed"] = (

        validation[
            "stateMatchesRiskThreshold"
        ]

        and

        validation[
            "attackDetectionConsistent"
        ]

        and

        validation[
            "confidenceConsistent"
        ]

        and

        validation[
            "dominantAttackValid"
        ]

        and

        validation[
            "validReplayState"
        ]

        and

        validation[
            "explanationPresent"
        ]

        and

        not hallucination
    )

    return validation


# =========================================================
# MAIN BENCHMARK
# =========================================================

def run_benchmark():

    print("\n" + "=" * 70)

    print(
        "CHIRON LIVE DETERMINISTIC GROUNDING BENCHMARK"
    )

    print("=" * 70)

    for run in range(TOTAL_RUNS):

        print(
            f"\nRUN {run+1}/{TOTAL_RUNS}"
        )

        for minutes in WINDOWS:

            try:

                url = (
                    f"{BASE_URL}"
                    f"{ROUTE}"
                )

                response = requests.get(
                    url,
                    timeout=REQUEST_TIMEOUT
                )

                raw_payload = response.json()

                payload = raw_payload.get(
                    "coreSummary",
                    {}
                )

                print("\n--------------------------------------------------")
                print(f"WINDOW: {minutes}m")
                print("--------------------------------------------------")

                debug_payload = {

                    "state":
                        payload.get("state"),

                    "riskScore0to100":
                        payload.get("riskScore0to100"),

                    "replayState":
                        payload.get("replayState"),

                    "dominantAttack":
                        safe_get(
                            payload,
                            [
                                "attackClassification",
                                "dominantAttack",
                                "type"
                            ]
                        ),

                    "dominantAttackScore":
                        safe_get(
                            payload,
                            [
                                "attackClassification",
                                "dominantAttack",
                                "score"
                            ]
                        ),

                    "attackDetected":
                        safe_get(
                            payload,
                            [
                                "reasoning",
                                "attackDetected"
                            ]
                        ),

                    "attackConfidence":
                        safe_get(
                            payload,
                            [
                                "reasoning",
                                "attackConfidence"
                            ]
                        ),

                    "evidenceScore":
                        safe_get(
                            payload,
                            [
                                "reasoning",
                                "evidenceScore"
                            ]
                        ),

                    "dominantAttackExplanation":
                        safe_get(
                            payload,
                            [
                                "reasoning",
                                "dominantAttackExplanation"
                            ]
                        ),

                    "riskExplanation":
                        safe_get(
                            payload,
                            [
                                "reasoning",
                                "riskExplanation"
                            ]
                        ),

                    "analystSummary":
                        safe_get(
                            payload,
                            [
                                "reasoning",
                                "analystSummary"
                            ]
                        )
                }

                print(
                    json.dumps(
                        debug_payload,
                        indent=2
                    )
                )

                validation = validate_response(
                    minutes,
                    payload
                )

                print("\nVALIDATION:")

                print(
                    json.dumps(
                        validation,
                        indent=2
                    )
                )

                results.append({

                    "windowMinutes":
                        minutes,

                    "riskScore0to100":
                        payload.get(
                            "riskScore0to100"
                        ),

                    "state":
                        payload.get(
                            "state"
                        ),

                    "replayState":
                        payload.get(
                            "replayState"
                        ),

                    "dominantAttack":
                        safe_get(
                            payload,
                            [
                                "attackClassification",
                                "dominantAttack",
                                "type"
                            ]
                        ),

                    "hallucinationDetected":
                        validation[
                            "hallucinationDetected"
                        ],

                    "estimatedReasoningTokens":
                        validation[
                            "estimatedReasoningTokens"
                        ],

                    "passed":
                        validation[
                            "passed"
                        ],

                    "validation":
                        validation
                })

                print(

                    f"\n[{minutes}m] "

                    f"state={payload.get('state')} "

                    f"risk={payload.get('riskScore0to100')} "

                    f"estimated≈{validation['estimatedReasoningTokens']} "

                    f"hallucination={validation['hallucinationDetected']} "

                    f"pass={validation['passed']}"
                )

            except Exception as e:

                print(
                    f"\nERROR [{minutes}m]: {e}"
                )

        time.sleep(2)

    # =====================================================
    # FINAL SUMMARY
    # =====================================================

    total = len(results)

    passed = len([
        r for r in results
        if r["passed"]
    ])

    hallucinations = len([
        r for r in results
        if r["hallucinationDetected"]
    ])

    avg_tokens = statistics.mean([

        r["estimatedReasoningTokens"]

        for r in results

    ]) if results else 0

    accuracy = (
        passed / total
        if total > 0
        else 0
    )

    print("\n" + "=" * 70)

    print("FINAL RESULTS")

    print("=" * 70)

    print(
        f"Total Evaluations: {total}"
    )

    print(
        f"Passed: {passed}"
    )

    print(
        f"Failed: {total - passed}"
    )

    print(
        f"Hallucinations Detected: "
        f"{hallucinations}"
    )

    print(
        f"Average Estimated Reasoning Tokens: "
        f"{avg_tokens:.2f}"
    )

    print(
        f"Grounding Accuracy: "
        f"{accuracy:.4f}"
    )

    # =====================================================
    # SAVE
    # =====================================================

    out_file = (
        "benchmark_grounding_results.json"
    )

    with open(out_file, "w") as f:

        json.dump(
            results,
            f,
            indent=2
        )

    print(
        f"\nSaved -> {out_file}"
    )


# =========================================================
# ENTRY
# =====================================================

if __name__ == "__main__":

    run_benchmark()