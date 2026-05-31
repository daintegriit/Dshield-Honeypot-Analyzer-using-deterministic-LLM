#!/usr/bin/env python3

import os
import json
import time
import statistics
import requests

# ============================================================
# CONFIG
# ============================================================

BASE_URL = os.getenv(
    "CHIRON_API_BASE",
    "http://32.195.28.224:5002"
)

CHIRON_API_KEY = os.getenv(
    "CHIRON_API_KEY",
    ""
)

REQUEST_TIMEOUT = 180

# ============================================================
# VALIDATION MODE
# ============================================================

TOTAL_RUNS = 1

WINDOWS = [1]

# TOTAL_RUNS = 3

# WINDOWS = [1, 5, 15, 30, 60]

MODELS = [

    "llama3.1:8b",

    "mistral",

    "qwen2.5:7b-instruct",

    "gemma",

    "phi3"

]
QUESTIONS = [
    "What behavior supports the detected attack?"
]

# ============================================================
# SESSION
# ============================================================

SESSION = requests.Session()

# ============================================================
# HEADERS
# ============================================================

HEADERS = {
    "Content-Type": "application/json"
}

if CHIRON_API_KEY:

    HEADERS["Authorization"] = (
        f"Bearer {CHIRON_API_KEY}"
    )

# ============================================================
# HALLUCINATION TERMS
# ============================================================

HALLUCINATION_TERMS = [

    "ransomware",

    "zero-day",

    "apt",

    "nation-state",

    "lateral movement",

    "credential theft",

    "data exfiltration",

    "privilege escalation",

    "backdoor",

    "rootkit",

    "file encryption",

    "payload delivery",

    "malware deployment",

    "persistence"
]

# ============================================================
# RESULTS
# ============================================================

RESULTS = []

# ============================================================
# HELPERS
# ============================================================

def contains_hallucination(text):

    if not text:
        return False

    lowered = str(text).lower()

    for term in HALLUCINATION_TERMS:

        if term.lower() in lowered:
            return True

    return False


def estimate_tokens(text):

    if not text:
        return 0

    return max(
        1,
        int(len(text) / 4)
    )


def safe_json(response):

    try:
        return response.json()

    except Exception:
        return {}


# ============================================================
# FETCH LIVE THREAT SUMMARY
# ============================================================

def fetch_live_summary(minutes):

    url = (
        f"{BASE_URL}"
        f"/api/charts/threat-summary"
        f"?minutes={minutes}"
    )

    response = SESSION.get(

        url,

        headers=HEADERS,

        timeout=REQUEST_TIMEOUT
    )

    response.raise_for_status()

    payload = response.json()

    return payload.get(
        "coreSummary",
        {}
    )


# ============================================================
# ASK GOVERNED CHIRON
# ============================================================

def ask_governed(

    summary,

    question,

    model

):

    url = (
        f"{BASE_URL}"
        f"/api/copilot/ask"
    )

    payload = {

        "summary":
            summary,

        "templateId":
            "ATTACK_INTENT",

        "question":
            question,

        "baselineMode":
            False,

        "model":
            model
    }

    started = time.perf_counter()

    response = SESSION.post(

        url,

        json=payload,

        headers=HEADERS,

        timeout=REQUEST_TIMEOUT
    )

    latency_ms = (
        time.perf_counter() - started
    ) * 1000

    response.raise_for_status()

    data = response.json()

    data["_latency_ms"] = latency_ms

    return data


# ============================================================
# ASK BASELINE LLM
# ============================================================

def ask_baseline(

    summary,

    question,

    model

):

    url = (
        f"{BASE_URL}"
        f"/api/copilot/ask"
    )

    payload = {

        "summary":
            summary,

        "templateId":
            "ATTACK_INTENT",

        "question":
            question,

        "baselineMode":
            True,

        "model":
            model
    }

    started = time.perf_counter()

    response = SESSION.post(

        url,

        json=payload,

        headers=HEADERS,

        timeout=REQUEST_TIMEOUT
    )

    latency_ms = (
        time.perf_counter() - started
    ) * 1000

    response.raise_for_status()

    data = response.json()

    data["_latency_ms"] = latency_ms

    return data


# ============================================================
# EVALUATE RESPONSE
# ============================================================

def evaluate_response(

    answer,

    mode,

    model,

    question,

    window,

    latency_ms,

    token_metrics=None

):

    hallucination = contains_hallucination(
        answer
    )

    estimated_tokens = estimate_tokens(
        answer
    )

    grounded = not hallucination

    passed = grounded

    token_metrics = token_metrics or {}

    return {

        "model":
            model,

        "mode":
            mode,

        "window":
            window,

        "question":
            question,

        "answer":
            answer,

        "estimatedTokens":
            estimated_tokens,

        "hallucinationDetected":
            hallucination,

        "grounded":
            grounded,

        "passed":
            passed,

        "latencyMs":
            round(latency_ms, 2),

        "promptTokens":
            token_metrics.get(
                "promptTokens",
                0
            ),

        "completionTokens":
            token_metrics.get(
                "completionTokens",
                0
            ),

        "totalTokens":
            token_metrics.get(
                "totalTokens",
                0
            ),

        "promptEvalDuration":
            token_metrics.get(
                "promptEvalDuration",
                0
            ),

        "evalDuration":
            token_metrics.get(
                "evalDuration",
                0
            )
    }


# ============================================================
# RUN SINGLE MODEL COMPARISON
# ============================================================

def run_model_comparison(

    summary,

    question,

    model,

    window

):

    print("\n" + "=" * 70)

    print(f"MODEL: {model}")

    print(f"WINDOW: {window}m")

    print("=" * 70)

    # ========================================================
    # GOVERNED
    # ========================================================

    governed_response = ask_governed(

        summary=summary,

        question=question,

        model=model
    )

    governed_answer = governed_response.get(
        "answer",
        ""
    )

    governed_eval = evaluate_response(

        answer=governed_answer,

        mode="governed",

        model=model,

        question=question,

        window=window,

        latency_ms=governed_response.get(
            "_latency_ms",
            0
        ),

        token_metrics=governed_response.get(
            "tokenMetrics",
            {}
        )
    )

    RESULTS.append(governed_eval)

    print("\n--------------------------------------------------")
    print("MODE: GOVERNED")
    print("--------------------------------------------------")

    print("\nQUESTION:")
    print(question)

    print("\nANSWER:")
    print(governed_answer)

    print("\nLATENCY MS:",
          governed_eval["latencyMs"])

    print("PROMPT TOKENS:",
          governed_eval["promptTokens"])

    print("COMPLETION TOKENS:",
          governed_eval["completionTokens"])

    print("TOTAL TOKENS:",
          governed_eval["totalTokens"])

    print("HALLUCINATION:",
          governed_eval["hallucinationDetected"])

    print("GROUNDED:",
          governed_eval["grounded"])

    # ========================================================
    # SMALL THROTTLE
    # ========================================================

    time.sleep(0.5)

    # ========================================================
    # BASELINE
    # ========================================================

    baseline_response = ask_baseline(

        summary=summary,

        question=question,

        model=model
    )

    baseline_answer = baseline_response.get(
        "answer",
        ""
    )

    baseline_eval = evaluate_response(

        answer=baseline_answer,

        mode="baseline",

        model=model,

        question=question,

        window=window,

        latency_ms=baseline_response.get(
            "_latency_ms",
            0
        ),

        token_metrics=baseline_response.get(
            "tokenMetrics",
            {}
        )
    )

    RESULTS.append(baseline_eval)

    print("\n--------------------------------------------------")
    print("MODE: BASELINE")
    print("--------------------------------------------------")

    print("\nQUESTION:")
    print(question)

    print("\nANSWER:")
    print(baseline_answer)

    print("\nLATENCY MS:",
          baseline_eval["latencyMs"])

    print("PROMPT TOKENS:",
          baseline_eval["promptTokens"])

    print("COMPLETION TOKENS:",
          baseline_eval["completionTokens"])

    print("TOTAL TOKENS:",
          baseline_eval["totalTokens"])

    print("HALLUCINATION:",
          baseline_eval["hallucinationDetected"])

    print("GROUNDED:",
          baseline_eval["grounded"])

    # ========================================================
    # SMALL THROTTLE
    # ========================================================

    time.sleep(0.5)


# ============================================================
# MAIN
# ============================================================

def run_benchmark():

    print("\n" + "=" * 70)

    print(
        "CHIRON GOVERNED vs BASELINE BENCHMARK"
    )

    print("=" * 70)

    print("\nBASE URL:", BASE_URL)

    print(
        "AUTH ENABLED:",
        bool(CHIRON_API_KEY)
    )

    for run in range(TOTAL_RUNS):

        print(f"\nRUN {run+1}/{TOTAL_RUNS}")

        for window in WINDOWS:

            print(
                f"\nFetching live telemetry ({window}m)..."
            )

            try:

                summary = fetch_live_summary(
                    window
                )

            except Exception as e:

                print(
                    f"Failed to fetch telemetry: {e}"
                )

                continue

            for model in MODELS:

                for question in QUESTIONS:

                    try:

                        run_model_comparison(

                            summary=summary,

                            question=question,

                            model=model,

                            window=window
                        )

                    except Exception as e:

                        print(
                            f"\nERROR [{model}]: {e}"
                        )

        time.sleep(2)

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    total = len(RESULTS)

    governed = [

        r for r in RESULTS

        if r["mode"] == "governed"
    ]

    baseline = [

        r for r in RESULTS

        if r["mode"] == "baseline"
    ]

    governed_accuracy = (

        len([
            r for r in governed
            if r["grounded"]
        ]) / len(governed)

        if governed else 0
    )

    baseline_accuracy = (

        len([
            r for r in baseline
            if r["grounded"]
        ]) / len(baseline)

        if baseline else 0
    )

    avg_tokens = statistics.mean([

        r["totalTokens"]

        for r in RESULTS

    ]) if RESULTS else 0

    avg_latency = statistics.mean([

        r["latencyMs"]

        for r in RESULTS

    ]) if RESULTS else 0

    print("\n" + "=" * 70)

    print("FINAL RESULTS")

    print("=" * 70)

    print(f"Total Evaluations: {total}")

    print(
        f"Governed Grounding Accuracy: "
        f"{governed_accuracy:.4f}"
    )

    print(
        f"Baseline Grounding Accuracy: "
        f"{baseline_accuracy:.4f}"
    )

    print(
        f"Average Tokens: "
        f"{avg_tokens:.2f}"
    )

    print(
        f"Average Latency (ms): "
        f"{avg_latency:.2f}"
    )

    # ========================================================
    # SAVE
    # ========================================================

    out_file = (
        "chiron_llm_comparison_results.json"
    )

    with open(out_file, "w") as f:

        json.dump(
            RESULTS,
            f,
            indent=2
        )

    print(
        f"\nSaved results -> {out_file}"
    )


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":

    run_benchmark()