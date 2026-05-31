#!/usr/bin/env python3

import os
import json
import time
import statistics
import requests
from pathlib import Path
import random

# ============================================================
# CONFIG
# ============================================================

BASE_URL = os.getenv(
    "CHIRON_API_BASE",
    "http://32.195.28.224:5002"
)

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://localhost:11434"
)

REQUEST_TIMEOUT = 180

TOTAL_RUNS = 3

WINDOWS = [1, 5, 15]

MODEL_COOLDOWN_SECONDS = 2

PCAP_ROOT = os.getenv(
    "ZEEK_LOG_DIR",
    "../pcaps/zeek_logs"
)

ZEEK_LOG_DIR = os.getenv(
    "ZEEK_LOG_DIR",
    "../research/pcaps/zeek_logs"
)


# ============================================================
# MODELS
# ============================================================

MODELS = [

    "llama3.1:8b",

    "mistral",

    "qwen2.5:7b-instruct",

    "gemma",

    "phi3"
]

# ============================================================
# QUESTIONS
# ============================================================

QUESTIONS = [

    "What behavior supports the detected attack?",

    "Why was this classified as malicious?",

    "What telemetry supports the current risk score?"
]

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

    "payload delivery",

    "malware deployment",

    "backdoor installation",

    "rootkit",

    "botnet",

    "worm propagation",

    "trojan activity",

    "remote shell",

    "persistence established",

    "successful compromise",

    "confirmed breach",

    "active exploitation"
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


def safe_mean(values):

    cleaned = [

        v for v in values

        if isinstance(v, (int, float))
    ]

    if not cleaned:
        return 0

    return statistics.mean(cleaned)


# ============================================================
# MODEL WARMUP
# ============================================================

def warmup_model(model):

    print("\n" + "-" * 60)

    print(f"WARMING MODEL: {model}")

    print("-" * 60)

    url = (
        f"{OLLAMA_URL}"
        f"/api/generate"
    )

    payload = {

        "model":
            model,

        "prompt":
            "warmup",

        "stream":
            False,

        "options": {

            "temperature":
                0,

            "num_predict":
                8,

            "num_ctx":
                512
        }
    }

    started = time.perf_counter()

    try:

        response = requests.post(

            url,

            json=payload,

            timeout=REQUEST_TIMEOUT
        )

        response.raise_for_status()

        latency_ms = round(
            (time.perf_counter() - started) * 1000,
            2
        )

        print(
            f"WARMUP COMPLETE: {model}"
        )

        print(
            f"WARMUP LATENCY: {latency_ms} ms"
        )

        return latency_ms

    except Exception as e:

        print(
            f"WARMUP FAILED [{model}]: {e}"
        )

        return None


# ============================================================
# LOAD RAW ZEEK CONTEXT
# ============================================================

def load_raw_zeek_context():

    zeek_root = Path(PCAP_ROOT)

    if not zeek_root.exists():

        print(
            f"ZEEK ROOT NOT FOUND: {zeek_root}"
        )

        return "", "NONE"

    candidate_dirs = [

        d for d in zeek_root.iterdir()

        if d.is_dir()
    ]

    if not candidate_dirs:

        print(
            "NO ZEEK PCAP DIRECTORIES FOUND"
        )

        return "", "NONE"

    selected_dir = random.choice(
        candidate_dirs
    )

    print(
        f"\nSELECTED PCAP: "
        f"{selected_dir.name}"
    )

    zeek_files = [

        "conn.log",
        "dns.log",
        "http.log",
        "ssl.log"
    ]

    collected = []

    for filename in zeek_files:

        file_path = selected_dir / filename

        if not file_path.exists():
            continue

        collected.append(
            f"\n========== {filename} ==========\n"
        )

        try:

            with open(
                file_path,
                "r",
                errors="ignore"
            ) as f:

                added = 0

                for line in f:

                    if line.startswith("#"):
                        continue

                    collected.append(
                        line.strip()
                    )

                    added += 1

        except Exception as e:

            print(
                f"FAILED LOADING {filename}: {e}"
            )

    return (
        "\n".join(collected),
        selected_dir.name
    )

# ============================================================
# ASK GOVERNED CHIRON
# ============================================================

def ask_governed(

    question,
    model,
    window

):

    url = (
        f"{BASE_URL}"
        f"/api/copilot/ask"
    )

    payload = {

        "question":
            question,

        "templateId":
            "ATTACK_INTENT",

        "minutes":
            window,

        "model":
            model,

        "baselineMode":
            False
    }

    started = time.perf_counter()

    response = requests.post(

        url,

        json=payload,

        timeout=REQUEST_TIMEOUT
    )

    latency_ms = round(
        (time.perf_counter() - started) * 1000,
        2
    )

    response.raise_for_status()

    data = response.json()

    token_metrics = data.get(
        "tokenMetrics",
        {}
    )

    return {

        "answer":
            data.get(
                "answer",
                ""
            ),

        "latencyMs":
            latency_ms,

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
# ASK RAW BASELINE MODEL
# ============================================================

def ask_no_evidence_baseline(

    question,
    model

):

    url = (
        f"{OLLAMA_URL}"
        f"/api/generate"
    )

    prompt = f"""
You are a cybersecurity analyst.

Answer the following question:

{question}

Provide a concise cybersecurity assessment.
"""

    payload = {

        "model":
            model,

        "prompt":
            prompt,

        "stream":
            False,

        "options": {
        }
    }

    started = time.perf_counter()

    response = requests.post(

        url,

        json=payload,

        timeout=REQUEST_TIMEOUT
    )

    latency_ms = round(
        (time.perf_counter() - started) * 1000,
        2
    )

    response.raise_for_status()

    data = response.json()

    return {

        "answer":
            data.get(
                "response",
                ""
            ),

        "latencyMs":
            latency_ms,

        "promptTokens":
            data.get(
                "prompt_eval_count",
                0
            ),

        "completionTokens":
            data.get(
                "eval_count",
                0
            ),

        "totalTokens":
            (
                data.get(
                    "prompt_eval_count",
                    0
                )
                +
                data.get(
                    "eval_count",
                    0
                )
            ),

        "promptEvalDuration":
            data.get(
                "prompt_eval_duration",
                0
            ),

        "evalDuration":
            data.get(
                "eval_duration",
                0
            )
    }

# ============================================================
# ASK RAW ZEEK BASELINE
# ============================================================

def ask_raw_zeek_baseline(

    question,
    model,
    raw_zeek_context

):

    url = (
        f"{OLLAMA_URL}"
        f"/api/generate"
    )

    prompt = f"""
You are a cybersecurity analyst.

You are provided raw Zeek telemetry.

RAW ZEEK TELEMETRY:
{raw_zeek_context}

QUESTION:
{question}

Provide a concise cybersecurity assessment
based ONLY on the telemetry.
"""

    payload = {

        "model":
            model,

        "prompt":
            prompt,

        "stream":
            False
    }

    started = time.perf_counter()

    response = requests.post(

        url,

        json=payload,

        timeout=REQUEST_TIMEOUT
    )

    latency_ms = round(
        (time.perf_counter() - started) * 1000,
        2
    )

    response.raise_for_status()

    data = response.json()

    return {

        "answer":
            data.get(
                "response",
                ""
            ),

        "latencyMs":
            latency_ms,

        "promptTokens":
            data.get(
                "prompt_eval_count",
                0
            ),

        "completionTokens":
            data.get(
                "eval_count",
                0
            ),

        "totalTokens":
            (
                data.get(
                    "prompt_eval_count",
                    0
                )
                +
                data.get(
                    "eval_count",
                    0
                )
            ),

        "promptEvalDuration":
            data.get(
                "prompt_eval_duration",
                0
            ),

        "evalDuration":
            data.get(
                "eval_duration",
                0
            )
    }

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
    warmup_latency_ms,
    prompt_tokens,
    completion_tokens,
    total_tokens,
    prompt_eval_duration,
    eval_duration

):

    hallucination = contains_hallucination(
        answer
    )

    grounded = not hallucination

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
            estimate_tokens(answer),

        "hallucinationDetected":
            hallucination,

        "grounded":
            grounded,

        "latencyMs":
            latency_ms,

        "warmupLatencyMs":
            warmup_latency_ms,

        "promptTokens":
            prompt_tokens,

        "completionTokens":
            completion_tokens,

        "totalTokens":
            total_tokens,

        "promptEvalDuration":
            prompt_eval_duration,

        "evalDuration":
            eval_duration
    }


# ============================================================
# MAIN
# ============================================================

def run_benchmark():

    print("\n" + "=" * 70)

    print(
        "CHIRON — GOVERNED vs NO-EVIDENCE BASELINE"
    )

    print("=" * 70)

    print(f"\nBASE URL: {BASE_URL}")

    print(f"OLLAMA URL: {OLLAMA_URL}")

    print(f"TOTAL RUNS: {TOTAL_RUNS}")

    print(f"MODELS: {len(MODELS)}")

    print(f"QUESTIONS: {len(QUESTIONS)}")

    print(f"WINDOWS: {WINDOWS}")
    
    raw_zeek_context, selected_pcap = (
        load_raw_zeek_context()
    )

    print(
        f"\nRAW ZEEK CONTEXT SIZE: "
        f"{len(raw_zeek_context)} chars"
    )
    
    print(
        f"ACTIVE PCAP: {selected_pcap}"
    )

    for run in range(TOTAL_RUNS):

        print("\n" + "=" * 70)

        print(f"RUN {run+1}/{TOTAL_RUNS}")

        print("=" * 70)

        # ====================================================
        # MODEL-BATCHED EXECUTION
        # ====================================================

        for model in MODELS:

            print("\n" + "=" * 70)

            print(f"MODEL: {model}")

            print("=" * 70)

            warmup_latency_ms = warmup_model(
                model
            )

            for question in QUESTIONS:

                for window in WINDOWS:

                    print("\n" + "-" * 60)

                    print(f"QUESTION: {question}")

                    print(f"WINDOW: {window}m")

                    print("-" * 60)

                    # ========================================
                    # GOVERNED
                    # ========================================

                    try:

                        governed = ask_governed(

                            question=question,
                            model=model,
                            window=window
                        )

                        governed_eval = evaluate_response(

                            answer=
                                governed["answer"],

                            mode=
                                "governed",

                            model=
                                model,

                            question=
                                question,

                            window=
                                window,

                            latency_ms=
                                governed["latencyMs"],

                            warmup_latency_ms=
                                warmup_latency_ms,

                            prompt_tokens=
                                governed["promptTokens"],

                            completion_tokens=
                                governed["completionTokens"],

                            total_tokens=
                                governed["totalTokens"],

                            prompt_eval_duration=
                                governed["promptEvalDuration"],

                            eval_duration=
                                governed["evalDuration"]
                        )

                        RESULTS.append(
                            governed_eval
                        )

                        print("\nMODE: GOVERNED")

                        print("\nANSWER:")

                        print(
                            governed_eval["answer"]
                        )

                        print(
                            "\nHALLUCINATION:",
                            governed_eval[
                                "hallucinationDetected"
                            ]
                        )

                        print(
                            "LATENCY:",
                            governed_eval[
                                "latencyMs"
                            ]
                        )

                        print(
                            "PROMPT TOKENS:",
                            governed_eval[
                                "promptTokens"
                            ]
                        )

                        print(
                            "COMPLETION TOKENS:",
                            governed_eval[
                                "completionTokens"
                            ]
                        )

                        print(
                            "TOTAL TOKENS:",
                            governed_eval[
                                "totalTokens"
                            ]
                        )

                    except requests.exceptions.HTTPError as e:

                        if e.response.status_code == 403:

                            refusal_result = {

                                "model":
                                    model,

                                "mode":
                                    "governed_refusal",

                                "window":
                                    window,

                                "question":
                                    question,

                                "answer":
                                    "REFUSED_BY_GOVERNANCE",

                                "estimatedTokens":
                                    0,

                                "hallucinationDetected":
                                    False,

                                "grounded":
                                    True,

                                "latencyMs":
                                    0,

                                "warmupLatencyMs":
                                    warmup_latency_ms,

                                "promptTokens":
                                    0,

                                "completionTokens":
                                    0,

                                "totalTokens":
                                    0,

                                "promptEvalDuration":
                                    0,

                                "evalDuration":
                                    0,

                                "refused":
                                    True
                            }

                            RESULTS.append(
                                refusal_result
                            )

                            print(
                                "\nMODE: GOVERNED REFUSAL"
                            )

                            print(
                                "QUESTION REJECTED BY GOVERNANCE"
                            )

                        else:

                            print(
                                f"\nGOVERNED HTTP ERROR [{model}]: {e}"
                            )

                    except Exception as e:

                        print(
                            f"\nGOVERNED ERROR [{model}]: {e}"
                        )

                    # ========================================
                    # BASELINE
                    # ========================================

                    try:

                        baseline = ask_no_evidence_baseline(

                            question=question,
                            model=model
                        )

                        baseline_eval = evaluate_response(

                            answer=
                                baseline["answer"],

                            mode=
                                "no_evidence_baseline",

                            model=
                                model,

                            question=
                                question,

                            window=
                                window,

                            latency_ms=
                                baseline["latencyMs"],

                            warmup_latency_ms=
                                warmup_latency_ms,

                            prompt_tokens=
                                baseline["promptTokens"],

                            completion_tokens=
                                baseline["completionTokens"],

                            total_tokens=
                                baseline["totalTokens"],

                            prompt_eval_duration=
                                baseline["promptEvalDuration"],

                            eval_duration=
                                baseline["evalDuration"]
                        )

                        RESULTS.append(
                            baseline_eval
                        )

                        print(
                            "\nMODE: NO-EVIDENCE BASELINE"
                        )

                        print("\nANSWER:")

                        print(
                            baseline_eval["answer"]
                        )

                        print(
                            "\nHALLUCINATION:",
                            baseline_eval[
                                "hallucinationDetected"
                            ]
                        )

                        print(
                            "LATENCY:",
                            baseline_eval[
                                "latencyMs"
                            ]
                        )

                        print(
                            "PROMPT TOKENS:",
                            baseline_eval[
                                "promptTokens"
                            ]
                        )

                        print(
                            "COMPLETION TOKENS:",
                            baseline_eval[
                                "completionTokens"
                            ]
                        )

                        print(
                            "TOTAL TOKENS:",
                            baseline_eval[
                                "totalTokens"
                            ]
                        )

                    except Exception as e:

                        print(
                            f"\nBASELINE ERROR [{model}]: {e}"
                        )
                    # ========================================
                    # RAW ZEEK BASELINE
                    # ========================================

                    try:

                        raw_zeek = ask_raw_zeek_baseline(

                            question=question,

                            model=model,

                            raw_zeek_context=raw_zeek_context
                        )

                        raw_zeek_eval = evaluate_response(

                            answer=
                                raw_zeek["answer"],

                            mode=
                                "raw_zeek_baseline",

                            model=
                                model,

                            question=
                                question,

                            window=
                                window,

                            latency_ms=
                                raw_zeek["latencyMs"],

                            warmup_latency_ms=
                                warmup_latency_ms,

                            prompt_tokens=
                                raw_zeek["promptTokens"],

                            completion_tokens=
                                raw_zeek["completionTokens"],

                            total_tokens=
                                raw_zeek["totalTokens"],

                            prompt_eval_duration=
                                raw_zeek["promptEvalDuration"],

                            eval_duration=
                                raw_zeek["evalDuration"]
                        )

                        RESULTS.append(
                            raw_zeek_eval
                        )

                        print(
                            "\nMODE: RAW ZEEK BASELINE"
                        )

                        print("\nANSWER:")

                        print(
                            raw_zeek_eval["answer"]
                        )

                        print(
                            "\nHALLUCINATION:",
                            raw_zeek_eval[
                                "hallucinationDetected"
                            ]
                        )

                        print(
                            "LATENCY:",
                            raw_zeek_eval[
                                "latencyMs"
                            ]
                        )

                        print(
                            "PROMPT TOKENS:",
                            raw_zeek_eval[
                                "promptTokens"
                            ]
                        )

                        print(
                            "COMPLETION TOKENS:",
                            raw_zeek_eval[
                                "completionTokens"
                            ]
                        )

                        print(
                            "TOTAL TOKENS:",
                            raw_zeek_eval[
                                "totalTokens"
                            ]
                        )

                    except Exception as e:

                        print(
                            f"\nRAW ZEEK BASELINE ERROR [{model}]: {e}"
                        )    
                                        
                    

            print(
                f"\nCooling model: {model}"
            )
            
            

            time.sleep(
                MODEL_COOLDOWN_SECONDS
            )

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

        if r["mode"] == "no_evidence_baseline"
    ]
    
    raw_zeek = [

        r for r in RESULTS

        if r["mode"] == "raw_zeek_baseline"
    ]

    governed_hallucinations = len([

        r for r in governed

        if r["hallucinationDetected"]
    ])

    baseline_hallucinations = len([

        r for r in baseline

        if r["hallucinationDetected"]
    ])

    avg_governed_latency = safe_mean([

        r["latencyMs"]

        for r in governed
    ])

    avg_baseline_latency = safe_mean([

        r["latencyMs"]

        for r in baseline
    ])

    avg_governed_tokens = safe_mean([

        r["totalTokens"]

        for r in governed
    ])

    avg_baseline_tokens = safe_mean([

        r["totalTokens"]

        for r in baseline
    ])
    
    
    avg_raw_zeek_tokens = safe_mean([

        r["totalTokens"]

        for r in raw_zeek
    ])

    avg_raw_zeek_latency = safe_mean([

        r["latencyMs"]

        for r in raw_zeek
    ])

    avg_warmup_latency = safe_mean([

        r["warmupLatencyMs"]

        for r in RESULTS

        if r.get(
            "warmupLatencyMs"
        ) is not None
    ])

    print("\n" + "=" * 70)

    print("FINAL RESULTS")

    print("=" * 70)

    print(
        f"Total Evaluations: {total}"
    )

    print(
        f"Governed Hallucinations: "
        f"{governed_hallucinations}"
    )

    print(
        f"No-Evidence Baseline Hallucinations: "
        f"{baseline_hallucinations}"
    )

    print(
        f"Average Governed Latency: "
        f"{avg_governed_latency:.2f} ms"
    )

    print(
        f"Average Baseline Latency: "
        f"{avg_baseline_latency:.2f} ms"
    )

    print(
        f"Average Governed Tokens: "
        f"{avg_governed_tokens:.2f}"
    )

    print(
        f"Average Baseline Tokens: "
        f"{avg_baseline_tokens:.2f}"
    )
    
    print(
        f"Average Raw Zeek Tokens: "
        f"{avg_raw_zeek_tokens:.2f}"
    )

    print(
        f"Average Raw Zeek Latency: "
        f"{avg_raw_zeek_latency:.2f} ms"
    )

    print(
        f"Average Warmup Latency: "
        f"{avg_warmup_latency:.2f} ms"
    )

    out_file = (
        "chiron_noevidence_results.json"
    )

    with open(out_file, "w") as f:

        json.dump(
            RESULTS,
            f,
            indent=2
        )

    print(
        f"\nSaved -> {out_file}"
    )


# ============================================================
# ENTRY
# ============================================================

if __name__ == "__main__":

    run_benchmark()