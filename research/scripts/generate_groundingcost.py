#!/usr/bin/env python3

import json
import pandas as pd
import matplotlib.pyplot as plt

# ======================================================
# CONFIG
# ======================================================

INPUT_FILE = "chiron_llm_comparison_results.json"

plt.rcParams.update({
    "font.size": 8
})

# ======================================================
# LOAD JSON
# ======================================================

with open(INPUT_FILE, "r") as f:
    data = json.load(f)

# ======================================================
# EXTRACT METRICS
# ======================================================

rows = []

for entry in data:
    rows.append({
        "model": entry["model"],
        "mode": entry["mode"],
        "estimatedTokens": entry["estimatedTokens"],
        "totalTokens": entry["totalTokens"],
        "latencyMs": entry["latencyMs"],
        "grounded": entry["grounded"],
        "hallucinationDetected": entry["hallucinationDetected"],
        "passed": entry["passed"]
    })

df = pd.DataFrame(rows)

# ======================================================
# TOKEN-BASED COST / OVERHEAD
# ======================================================

df["inferenceCostTokens"] = df["totalTokens"]

# ======================================================
# AGGREGATE
# ======================================================

summary = (
    df.groupby(["model", "mode"])
      .agg({
          "estimatedTokens": "mean",
          "totalTokens": "mean",
          "latencyMs": "mean",
          "inferenceCostTokens": "mean",
          "grounded": "mean",
          "passed": "mean"
      })
      .reset_index()
)

# ======================================================
# PIVOTS
# ======================================================

token_pivot = summary.pivot(
    index="model",
    columns="mode",
    values="estimatedTokens"
)

latency_pivot = summary.pivot(
    index="model",
    columns="mode",
    values="latencyMs"
)

cost_pivot = summary.pivot(
    index="model",
    columns="mode",
    values="inferenceCostTokens"
)

# ======================================================
# MODEL ORDER
# ======================================================

desired_order = [
    "gemma",
    "llama3.1:8b",
    "mistral",
    "phi3",
    "qwen2.5:7b-instruct"
]

token_pivot = token_pivot.reindex(desired_order)
latency_pivot = latency_pivot.reindex(desired_order)
cost_pivot = cost_pivot.reindex(desired_order)

# ======================================================
# COMPUTE REDUCTIONS
# ======================================================

comparison_rows = []

for model in desired_order:
    governed_tokens = token_pivot.loc[model, "governed"]
    baseline_tokens = token_pivot.loc[model, "baseline"]

    governed_latency = latency_pivot.loc[model, "governed"]
    baseline_latency = latency_pivot.loc[model, "baseline"]

    governed_cost = cost_pivot.loc[model, "governed"]
    baseline_cost = cost_pivot.loc[model, "baseline"]

    token_reduction = (
        (baseline_tokens - governed_tokens)
        / baseline_tokens
    ) * 100

    latency_change = (
        (baseline_latency - governed_latency)
        / baseline_latency
    ) * 100

    cost_reduction = (
        (baseline_cost - governed_cost)
        / baseline_cost
    ) * 100

    comparison_rows.append({
        "model": model,
        "tokenReductionPercent": round(token_reduction, 2),
        "latencyChangePercent": round(latency_change, 2),
        "costReductionPercent": round(cost_reduction, 2)
    })

comparison_df = pd.DataFrame(comparison_rows)

# ======================================================
# PRINT RESULTS
# ======================================================

print("\n================================================")
print("TOKEN COMPARISON")
print("================================================\n")
print(token_pivot)

print("\n================================================")
print("LATENCY COMPARISON")
print("================================================\n")
print(latency_pivot)

print("\n================================================")
print("TOKEN-BASED INFERENCE COST")
print("================================================\n")
print(cost_pivot)

print("\n================================================")
print("REDUCTION SUMMARY")
print("================================================\n")
print(comparison_df)

# ======================================================
# SAVE CSV
# ======================================================

comparison_df.to_csv(
    "governed_vs_baseline_summary.csv",
    index=False
)

summary.to_csv(
    "governed_vs_baseline_raw_metrics.csv",
    index=False
)

# ======================================================
# STYLE LEGEND
# ======================================================

def style_plot(ax):
    handles, labels = ax.get_legend_handles_labels()
    clean_labels = [
        label.capitalize()
        for label in labels
    ]

    ax.legend(
        handles,
        clean_labels,
        frameon=True,
        fontsize=7
    )

    plt.xticks(rotation=0, fontsize=7)
    plt.yticks(fontsize=7)

    plt.grid(
        axis="y",
        linestyle="--",
        alpha=0.4
    )

    plt.tight_layout(pad=0.4)

# ======================================================
# TOKEN CHART
# ======================================================

ax = token_pivot.plot(
    kind="bar",
    figsize=(7, 3.2)
)

plt.ylabel("Average Output Tokens")
plt.xlabel("LLM")
plt.title("Governed vs Baseline Operational Output Size")

style_plot(ax)

plt.savefig(
    "governed_vs_baseline_tokens.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

# ======================================================
# LATENCY CHART
# ======================================================

ax = latency_pivot.plot(
    kind="bar",
    figsize=(7, 3.2)
)

plt.ylabel("Average Latency (ms)")
plt.xlabel("LLM")
plt.title("Governed vs Baseline Inference Latency")

style_plot(ax)

plt.savefig(
    "governed_vs_baseline_latency.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

# ======================================================
# COST CHART — RAW TOKEN-BASED COST
# ======================================================

ax = cost_pivot.plot(
    kind="bar",
    figsize=(7, 3.2)
)

plt.ylabel("Token-Based Inference Cost")
plt.xlabel("LLM")
plt.title("Governed vs Baseline Token-Based Inference Cost")

style_plot(ax)

plt.savefig(
    "governed_vs_baseline_cost.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

# ======================================================
# COST REDUCTION CHART
# ======================================================

plt.figure(figsize=(7, 3.2))

plt.bar(
    comparison_df["model"],
    comparison_df["costReductionPercent"]
)

plt.ylabel("Cost Reduction (%)")
plt.xlabel("LLM")
plt.title("Governed Token-Based Inference Cost Reduction")

plt.xticks(rotation=0, fontsize=7)
plt.yticks(fontsize=7)

plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.4
)

plt.tight_layout(pad=0.4)

plt.savefig(
    "governed_cost_reduction.png",
    dpi=300,
    bbox_inches="tight"
)

plt.close()

# ======================================================
# FINAL
# ======================================================

print("\n================================================")
print("SAVED FILES")
print("================================================")
print(" - governed_vs_baseline_tokens.png")
print(" - governed_vs_baseline_latency.png")
print(" - governed_vs_baseline_cost.png")
print(" - governed_cost_reduction.png")
print(" - governed_vs_baseline_summary.csv")
print(" - governed_vs_baseline_raw_metrics.csv")
print("================================================\n")