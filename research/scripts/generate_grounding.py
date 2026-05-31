#!/usr/bin/env python3

import json
import pandas as pd
import matplotlib.pyplot as plt

# ======================================================
# CONFIG
# ======================================================

INPUT_FILE = "chiron_llm_comparison_results.json"
OUTPUT_FILE = "governed_vs_baseline_tokens.png"

# ======================================================
# IEEE / ACSAC STYLE
# ======================================================

plt.rcParams.update({
    "font.size": 8
})

# ======================================================
# LOAD JSON
# ======================================================

with open(INPUT_FILE, "r") as f:
    data = json.load(f)

# ======================================================
# EXTRACT TOKEN DATA
# ======================================================

rows = []

for entry in data:

    rows.append({
        "model": entry["model"],
        "mode": entry["mode"],
        "tokens": entry["estimatedTokens"]
    })

df = pd.DataFrame(rows)

# ======================================================
# AGGREGATE TOKEN COUNTS
# ======================================================

summary = (
    df.groupby(["model", "mode"])["tokens"]
      .mean()
      .reset_index()
)

pivot = summary.pivot(
    index="model",
    columns="mode",
    values="tokens"
)

# ======================================================
# SORT MODELS
# ======================================================

desired_order = [
    "gemma",
    "llama3.1:8b",
    "mistral",
    "phi3",
    "qwen2.5:7b-instruct"
]

pivot = pivot.reindex(desired_order)

# ======================================================
# PRINT SUMMARY
# ======================================================

print("\n================================================")
print("AVERAGE OUTPUT TOKENS")
print("================================================\n")

print(pivot)

# ======================================================
# PLOT
# ======================================================

ax = pivot.plot(
    kind="bar",
    figsize=(7, 3.2)
)

# ------------------------------------------------------
# LABELS
# ------------------------------------------------------

plt.ylabel("Average Output Tokens")
plt.xlabel("LLM")

plt.title(
    "Governed vs Baseline Operational Output Size"
)

# ------------------------------------------------------
# LEGEND
# ------------------------------------------------------

handles, labels = ax.get_legend_handles_labels()

ax.legend(
    handles,
    ["Baseline", "Governed"],
    frameon=True,
    fontsize=7
)

# ------------------------------------------------------
# TICKS
# ------------------------------------------------------

plt.xticks(
    rotation=0,
    fontsize=7
)

plt.yticks(fontsize=7)

# ------------------------------------------------------
# GRID
# ------------------------------------------------------

plt.grid(
    axis="y",
    linestyle="--",
    alpha=0.4
)

# ------------------------------------------------------
# LAYOUT
# ------------------------------------------------------

plt.tight_layout(pad=0.4)

# ======================================================
# SAVE
# ======================================================

plt.savefig(
    OUTPUT_FILE,
    dpi=300,
    bbox_inches="tight"
)

print("\n================================================")
print("SAVED:")
print(OUTPUT_FILE)
print("================================================\n")