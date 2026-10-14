#!/usr/bin/env node
//
// add_config_provenance.js — records the detector configuration in every run.
//
// WHY
// ---
// A run's output records which guards ran and what they returned. Nothing
// records what the DETECTOR was configured to do while producing it.
//
// The ablated batch of 2026-08-09 ran with four C2 gates disabled and budget
// normalisation enabled. The earlier batch of 2026-08-08 ran with the same
// harness, the same captures, the same labels, and the gates at their defaults.
// The two sets of JSON are indistinguishable: same fields, same shape, F1 of
// 0.933 in one and 0 in the other, with nothing in either file explaining the
// difference.
//
// That is the same failure the guards block was added to prevent, one level
// down. A result should carry the configuration that produced it.
//
// This asks the backend for its own configuration at run start, via the
// riskBudget block the core already publishes, and records it alongside the
// results.
//
// Run from ~/research/scripts:  node add_config_provenance.js

const fs = require("fs");
const F = "run_full_experiment.js";
let s = fs.readFileSync(F, "utf8");

function sub(name, oldStr, newStr) {
  const n = s.split(oldStr).length - 1;
  if (n !== 1) {
    console.error(`FAIL [${name}]: anchor matched ${n} times, expected 1`);
    process.exit(1);
  }
  s = s.replace(oldStr, newStr);
  console.log(`ok   [${name}]`);
}

// --- capture the detector config once, at run start ---------------------
sub(
  "capture",
  "  const output = {",
  `  // Detector configuration as reported by the backend itself, rather than as
  // assumed by this harness. The core publishes its risk budget, profile and
  // normalisation state; the C2 gate values are read from the environment the
  // backend was started with, which this harness cannot see directly and so
  // records as "unknown" unless supplied.
  let detectorConfig = { captured: false };
  try {
    const probe = await fetchJSON(
      \`\${BASE_URL}/api/copilot/insight?minutes=1&source=\${SOURCE_SCOPE}\`
    );
    const budget = probe?.coreSummary?.riskBudget || {};
    detectorConfig = {
      captured: true,
      capturedAt: new Date().toISOString(),
      coreVersion: probe?.coreSummary?.coreVersion || null,
      riskProfile: budget.profile || null,
      normalised: budget.normalised ?? null,
      reachableBudget: budget.reachableBudget ?? null,
      referenceBudget: budget.referenceBudget ?? null,
      reachable: budget.reachable || null,
      stateThresholds: { elevated: 45, high: 60, critical: 85 },
      // Supplied by the caller when running an ablation; absent means the
      // backend defaults were in effect, which this harness cannot verify.
      c2Gates: {
        minEvents: process.env.C2_MIN_EVENTS ?? "backend default",
        minFlowCount: process.env.C2_MIN_FLOW_COUNT ?? "backend default",
        minSpanSec: process.env.C2_MIN_SPAN_SEC ?? "backend default",
        bonusMinScore: process.env.C2_BONUS_MIN_SCORE ?? "backend default",
      },
      replay: {
        mode: process.env.REPLAY_MODE || "scaled_ts",
        sourceWindowPre: Number(process.env.SOURCE_WINDOW_PRE || 0),
        sourceWindowPost: Number(process.env.SOURCE_WINDOW_POST || 0),
        targetDurationSeconds: Number(process.env.TARGET_DURATION_SECONDS || 5400),
      },
      note:
        "c2Gates values marked 'backend default' were not set by this harness. " +
        "The backend is a separate long-running process and may have been " +
        "started with overrides this run cannot observe.",
    };
  } catch (e) {
    detectorConfig = { captured: false, error: e.message };
  }

  const output = {`
);

// --- emit it -------------------------------------------------------------
sub(
  "emit",
  "    runId,",
  "    runId,\n    detectorConfig,"
);

fs.copyFileSync(F, F + ".bak_preconfig");
fs.writeFileSync(F, s);
console.log("\nwrote " + F + "  (backup: " + F + ".bak_preconfig)");
console.log();
console.log("NOTE: the probe uses fetchJSON and BASE_URL. If this harness names");
console.log("those differently, adjust the inserted block accordingly.");

