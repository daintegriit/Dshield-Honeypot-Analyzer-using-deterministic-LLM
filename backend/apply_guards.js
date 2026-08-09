// apply_guards.js
//
// Adds two validity guards to analyze_ctu13.js, alongside the existing
// window-to-span rule. Both refuse to emit a confusion matrix under conditions
// that make one uninterpretable, and both say so in the output rather than
// omitting the field.
//
// GUARD 1 — UNREACHABLE THRESHOLD
//   The deployed operating point labels a window as predicted-attack when its
//   state is high or critical, i.e. risk >= 60. If no window could reach 60,
//   TP and FP are structurally zero and the matrix measures the evaluation.
//   Measured across 19 CTU-13 runs: observed ceilings 41.00 to 70.66, and
//   every single run had at least one unreachable state. Six could not reach
//   'elevated' at 45.
//
// GUARD 2 — EMPTY CLASS
//   With no malicious windows, recall is undefined and balanced accuracy
//   collapses to a function of specificity alone. CTU-13 scenario 8 has
//   malicious_n = 0 at every window width tested, because its botnet never
//   exceeds ~18% of a window against a 0.5 truth threshold. The same condition
//   made every pcap experiment before 2026-08-08 a presence check: baseline
//   windows contained no events at all, so "benign" meant "no traffic" and any
//   monotonic function of volume scored F1 = 1.0.
//
// Run from ~/backend:  node apply_guards.js

const fs = require("fs");
const F = "analyze_ctu13.js";
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

/* ------------------------------------------------------------------ */
/* 1. Compute the observed ceiling and evaluate both guards            */
/* ------------------------------------------------------------------ */

sub(
  "guards",
  `  const deployed = rates(deployedCm);`,
  `  const deployed = rates(deployedCm);

  // ------------------------------------------------------------------
  // VALIDITY GUARDS — refuse a confusion matrix that cannot mean anything.
  //
  // These sit alongside the window-to-span rule above. That rule catches too
  // few windows; these catch two conditions under which the right number of
  // windows still yields an uninterpretable matrix.
  // ------------------------------------------------------------------

  // Nominal budgets, from copilotCore.js RISK_BUDGET. Duplicated rather than
  // imported: a guard that shares a constant with the code it guards cannot
  // detect that constant changing in one place.
  const COMPONENT_BUDGETS = {
    severityComponent: 25,
    behaviorComponent: 20,
    entropyComponent: 20,
    concentrationComponent: 15,
    signalAmplifier: 25,
    c2Bonus: 20,
    impactBonus: 12,
    couplingBonus: 5,
    volumeComponent: 0, // retired v4.0
  };

  // The operating point predicts attack at state high or critical.
  const DEPLOYED_STATE_THRESHOLD = 60;

  const componentMaxima = {};
  const componentNonZero = {};
  for (const w of windows) {
    const rc = w.riskComponents || {};
    for (const [k, raw] of Object.entries(rc)) {
      const v = Number(raw) || 0;
      componentMaxima[k] = Math.max(componentMaxima[k] || 0, v);
      if (v > 0) componentNonZero[k] = (componentNonZero[k] || 0) + 1;
    }
  }
  const observedCeiling = +Object.values(componentMaxima)
    .reduce((a, b) => a + b, 0)
    .toFixed(2);

  const neverExercised = Object.keys(COMPONENT_BUDGETS).filter(
    (k) => COMPONENT_BUDGETS[k] > 0 && !componentNonZero[k]
  );

  const nMalicious = windows.filter((w) => w.botnet_fraction >= DEPLOYED_TRUTH_THR).length;
  const nBenign = windows.length - nMalicious;

  const guardFailures = [];

  if (observedCeiling < DEPLOYED_STATE_THRESHOLD) {
    guardFailures.push({
      guard: "UNREACHABLE_THRESHOLD",
      detail:
        \`the deployed operating point predicts attack at risk >= \${DEPLOYED_STATE_THRESHOLD}, \` +
        \`but the highest attainable score over \${windows.length} scored windows is \` +
        \`\${observedCeiling}. No window could be predicted attack, so TP and FP are \` +
        \`structurally zero and the matrix describes the evaluation rather than the detector.\`,
      observed_ceiling: observedCeiling,
      required: DEPLOYED_STATE_THRESHOLD,
      component_maxima: componentMaxima,
      never_exercised: neverExercised,
    });
  }

  if (nMalicious === 0 || nBenign === 0) {
    const empty = nMalicious === 0 ? "malicious" : "benign";
    guardFailures.push({
      guard: "EMPTY_CLASS",
      detail:
        \`no \${empty} windows at truth threshold \${DEPLOYED_TRUTH_THR} \` +
        \`(malicious \${nMalicious}, benign \${nBenign} of \${windows.length}). \` +
        \`Recall or specificity is undefined and balanced accuracy reduces to a \` +
        \`function of the populated class alone.\`,
      malicious_n: nMalicious,
      benign_n: nBenign,
      truth_threshold: DEPLOYED_TRUTH_THR,
    });
  }

  if (guardFailures.length) {
    console.log("");
    console.log("  " + "!".repeat(70));
    console.log("  ⚠️  VALIDITY GUARD — confusion matrix withheld");
    console.log("  " + "!".repeat(70));
    for (const g of guardFailures) {
      console.log(\`     [\${g.guard}]\`);
      console.log(\`     \${g.detail}\`);
      if (g.never_exercised && g.never_exercised.length) {
        console.log(\`     never exercised: \${g.never_exercised.join(", ")}\`);
      }
      console.log("");
    }
    console.log("     Correlation and risk separation are still reported where both");
    console.log("     classes are populated. The binary metrics are not.");
    console.log("");
  }

  // Withheld, not omitted: a stale run in the archive should say why it has no
  // matrix rather than appear to have lost the field.
  const deployedReported = guardFailures.length
    ? {
        withheld: true,
        reason: guardFailures.map((g) => g.guard).join("+"),
        guards: guardFailures,
        truth_threshold: DEPLOYED_TRUTH_THR,
        // retained so the withheld values can be inspected deliberately
        would_have_been: { ...deployedCm, ...deployed },
      }
    : { truth_threshold: DEPLOYED_TRUTH_THR, ...deployed };`
);

/* ------------------------------------------------------------------ */
/* 2. Emit the guarded field and a reachability block                  */
/* ------------------------------------------------------------------ */

sub(
  "output",
  `    deployed_operating_point: { truth_threshold: DEPLOYED_TRUTH_THR, ...deployed },`,
  `    deployed_operating_point: deployedReported,
    reachability: {
      observed_ceiling: observedCeiling,
      nominal_budget: Object.values(COMPONENT_BUDGETS).reduce((a, b) => a + b, 0),
      deployed_state_threshold: DEPLOYED_STATE_THRESHOLD,
      component_maxima: componentMaxima,
      component_nonzero_windows: componentNonZero,
      never_exercised: neverExercised,
    },
    guard_failures: guardFailures,`
);

fs.copyFileSync(F, F + ".bak_preguards");
fs.writeFileSync(F, s);
console.log("\nwrote " + F + "  (backup: " + F + ".bak_preguards)");
