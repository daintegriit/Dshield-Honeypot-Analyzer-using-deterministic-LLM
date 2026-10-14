// apply_guard3.js
//
// GUARD 3 — SATURATED / INVARIANT COMPONENTS
//
// A component that takes the same value in every window contributes a constant
// offset and cannot affect the ranking between windows. It looks like a
// contributing signal in the score decomposition and carries no information.
//
// Two distinct conditions, reported separately:
//
//   SATURATED  pinned at or near its cap in nearly every window. The cap is
//              too low for the traffic: information above it is discarded.
//              Measured on this system --- entropyComponent sat at its 20-point
//              ceiling in 59 of 60 live honeypot windows, its ceiling being
//              log2(10) = 3.32 bits, which any window touching ten ports
//              exceeds. The earlier dosScore had the same pathology: a
//              log10 term reaching its 60-point cap at ~1,000 events per
//              window, saturating in 100% of CTU-13 scenario 1 windows, so
//              pickTop() returned "dos" for every window and the attack-type
//              table was uninformative by construction.
//
//   INVARIANT  constant across windows at any value, not necessarily the cap.
//              Same consequence for discrimination, different cause.
//
// Unlike guards 1 and 2 this does NOT withhold the confusion matrix. A
// saturated component does not make the matrix uninterpretable; it means one
// input to the score is inert. That belongs in the output as a warning, and in
// the write-up as a caveat on any claim about multi-signal fusion.
//
// Run from ~/backend:  node apply_guard3.js

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
/* Compute per-component distribution stats and evaluate guard 3       */
/* ------------------------------------------------------------------ */

sub(
  "guard3",
  `  const guardFailures = [];`,
  `  // ------------------------------------------------------------------
  // GUARD 3 — saturated / invariant components.
  //
  // Reported, not withheld: an inert component does not invalidate the
  // matrix, it invalidates claims that the score fuses multiple signals.
  // ------------------------------------------------------------------
  const SATURATION_VALUE_FRAC = 0.95;  // "at its cap" means >= 95% of budget
  const SATURATION_WINDOW_FRAC = 0.95; // "in nearly every window"
  const INVARIANCE_CV = 0.01;          // coefficient of variation below this

  const componentSeries = {};
  for (const w of windows) {
    const rc = w.riskComponents || {};
    for (const [k, raw] of Object.entries(rc)) {
      (componentSeries[k] = componentSeries[k] || []).push(Number(raw) || 0);
    }
  }

  const componentStats = {};
  const inertComponents = [];

  for (const [name, series] of Object.entries(componentSeries)) {
    const budget = COMPONENT_BUDGETS[name] || 0;
    const n = series.length;
    if (!n) continue;

    const mu = series.reduce((a, b) => a + b, 0) / n;
    const variance = series.reduce((a, v) => a + (v - mu) ** 2, 0) / n;
    const sd = Math.sqrt(variance);
    const cv = mu > 0 ? sd / mu : 0;
    const atCap = budget > 0
      ? series.filter((v) => v >= budget * SATURATION_VALUE_FRAC).length
      : 0;

    componentStats[name] = {
      budget,
      mean: +mu.toFixed(3),
      sd: +sd.toFixed(3),
      cv: +cv.toFixed(4),
      min: +Math.min(...series).toFixed(3),
      max: +Math.max(...series).toFixed(3),
      windows_at_cap: atCap,
      windows: n,
    };

    if (budget > 0 && atCap >= n * SATURATION_WINDOW_FRAC) {
      inertComponents.push({
        component: name,
        condition: "SATURATED",
        detail:
          \`at >= \${Math.round(SATURATION_VALUE_FRAC * 100)}% of its \${budget}-point budget \` +
          \`in \${atCap} of \${n} windows. The cap discards any variation above it, so the \` +
          \`component contributes a near-constant offset and cannot separate windows.\`,
        ...componentStats[name],
      });
    } else if (budget > 0 && mu > 0 && cv < INVARIANCE_CV) {
      inertComponents.push({
        component: name,
        condition: "INVARIANT",
        detail:
          \`constant at \${mu.toFixed(2)} across all \${n} windows \` +
          \`(cv = \${cv.toFixed(4)}). Contributes a fixed offset to every score and \` +
          \`cannot affect the ranking between windows.\`,
        ...componentStats[name],
      });
    }
  }

  if (inertComponents.length) {
    console.log("");
    console.log("  " + "~".repeat(70));
    console.log("  ⚠️  VALIDITY WARNING — component carries no discriminative information");
    console.log("  " + "~".repeat(70));
    for (const c of inertComponents) {
      console.log(\`     [\${c.condition}] \${c.component}\`);
      console.log(\`     \${c.detail}\`);
      console.log(
        \`     mean \${c.mean}  sd \${c.sd}  range \${c.min}..\${c.max}  budget \${c.budget}\`
      );
      console.log("");
    }
    console.log("     The confusion matrix is unaffected and is reported as normal.");
    console.log("     Claims that the score fuses these signals are not supported.");
    console.log("");
  }

  const guardFailures = [];`
);

/* ------------------------------------------------------------------ */
/* Emit in the output object                                           */
/* ------------------------------------------------------------------ */

sub(
  "output3",
  `    guard_failures: guardFailures,`,
  `    guard_failures: guardFailures,
    component_distribution: componentStats,
    inert_components: inertComponents,`
);

fs.copyFileSync(F, F + ".bak_preguard3");
fs.writeFileSync(F, s);
console.log("\nwrote " + F + "  (backup: " + F + ".bak_preguard3)");
