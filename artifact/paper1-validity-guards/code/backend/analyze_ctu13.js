/**
 * analyze_ctu13.js
 * ---------------------------------------------------------------------------
 * Offline evaluation of the Chiron deterministic detector against CTU-13
 * hand-labeled ground truth.
 *
 * WHY THIS EXISTS
 * ---------------
 * The reviewers' core criticism was that the evaluation did not measure the
 * detector against verified ground truth. CTU-13 provides per-flow labels
 * (Botnet / Normal / Background) assigned manually by the Stratosphere lab.
 * After replaying a scenario with replay_ctu13.py, every ingested document
 * carries its label in ctu_class / ctu_subclass. This script walks the replay
 * window-by-window, scores each window with the REAL production core
 * (buildCopilotCore, via its new windowEnd parameter — no reimplementation),
 * and compares the detector's verdict to the labels.
 *
 * WHAT IT REPORTS
 * ---------------
 *  1. Per-window records: (botnet_fraction, riskScore, state, dominantAttack, ...)
 *  2. Binary detection metrics swept across botnet-fraction thresholds AND
 *     risk-score thresholds -> lets you plot ROC rather than assert one
 *     arbitrary operating point.
 *  3. Risk separation: mean riskScore on malicious vs benign windows.
 *  4. C2-specific evaluation: does attackTypeScores.c2 rise on windows that
 *     actually contain labeled C&C flows?
 *  5. Attack-type confusion: dominantAttack.type vs the dominant ctu_subclass.
 *
 * IMPORTANT HONESTY NOTES
 * -----------------------
 *  - Windows are over INGEST wall-clock (`timestamp`), not the original 2011
 *    capture time. The replay compresses the capture, so this is the correct
 *    axis for scoring, but it means absolute rates differ from the original.
 *  - Background flows are excluded from ground truth (CTU treats them as
 *    unlabeled/uncertain). If a replay included them they still influence the
 *    detector's inputs, which is realistic, but they never count as truth.
 *  - The Chiron attack taxonomy (dos/scan/brute_force/web_probe/c2/impact) does
 *    NOT map 1:1 onto the CTU-13 behaviour labels (c2/spam/dns/ad/download).
 *    Only `c2` is a genuine overlap. The type-confusion table is therefore
 *    reported as-is, without forcing a mapping.
 *
 * USAGE
 *   node analyze_ctu13.js --pcap ctu13-s1
 *   node analyze_ctu13.js --pcap ctu13-s1 --window 1 --step 1
 *   node analyze_ctu13.js --pcap ctu13-s1 --out results_s1.json
 */

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");

const Attack = require("./models/AttackModel");
const { buildCopilotCore } = require("./services/copilotCore");

// ---------------- ARGS ----------------

function arg(name, def = null) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith("--") ? v : true;
}

const PCAP = arg("pcap", "ctu13-s1");
const WINDOW_MIN = Number(arg("window", 1)); // scoring window size (minutes)
const STEP_MIN = Number(arg("step", 1)); // stride between windows (minutes)
const OUT = arg("out", null);
const FORCE = arg("force", false) !== false;  // --force bypasses the validity guard

// ---------------- HELPERS ----------------

function mean(a) {
  return a.length ? a.reduce((x, y) => x + y, 0) / a.length : null;
}

function rates({ TP, FP, TN, FN }) {
  const total = TP + FP + TN + FN;
  const precision = TP + FP === 0 ? 0 : TP / (TP + FP);
  const recall = TP + FN === 0 ? 0 : TP / (TP + FN);
  const specificity = TN + FP === 0 ? 0 : TN / (TN + FP);
  const fpr = FP + TN === 0 ? 0 : FP / (FP + TN);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return {
    total_windows: total,
    TP, FP, TN, FN,
    precision: +precision.toFixed(4),
    recall: +recall.toFixed(4),
    specificity: +specificity.toFixed(4),
    fpr: +fpr.toFixed(4),
    accuracy: total ? +((TP + TN) / total).toFixed(4) : 0,
    balanced_accuracy: +(((recall + specificity) / 2)).toFixed(4),
    f1: +f1.toFixed(4),
  };
}

/** Pearson correlation. */
function pearson(xs, ys) {
  const n = xs.length;
  if (n < 3) return null;
  const mx = mean(xs), my = mean(ys);
  let num = 0, dx = 0, dy = 0;
  for (let i = 0; i < n; i++) {
    const a = xs[i] - mx, b = ys[i] - my;
    num += a * b; dx += a * a; dy += b * b;
  }
  const den = Math.sqrt(dx * dy);
  return den === 0 ? null : +(num / den).toFixed(4);
}

// ---------------- MAIN ----------------

(async () => {
  await mongoose.connect(process.env.MONGO_URI, { socketTimeoutMS: 0 });

  console.log("=".repeat(76));
  console.log("        CTU-13 GROUND-TRUTH EVALUATION OF THE CHIRON DETECTOR");
  console.log("=".repeat(76));
  console.log(`  replay_pcap:   ${PCAP}`);
  console.log(`  window:        ${WINDOW_MIN} min   step: ${STEP_MIN} min`);

  // ---- 1. Establish the replay's ingest time range ----
  const first = await Attack.findOne({ replay_pcap: PCAP }).sort({ timestamp: 1 }).select({ timestamp: 1 }).lean();
  const last = await Attack.findOne({ replay_pcap: PCAP }).sort({ timestamp: -1 }).select({ timestamp: 1 }).lean();

  if (!first || !last) {
    console.log(`\n❌ No documents found for replay_pcap="${PCAP}". Did the replay run?`);
    await mongoose.disconnect();
    process.exit(1);
  }

  const t0 = new Date(first.timestamp).getTime();
  const t1 = new Date(last.timestamp).getTime();
  const spanMin = (t1 - t0) / 60000;

  console.log(`  ingest span:   ${new Date(t0).toISOString()} → ${new Date(t1).toISOString()}`);
  console.log(`                 ${spanMin.toFixed(1)} minutes`);

  // ------------------------------------------------------------------
  // VALIDITY GUARD — refuse to produce degenerate metrics.
  //
  // A scoring window must be small relative to the replay span, or you get
  // too few windows for any statistic to mean anything. Observed failure:
  // CTU-13 scenario 2 (14.0 min span) analysed at 15-min windows produced
  // exactly ONE window, with correlation = null and F1 = 1.000 computed on
  // n=1. Those numbers are not wrong so much as meaningless, and they look
  // like results.
  //
  // Rule: window <= span/3 (i.e. at least 3 non-overlapping window widths
  // fit in the replay). This is a floor, not a guarantee of sufficiency —
  // check windows_scored and benign_n/malicious_n in the output too.
  //
  // Override with --force if you explicitly want the degenerate output.
  // ------------------------------------------------------------------
  const maxValidWindow = Math.floor(spanMin / 3);
  if (WINDOW_MIN * 3 > spanMin && !FORCE) {
    console.log("");
    console.log("  " + "!".repeat(70));
    console.log(`  ⚠️  WINDOW TOO LARGE FOR THIS REPLAY — refusing to run.`);
    console.log("  " + "!".repeat(70));
    console.log(`     replay span : ${spanMin.toFixed(1)} min`);
    console.log(`     window size : ${WINDOW_MIN} min`);
    console.log(`     rule        : window <= span/3`);
    console.log(`     max valid   : ${maxValidWindow} min`);
    console.log("");
    console.log(`     A ${WINDOW_MIN}-min window over a ${spanMin.toFixed(1)}-min replay yields too few`);
    console.log(`     windows for correlations or confusion matrices to be meaningful.`);
    console.log("");
    console.log(`     Options:`);
    console.log(`       - use --window ${maxValidWindow} (or smaller)`);
    console.log(`       - re-replay slower to lengthen the span:`);
    console.log(`           SEND_DELAY=0.1 python3 replay_ctu13.py --scenario N`);
    console.log(`       - use --force to override (output will be degenerate)`);
    console.log("");
    await mongoose.disconnect();
    process.exit(2);
  }

  if (WINDOW_MIN * 6 > spanMin) {
    console.log(`  ⚠️  marginal: window=${WINDOW_MIN}min vs span=${spanMin.toFixed(1)}min ` +
                `(only ~${Math.floor(spanMin / WINDOW_MIN)} independent windows). ` +
                `Treat the statistics as indicative, not conclusive.`);
  }

  // ---- 2. Overall label census ----
  const census = await Attack.aggregate([
    { $match: { replay_pcap: PCAP } },
    { $group: { _id: "$ctu_class", n: { $sum: 1 } } },
  ]);
  const subCensus = await Attack.aggregate([
    { $match: { replay_pcap: PCAP } },
    { $group: { _id: "$ctu_subclass", n: { $sum: 1 } } },
    { $sort: { n: -1 } },
  ]);

  console.log("\n  ground truth census:");
  census.forEach((c) => console.log(`    ${String(c._id).padEnd(12)} ${c.n.toLocaleString()}`));
  console.log("  subclass census:");
  subCensus.forEach((c) => console.log(`    ${String(c._id).padEnd(12)} ${c.n.toLocaleString()}`));
  console.log("-".repeat(76));

  // ---- 3. Walk windows, score with the PRODUCTION core ----
  const windows = [];
  const stepMs = STEP_MIN * 60000;
  const winMs = WINDOW_MIN * 60000;

  // Start at t0+window so the first window is fully populated.
  let cursor = t0 + winMs;
  let idx = 0;

  console.log("\n🔬 Scoring windows with buildCopilotCore(windowEnd=...)\n");

  while (cursor <= t1 + stepMs) {
    const windowEnd = new Date(cursor);
    const windowStart = new Date(cursor - winMs);

    // --- ground truth composition for THIS window ---
    const comp = await Attack.aggregate([
      {
        $match: {
          replay_pcap: PCAP,
          timestamp: { $gte: windowStart, $lte: windowEnd },
        },
      },
      { $group: { _id: "$ctu_subclass", n: { $sum: 1 } } },
    ]);

    const counts = {};
    let labeled = 0;
    for (const c of comp) {
      const k = c._id || "unlabeled";
      counts[k] = c.n;
      if (k !== "background" && k !== "unlabeled") labeled += c.n;
    }

    const botnetCount = Object.entries(counts)
      .filter(([k]) => k !== "normal" && k !== "background" && k !== "unlabeled")
      .reduce((s, [, v]) => s + v, 0);
    const normalCount = counts["normal"] || 0;
    const c2Count = counts["c2"] || 0;

    // Skip empty windows entirely — nothing to score or compare.
    if (labeled === 0) {
      cursor += stepMs;
      idx++;
      continue;
    }

    const botnetFraction = labeled > 0 ? botnetCount / labeled : 0;

    // --- detector verdict, scored by the REAL core at this instant ---
    const core = await buildCopilotCore({
      minutes: WINDOW_MIN,
      sourceFilter: "replay",
      windowEnd,
    });

    // dominant ground-truth behaviour in this window (for the type table)
    const dominantTruth = Object.entries(counts)
      .filter(([k]) => k !== "background" && k !== "unlabeled")
      .sort((a, b) => b[1] - a[1])[0]?.[0] || "none";

    const rec = {
      idx,
      windowStart: windowStart.toISOString(),
      windowEnd: windowEnd.toISOString(),

      // ground truth
      labeled_flows: labeled,
      botnet_flows: botnetCount,
      normal_flows: normalCount,
      c2_flows: c2Count,
      botnet_fraction: +botnetFraction.toFixed(4),
      dominant_truth: dominantTruth,
      truth_counts: counts,

      // detector output (production core)
      riskScore: core.riskScore0to100,
      state: core.state,
      dominantAttack: core.attackClassification.dominantAttack.type,
      dominantAttackScore: +core.attackClassification.dominantAttack.score.toFixed(2),
      attackTypeScores: core.attackClassification.attackTypeScores,
      riskComponents: core.riskComponents,
      rateIndependentFeatures: core.rateIndependentFeatures || null,
      coreVersion: core.coreVersion,
      attackDetected: core.reasoning.attackDetected,
      eventsInWindow: core.scanningIndicators.windowedEventCount,
      scoringMode: core.scoringMode,
    };

    windows.push(rec);

    if (idx % 5 === 0) {
      console.log(
        `  [${rec.windowEnd.slice(11, 19)}] flows=${String(labeled).padStart(5)} ` +
        `bot%=${(botnetFraction * 100).toFixed(0).padStart(3)} ` +
        `c2=${String(c2Count).padStart(3)} | ` +
        `risk=${String(rec.riskScore).padStart(3)} state=${rec.state.padEnd(8)} ` +
        `dom=${rec.dominantAttack.padEnd(11)} c2score=${rec.attackTypeScores.c2.toFixed(0)}`
      );
    }

    cursor += stepMs;
    idx++;
  }

  console.log(`\n✅ Scored ${windows.length} non-empty windows`);

  if (windows.length === 0) {
    console.log("❌ No scoreable windows.");
    await mongoose.disconnect();
    process.exit(1);
  }

  // ---- 4. Binary metrics swept over BOTH thresholds ----
  // truth: window is malicious iff botnet_fraction >= truthThr
  // pred : detector fires iff riskScore >= riskThr
  const truthThrs = [0.01, 0.05, 0.10, 0.25, 0.50, 0.75];
  const riskThrs = [10, 20, 30, 40, 45, 50, 60, 70, 85];

  const sweep = [];
  for (const tt of truthThrs) {
    for (const rt of riskThrs) {
      const cm = { TP: 0, FP: 0, TN: 0, FN: 0 };
      for (const w of windows) {
        const truth = w.botnet_fraction >= tt;
        const pred = w.riskScore >= rt;
        if (truth && pred) cm.TP++;
        else if (!truth && pred) cm.FP++;
        else if (!truth && !pred) cm.TN++;
        else cm.FN++;
      }
      sweep.push({ truth_threshold: tt, risk_threshold: rt, ...rates(cm) });
    }
  }

  // The system's own deployed operating point: state high/critical => Attack
  const deployedCm = { TP: 0, FP: 0, TN: 0, FN: 0 };
  const DEPLOYED_TRUTH_THR = 0.5;
  for (const w of windows) {
    const truth = w.botnet_fraction >= DEPLOYED_TRUTH_THR;
    const pred = w.state === "high" || w.state === "critical";
    if (truth && pred) deployedCm.TP++;
    else if (!truth && pred) deployedCm.FP++;
    else if (!truth && !pred) deployedCm.TN++;
    else deployedCm.FN++;
  }
  const deployed = rates(deployedCm);

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
  // The threshold is compared against riskScore, so the guard must be too.
  // Summing per-component maxima overestimates: the maxima occur in different
  // windows and need not co-occur. Measured on CTU-13 s9, 100 windows:
  // summed maxima 59.06, actual highest riskScore 50.00 unnormalised and
  // 77.00 normalised. The sum was simultaneously too high to describe any real
  // window and blind to the normalisation applied after summation.
  const observedCeiling = +Math.max(...windows.map((w) => Number(w.riskScore) || 0)).toFixed(2);
  const summedComponentMaxima = +Object.values(componentMaxima)
    .reduce((a, b) => a + b, 0)
    .toFixed(2);

  const neverExercised = Object.keys(COMPONENT_BUDGETS).filter(
    (k) => COMPONENT_BUDGETS[k] > 0 && !componentNonZero[k]
  );

  const nMalicious = windows.filter((w) => w.botnet_fraction >= DEPLOYED_TRUTH_THR).length;
  const nBenign = windows.length - nMalicious;

  // ------------------------------------------------------------------
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
          `at >= ${Math.round(SATURATION_VALUE_FRAC * 100)}% of its ${budget}-point budget ` +
          `in ${atCap} of ${n} windows. The cap discards any variation above it, so the ` +
          `component contributes a near-constant offset and cannot separate windows.`,
        ...componentStats[name],
      });
    } else if (budget > 0 && mu > 0 && cv < INVARIANCE_CV) {
      inertComponents.push({
        component: name,
        condition: "INVARIANT",
        detail:
          `constant at ${mu.toFixed(2)} across all ${n} windows ` +
          `(cv = ${cv.toFixed(4)}). Contributes a fixed offset to every score and ` +
          `cannot affect the ranking between windows.`,
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
      console.log(`     [${c.condition}] ${c.component}`);
      console.log(`     ${c.detail}`);
      console.log(
        `     mean ${c.mean}  sd ${c.sd}  range ${c.min}..${c.max}  budget ${c.budget}`
      );
      console.log("");
    }
    console.log("     The confusion matrix is unaffected and is reported as normal.");
    console.log("     Claims that the score fuses these signals are not supported.");
    console.log("");
  }

  const guardFailures = [];

  if (observedCeiling < DEPLOYED_STATE_THRESHOLD) {
    guardFailures.push({
      guard: "UNREACHABLE_THRESHOLD",
      detail:
        `the deployed operating point predicts attack at risk >= ${DEPLOYED_STATE_THRESHOLD}, ` +
        `but the highest attainable score over ${windows.length} scored windows is ` +
        `${observedCeiling}. No window could be predicted attack, so TP and FP are ` +
        `structurally zero and the matrix describes the evaluation rather than the detector.`,
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
        `no ${empty} windows at truth threshold ${DEPLOYED_TRUTH_THR} ` +
        `(malicious ${nMalicious}, benign ${nBenign} of ${windows.length}). ` +
        `Recall or specificity is undefined and balanced accuracy reduces to a ` +
        `function of the populated class alone.`,
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
      console.log(`     [${g.guard}]`);
      console.log(`     ${g.detail}`);
      if (g.never_exercised && g.never_exercised.length) {
        console.log(`     never exercised: ${g.never_exercised.join(", ")}`);
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
    : { truth_threshold: DEPLOYED_TRUTH_THR, ...deployed };

  // ---- 5. Risk separation ----
  const malicious = windows.filter((w) => w.botnet_fraction >= 0.5).map((w) => w.riskScore);
  const benign = windows.filter((w) => w.botnet_fraction < 0.5).map((w) => w.riskScore);
  const separation = {
    malicious_n: malicious.length,
    benign_n: benign.length,
    malicious_mean_risk: malicious.length ? +mean(malicious).toFixed(2) : null,
    benign_mean_risk: benign.length ? +mean(benign).toFixed(2) : null,
    separation_margin:
      malicious.length && benign.length ? +(mean(malicious) - mean(benign)).toFixed(2) : null,
  };

  // ---- 6. Correlation: does the score track actual maliciousness? ----
  const correlation = {
    risk_vs_botnet_fraction: pearson(
      windows.map((w) => w.botnet_fraction),
      windows.map((w) => w.riskScore)
    ),
    c2score_vs_c2_flows: pearson(
      windows.map((w) => w.c2_flows),
      windows.map((w) => w.attackTypeScores.c2)
    ),
    c2score_vs_c2_fraction: pearson(
      windows.map((w) => (w.labeled_flows ? w.c2_flows / w.labeled_flows : 0)),
      windows.map((w) => w.attackTypeScores.c2)
    ),
  };

  // ---- 7. C2-specific: windows WITH labeled C&C vs without ----
  const withC2 = windows.filter((w) => w.c2_flows > 0);
  const withoutC2 = windows.filter((w) => w.c2_flows === 0);
  const c2Eval = {
    windows_with_c2: withC2.length,
    windows_without_c2: withoutC2.length,
    mean_c2score_when_c2_present: withC2.length ? +mean(withC2.map((w) => w.attackTypeScores.c2)).toFixed(2) : null,
    mean_c2score_when_absent: withoutC2.length ? +mean(withoutC2.map((w) => w.attackTypeScores.c2)).toFixed(2) : null,
    c2_dominant_when_present: withC2.filter((w) => w.dominantAttack === "c2").length,
    c2_dominant_when_absent: withoutC2.filter((w) => w.dominantAttack === "c2").length,
  };

  // ---- 8. Attack-type confusion (reported without forcing a mapping) ----
  const typeTable = {};
  for (const w of windows) {
    const t = w.dominant_truth;
    const p = w.dominantAttack;
    typeTable[t] = typeTable[t] || {};
    typeTable[t][p] = (typeTable[t][p] || 0) + 1;
  }

  // ---- REPORT ----
  console.log("\n" + "=".repeat(76));
  console.log("  RESULTS");
  console.log("=".repeat(76));

  console.log("\n📊 RISK SEPARATION (truth: botnet_fraction >= 0.5)");
  console.log(JSON.stringify(separation, null, 2));

  console.log("\n📈 CORRELATION");
  console.log(JSON.stringify(correlation, null, 2));

  console.log("\n🎯 DEPLOYED OPERATING POINT (state ∈ {high,critical}; truth thr 0.5)");
  console.log(JSON.stringify(deployed, null, 2));

  console.log("\n🛰  C2 EVALUATION");
  console.log(JSON.stringify(c2Eval, null, 2));

  console.log("\n🔀 ATTACK-TYPE TABLE  (rows = dominant CTU-13 truth, cols = detector dominantAttack)");
  console.table(typeTable);

  console.log("\n📉 THRESHOLD SWEEP (best F1 per truth threshold)");
  for (const tt of truthThrs) {
    const rows = sweep.filter((r) => r.truth_threshold === tt);
    const best = rows.slice().sort((a, b) => b.f1 - a.f1)[0];
    if (best) {
      console.log(
        `  truth>=${String(tt).padEnd(5)} best risk>=${String(best.risk_threshold).padStart(2)} ` +
        `| P=${best.precision.toFixed(3)} R=${best.recall.toFixed(3)} ` +
        `F1=${best.f1.toFixed(3)} FPR=${best.fpr.toFixed(3)} ` +
        `(n=${best.total_windows})`
      );
    }
  }

  // ---- OUT ----
  const output = {
    pcap: PCAP,
    generatedAt: new Date().toISOString(),
    coreVersion: windows[0]?.coreVersion || "unknown",
    config: { window_minutes: WINDOW_MIN, step_minutes: STEP_MIN, forced: FORCE },
    validity: {
      span_minutes: +spanMin.toFixed(2),
      window_minutes: WINDOW_MIN,
      max_valid_window_minutes: Math.floor(spanMin / 3),
      window_to_span_ratio: +(WINDOW_MIN / spanMin).toFixed(3),
      meets_third_rule: WINDOW_MIN * 3 <= spanMin,
      independent_windows: Math.floor(spanMin / WINDOW_MIN),
    },
    ingest_span: { from: new Date(t0).toISOString(), to: new Date(t1).toISOString(), minutes: +spanMin.toFixed(2) },
    census: Object.fromEntries(census.map((c) => [c._id, c.n])),
    subclass_census: Object.fromEntries(subCensus.map((c) => [c._id, c.n])),
    windows_scored: windows.length,
    separation,
    correlation,
    deployed_operating_point: deployedReported,
    reachability: {
      observed_ceiling: observedCeiling,
      nominal_budget: Object.values(COMPONENT_BUDGETS).reduce((a, b) => a + b, 0),
      deployed_state_threshold: DEPLOYED_STATE_THRESHOLD,
      summed_component_maxima: summedComponentMaxima,
      component_maxima: componentMaxima,
      component_nonzero_windows: componentNonZero,
      never_exercised: neverExercised,
    },
    // Which guards were present when this result was produced, not only which
    // tripped. A result carrying no guards block predates guard instrumentation
    // entirely; a result carrying one lists what it was checked against. Both
    // are recoverable from the artifact rather than from the file date.
    //
    // Retroactively applying the 2026-08-08 guard set to this project's own
    // archive: 68 of 92 previously published runs would be withheld today.
    guards: {
      version: "2026-08-08",
      ran: [
        "WINDOW_SPAN",
        "UNREACHABLE_THRESHOLD",
        "EMPTY_CLASS",
        "SATURATED_COMPONENT",
      ],
      failed: guardFailures.map((g) => g.guard),
      passed: [
        "WINDOW_SPAN",
        "UNREACHABLE_THRESHOLD",
        "EMPTY_CLASS",
        "SATURATED_COMPONENT",
      ].filter((g) => !guardFailures.some((f) => f.guard === g)),
      warnings: inertComponents.map((c) => c.condition + ":" + c.component),
      // Not implemented in this harness; audited retroactively by
      // research/scripts/guard_audit.py.
      not_run: ["TRIVIAL_NEGATIVE_CLASS", "UNDERPOWERED_CLASS", "DEGENERATE_SWEEP"],
    },
    guard_failures: guardFailures,
    component_distribution: componentStats,
    inert_components: inertComponents,
    c2_evaluation: c2Eval,
    attack_type_table: typeTable,
    threshold_sweep: sweep,
    windows,
  };

  const outPath = OUT || path.join(__dirname, `ctu13_eval_${PCAP}_${Date.now()}.json`);
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\n✅ Full results written → ${outPath}`);

  await mongoose.disconnect();
  process.exit(0);
})().catch((err) => {
  console.error("❌ Analysis failed:", err);
  process.exit(1);
});
