// backend/services/coreConsistency.js
//
// WHY THIS EXISTS
// ---------------
// Every value the core publishes is derived from other values it publishes.
// Nothing checked that the derivations agreed. Measured on this system in one
// session:
//
//   - The reported risk score was 42 while the seven-term equation given in the
//     paper and implemented in the operator interface summed to 19.52. Two
//     components (entropy 20.00, peer concentration 2.44) were absent from both.
//     The interface displayed the 22.47-point disagreement next to a badge
//     indicating the check had passed.
//
//   - reasoning.riskExplanation asserted "traffic is distributed across a wide
//     range of destination ports, consistent with enumeration or scanning
//     behaviour" in the same object where attackIndicators.scanningDetected was
//     false. The prose fired on entropyComponent >= 12; the boolean is
//     (dominantAttack.type === "scan" || scanCandidates.length > 0). Two
//     definitions of scanning, no shared criterion.
//
//   - A comment stating a component is "computed since v3.x and NEVER used in
//     risk" sits ninety lines above the summation that uses it.
//
// None of these produced an error. Each was found by hand.
//
// WHAT THIS CHECKS
// Derived quantity against the inputs it was derived from. Every check is an
// identity or a rule already present in the code; none introduces a new
// threshold or a judgement about whether the underlying value is correct.
//
// WHAT THIS DOES NOT CHECK
// Whether the core is right. A report can be perfectly self-consistent and
// wrong about the traffic. This detects disagreement between a system's own
// statements, which is a strictly weaker and strictly cheaper property.

"use strict";

// Thresholds duplicated from copilotCore.js. They are duplicated deliberately:
// a checker that imports the same constant as the code it checks cannot detect
// the constant changing in one place. If these drift, that is itself a finding.
const STATE_THRESHOLDS = { elevated: 45, high: 60, critical: 85 };
const BURST_DETECTED_MIN = 0.35;
const HIGH_VOLUME_MIN = 25;
const C2_FLOW_COUNT_MIN = 12;
const C2_DOMINANT_RATIO_MIN = 0.4;

// Only these five classes are eligible to be the dominant attack. `impact` is
// scored but excluded, so an argmax over all six would misfire.
const BEHAVIOURAL_CLASSES = ["dos", "scan", "brute_force", "web_probe", "c2"];

const EPSILON = 0.51; // tolerates rounding to integer

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function stateFor(score) {
  if (score >= STATE_THRESHOLDS.critical) return "critical";
  if (score >= STATE_THRESHOLDS.high) return "high";
  if (score >= STATE_THRESHOLDS.elevated) return "elevated";
  return "stable";
}

/**
 * 1. Does the reported score equal the sum of the components it reports?
 *
 * This is the check that would have caught the published-equation mismatch
 * immediately: any consumer summing a different set of terms disagrees here.
 */
function checkRiskSum(core) {
  const rc = core.riskComponents || {};
  const budget = core.riskBudget || {};

  const sum =
    num(rc.volumeComponent) +
    num(rc.severityComponent) +
    num(rc.behaviorComponent) +
    num(rc.entropyComponent) +
    num(rc.concentrationComponent) +
    num(rc.signalAmplifier) +
    num(rc.c2Bonus) +
    num(rc.impactBonus) +
    num(rc.couplingBonus);

  const raw = Math.min(100, Math.round(sum));
  const reported = num(core.riskScore0to100);

  // Under budget normalisation the reported score is rescaled, so compare
  // against the normalised value the core itself published rather than the raw
  // sum. If riskBudget is absent, the raw sum is the expectation.
  let expected = raw;
  let basis = "raw component sum";
  if (budget.normalised === true && Number.isFinite(budget.referenceBudget)) {
    expected = Math.min(
      100,
      Math.round((raw / budget.referenceBudget) * 100)
    );
    basis = `normalised against reachable budget ${budget.referenceBudget}`;
  }

  if (Math.abs(expected - reported) > EPSILON) {
    return [{
      check: "RISK_SUM",
      severity: "error",
      detail:
        `reported riskScore0to100 = ${reported} but components sum to ` +
        `${sum.toFixed(2)} (${basis}, expected ${expected}). ` +
        `Difference ${(reported - expected).toFixed(2)}.`,
      components: rc,
    }];
  }
  return [];
}

/** 2. Does the reported state match the reported score? */
function checkState(core) {
  const score = num(core.riskScore0to100);
  const expected = stateFor(score);
  const reported = String(core.state || "");
  if (reported && reported !== expected) {
    return [{
      check: "STATE_MAPPING",
      severity: "error",
      detail:
        `state "${reported}" does not match riskScore0to100 = ${score} ` +
        `(thresholds 45/60/85 give "${expected}")`,
    }];
  }
  return [];
}

/**
 * 3. Is the dominant attack the highest-scoring eligible class?
 *
 * Reported separately from the scores it derives from, so the two can drift.
 */
function checkDominantAttack(core) {
  const ac = core.attackClassification || {};
  const scores = ac.attackTypeScores || {};
  const dominant = ac.dominantAttack || {};

  const eligible = BEHAVIOURAL_CLASSES
    .filter((k) => k in scores)
    .map((k) => [k, num(scores[k])])
    .sort((a, b) => b[1] - a[1]);

  if (!eligible.length || !dominant.type) return [];

  const [topName, topScore] = eligible[0];
  const issues = [];

  if (dominant.type !== topName && topScore > num(dominant.score)) {
    issues.push({
      check: "DOMINANT_ATTACK",
      severity: "error",
      detail:
        `dominantAttack.type = "${dominant.type}" (${num(dominant.score).toFixed(2)}) ` +
        `but "${topName}" scores higher (${topScore.toFixed(2)})`,
      scores: Object.fromEntries(eligible),
    });
  }

  if (Math.abs(num(dominant.score) - num(scores[dominant.type])) > 0.01) {
    issues.push({
      check: "DOMINANT_SCORE",
      severity: "error",
      detail:
        `dominantAttack.score = ${num(dominant.score)} but ` +
        `attackTypeScores.${dominant.type} = ${num(scores[dominant.type])}`,
    });
  }

  return issues;
}

/**
 * 4. Do the boolean indicators match the values they are defined over?
 *
 * Each rule below is transcribed from buildAttackIndicators. A mismatch means
 * either the rule changed in one place, or an indicator is being set elsewhere.
 */
function checkIndicators(core) {
  const ind = (core.reasoning || {}).attackIndicators;
  if (!ind) return [];

  const am = core.attackMetrics || {};
  const si = core.scanningIndicators || {};
  const ss = core.severitySignals || {};
  const ac = core.attackClassification || {};
  const c2 = ac.c2Signals || {};
  const dominantType = (ac.dominantAttack || {}).type;

  const rules = [
    {
      name: "highVolumeDetected",
      expected: num(am.attacksLast5Min) >= HIGH_VOLUME_MIN,
      basis: `attacksLast5Min = ${num(am.attacksLast5Min)} vs >= ${HIGH_VOLUME_MIN}`,
    },
    {
      name: "burstDetected",
      expected: num(am.burstRatio5mOverHour) > BURST_DETECTED_MIN,
      basis:
        `burstRatio5mOverHour = ${num(am.burstRatio5mOverHour).toFixed(4)} ` +
        `vs > ${BURST_DETECTED_MIN}`,
    },
    {
      name: "scanningDetected",
      expected:
        dominantType === "scan" ||
        (Array.isArray(si.scanCandidates) && si.scanCandidates.length > 0),
      basis:
        `dominantAttack.type = "${dominantType}", ` +
        `scanCandidates = ${(si.scanCandidates || []).length}`,
    },
    {
      name: "c2BehaviorDetected",
      expected:
        dominantType === "c2" ||
        num(c2.topFlowCount) >= C2_FLOW_COUNT_MIN ||
        num(c2.dominantFlowRatio) >= C2_DOMINANT_RATIO_MIN,
      basis:
        `dominantAttack.type = "${dominantType}", ` +
        `topFlowCount = ${num(c2.topFlowCount)}, ` +
        `dominantFlowRatio = ${num(c2.dominantFlowRatio).toFixed(3)}`,
    },
    {
      name: "severityEscalationDetected",
      expected: num(ss.criticalCountWindow ?? ss.criticalCount) > 0,
      basis: `criticalCountWindow = ${num(ss.criticalCountWindow ?? ss.criticalCount)}`,
    },
  ];

  const issues = [];
  for (const r of rules) {
    if (!(r.name in ind)) continue;
    if (Boolean(ind[r.name]) !== r.expected) {
      issues.push({
        check: "INDICATOR",
        severity: "error",
        detail:
          `attackIndicators.${r.name} = ${ind[r.name]} but its rule gives ` +
          `${r.expected} (${r.basis})`,
      });
    }
  }
  return issues;
}

/**
 * 5. Does the generated prose agree with the booleans?
 *
 * riskExplanation is emitted by the core, not the model. Before this session it
 * was gated on independent magnitude thresholds and could assert a behaviour the
 * indicators denied.
 */
const PROSE_SUBJECTS = [
  { indicator: "scanningDetected",         terms: ["enumeration", "scanning behaviour", "scanning behavior"] },
  { indicator: "severityEscalationDetected", terms: ["critical and high severity"] },
  { indicator: "c2BehaviorDetected",       terms: ["command-and-control"] },
  { indicator: "authenticationTargeting",  terms: ["sensitive service categories"] },
];

function checkProse(core) {
  const reasoning = core.reasoning || {};
  const ind = reasoning.attackIndicators || {};
  const lines = Array.isArray(reasoning.riskExplanation)
    ? reasoning.riskExplanation
    : [];
  if (!lines.length) return [];

  const issues = [];
  for (const line of lines) {
    const t = String(line).toLowerCase();
    for (const s of PROSE_SUBJECTS) {
      if (!(s.indicator in ind)) continue;
      if (ind[s.indicator] === false && s.terms.some((k) => t.includes(k))) {
        issues.push({
          check: "PROSE_CONTRADICTS_INDICATOR",
          severity: "error",
          detail:
            `riskExplanation asserts ${s.indicator.replace("Detected", "")} ` +
            `while attackIndicators.${s.indicator} = false`,
          line: String(line),
        });
      }
    }
  }
  return issues;
}

/**
 * 6. Does the declared reachability profile match what the window produced?
 *
 * A component marked reachable that is zero is not necessarily wrong for one
 * window. A component marked UNreachable that is non-zero is a profile error.
 */
function checkReachability(core) {
  const budget = core.riskBudget;
  if (!budget || !budget.reachable) return [];

  const rc = core.riskComponents || {};
  const map = {
    severity: "severityComponent",
    behavior: "behaviorComponent",
    entropy: "entropyComponent",
    concentration: "concentrationComponent",
    amplifier: "signalAmplifier",
    c2: "c2Bonus",
    impact: "impactBonus",
    coupling: "couplingBonus",
  };

  const issues = [];
  for (const [key, field] of Object.entries(map)) {
    if (budget.reachable[key] === false && num(rc[field]) > 0) {
      issues.push({
        check: "REACHABILITY_PROFILE",
        severity: "warning",
        detail:
          `riskBudget declares "${key}" unreachable but ${field} = ` +
          `${num(rc[field]).toFixed(2)} in this window`,
      });
    }
  }
  return issues;
}

/**
 * Run every check against one core summary.
 */
function checkCoreConsistency(core) {
  if (!core || typeof core !== "object") {
    return { checkedAt: new Date().toISOString(), consistent: false,
             issues: [{ check: "INPUT", severity: "error", detail: "no core summary" }] };
  }

  const issues = [
    ...checkRiskSum(core),
    ...checkState(core),
    ...checkDominantAttack(core),
    ...checkIndicators(core),
    ...checkProse(core),
    ...checkReachability(core),
  ];

  const counts = issues.reduce((a, i) => {
    a[i.check] = (a[i.check] || 0) + 1;
    return a;
  }, {});

  return {
    checkedAt: new Date().toISOString(),
    coreVersion: core.coreVersion || null,
    windowEnd: core.windowEnd || null,
    consistent: issues.filter((i) => i.severity === "error").length === 0,
    errorCount: issues.filter((i) => i.severity === "error").length,
    warningCount: issues.filter((i) => i.severity === "warning").length,
    counts,
    issues,
    note:
      "Checks derived quantities against the inputs they were derived from. " +
      "A consistent report may still be wrong about the traffic; this detects " +
      "disagreement between the system's own statements only.",
  };
}

module.exports = { checkCoreConsistency, STATE_THRESHOLDS };
