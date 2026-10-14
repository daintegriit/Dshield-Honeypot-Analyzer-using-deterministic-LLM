// backend/services/stateDegeneracy.js
//
// WHY THIS EXISTS
// ---------------
// The validity guards in the analysis harness refuse to emit metrics that the
// evaluation's own configuration makes meaningless. Nothing did the equivalent
// at runtime: the reasoning layer would narrate any state it was handed.
//
// Measured 2026-08-08. A 60-minute window containing zero events produced:
//
//     riskScore0to100  15
//     attackMetrics    all zero
//     dominantAttack   dos (score 0)
//
// and the governed model generated:
//
//     "Stable System State with Elevated Scanning Activity"
//     "Elevated port entropy indicates scanning activity"
//     evidence: ["scanningIndicators.portEntropy"]
//
// The citation resolves. The field exists and is non-zero -- it is computed
// over lifetime aggregates, not the empty window. Grounding scores 100%,
// schema compliance 100%, fabrication 0%. Every governance metric passes and
// the sentence describes traffic that did not occur.
//
// No amount of citation governance fixes this, because the failure is not in
// how the claim is evidenced. It is that the state supports no claim at all.
//
// WHAT THIS CHECKS
// Whether the window contains enough to characterise. Not whether the core is
// self-consistent (coreConsistency.js), and not whether a generated claim is
// supported (insightValidator.js) -- both presuppose there is something to say.

"use strict";

// Duplicated from copilotCore.js. A checker sharing a constant with the code it
// checks cannot detect that constant changing in one place.
const COMPONENT_BUDGETS = {
  severityComponent: 25,
  behaviorComponent: 20,
  entropyComponent: 20,
  concentrationComponent: 15,
  signalAmplifier: 25,
  c2Bonus: 20,
  impactBonus: 12,
  couplingBonus: 5,
  volumeComponent: 0,
};

const AT_CAP_FRAC = 0.99;

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

// 1. Did anything happen in the window?
//
// The trap is that the report stays fully populated when nothing did:
// scanningIndicators, severitySignals and lifetimeContext are computed over
// cumulative data and remain non-zero. A model reading the report sees numbers
// everywhere and describes them.
function checkEmptyWindow(core) {
  const am = core.attackMetrics || {};
  const windowed =
    num(am.attacksLast1Min) +
    num(am.attacksLast5Min) +
    num(am.attacksLast15Min);

  if (windowed > 0) return null;

  const lastHour = num(am.attacksLastHour);
  return {
    condition: "EMPTY_WINDOW",
    detail:
      lastHour > 0
        ? `no events in the scoring window (${lastHour} in the last hour). ` +
          `Fields computed over wider or cumulative ranges remain populated ` +
          `and do not describe this window.`
        : `no events in the scoring window and none in the last hour. This is ` +
          `either a quiet period or a collection failure; the report cannot ` +
          `distinguish them.`,
    attacksLast1Min: num(am.attacksLast1Min),
    attacksLast5Min: num(am.attacksLast5Min),
    attacksLastHour: lastHour,
  };
}

// 2. Is every contributing component pinned?
function checkAllComponentsPinned(core) {
  const rc = core.riskComponents || {};
  const live = [];
  const capped = [];

  for (const [name, budget] of Object.entries(COMPONENT_BUDGETS)) {
    if (budget <= 0) continue;
    const v = num(rc[name]);
    if (v <= 0) continue;
    live.push(name);
    if (v >= budget * AT_CAP_FRAC) capped.push(name);
  }

  if (!live.length) {
    return {
      condition: "NO_LIVE_COMPONENTS",
      detail:
        `every risk component is zero. The reported score is the floor value ` +
        `and reflects no observed behaviour.`,
      components: rc,
    };
  }

  // Refusing whenever all live components are capped was wrong on first
  // contact with real data: a WannaCry window capped severity, amplifier and
  // impact because the attack genuinely maxed them. Three of eight at cap is a
  // strong signal, not an absent one. Only treat saturation as degenerate when
  // it includes entropy, which caps on any traffic touching ten ports and
  // therefore carries no information about this window specifically.
  if (capped.length === live.length && capped.includes("entropyComponent")) {
    return {
      condition: "ALL_LIVE_COMPONENTS_CAPPED",
      detail:
        `every contributing component is at its cap (${capped.join(", ")}), ` +
        `including entropy, which saturates on any dispersed traffic. The ` +
        `score cannot distinguish this window from any other that also caps ` +
        `them.`,
      capped,
      components: rc,
    };
  }

  return null;
}

// 3. Is the dominant classification meaningful?
//
// pickTop returns the first key when every score is zero, so an empty window
// yields a confident-looking dominant attack type with score 0.
function checkDominantAttack(core) {
  const ac = core.attackClassification || {};
  const dominant = ac.dominantAttack || {};
  const scores = ac.attackTypeScores || {};

  const total = Object.values(scores).reduce((a, v) => a + num(v), 0);
  if (total > 0) return null;

  return {
    condition: "NULL_CLASSIFICATION",
    detail:
      `all attack-type scores are zero, but dominantAttack reports ` +
      `"${dominant.type || "unknown"}". The selection returns its first key ` +
      `when there is nothing to rank; the type carries no evidence.`,
    dominantAttack: dominant,
    attackTypeScores: scores,
  };
}

function checkStateSupportsNarration(core) {
  if (!core || typeof core !== "object") {
    return {
      narratable: false,
      conditions: [{ condition: "NO_CORE", detail: "no core summary supplied" }],
    };
  }

  const conditions = [
    checkEmptyWindow(core),
    checkAllComponentsPinned(core),
    checkDominantAttack(core),
  ].filter(Boolean);

  const narratable = conditions.length === 0;

  return {
    checkedAt: new Date().toISOString(),
    windowEnd: core.windowEnd || null,
    windowMinutes: core.windowMinutes ?? null,
    narratable,
    conditions,
    refusal: narratable
      ? null
      : {
          refused: true,
          reason: "DEGENERATE_STATE",
          conditions: conditions.map((c) => c.condition),
          headline: conditions.some((c) => c.condition === "EMPTY_WINDOW")
            ? "No activity in this window"
            : "Insufficient signal to characterise this window",
          assessment: conditions.map((c) => c.detail).join(" "),
          top_findings: [],
          evidence: [],
          note:
            "Generation was not attempted. The deterministic score and its " +
            "components are reported unchanged above.",
        },
  };
}

module.exports = { checkStateSupportsNarration, COMPONENT_BUDGETS };
