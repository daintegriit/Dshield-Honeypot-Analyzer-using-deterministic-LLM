// backend/services/skills/questionTemplates.js
// Defines analyst-grade reasoning templates for the Copilot

module.exports = {
  ATTACK_INTENT: {
    id: "attack_intent",
    description: "Explain why a resource is being targeted",
    requires: [
      "distributions.ports",
      "distributions.services",
      "signals.scanCandidates",
      "signals.portEntropy"
    ],
    prompt: `
Explain the attacker intent using:
- targeted ports and associated services
- scan behavior (if present)
- whether activity is focused or widely distributed

Do NOT speculate attribution.
Base conclusions strictly on observed behavior.
`
  },

  BEHAVIOR_CHANGE: {
    id: "behavior_change",
    description: "Detect and explain shifts in attacker behavior",
    requires: [
      "signals.burstRatio",
      "signals.portEntropy",
      "signals.sourceEntropy",
      "window"
    ],
    prompt: `
Compare current activity to baseline.
Explain what changed, when it changed, and why it matters.
Highlight any escalation or de-escalation signals.
`
  },

  RISK_EXPLANATION: {
    id: "risk_explanation",
    description: "Justify the computed risk score",
    requires: [
      "scores.riskScore0to100",
      "signals"
    ],
    prompt: `
Explain why the risk score is high or low.
Reference contributing signals explicitly.
Avoid qualitative language not supported by data.
`
  },

  WHAT_CHANGED_RECENTLY: {
    id: "what_changed_recently",
    description: "Summarize new developments in the last window",
    requires: [
      "signals.latestMinuteCount",
      "signals.medianMinuteCount",
      "signals.scanCandidates"
    ],
    prompt: `
Summarize what is new or different in the most recent window.
Focus on changes, not restating baseline behavior.
`
  }
};