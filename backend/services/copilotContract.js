// backend/services/copilotContract.js
// response contract

const RISK_LEVELS = ["low", "elevated", "high", "critical"];

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function normalizeCopilotResponse(payload) {
  const out = {
    headline: String(payload?.headline || "Threat posture update"),
    risk: RISK_LEVELS.includes(payload?.risk) ? payload.risk : "low",
    confidence: clamp(Number(payload?.confidence ?? 0.55), 0, 1),

    // “why we think this”
    evidence: Array.isArray(payload?.evidence) ? payload.evidence.map(String) : [],

    // “what it means”
    insights: Array.isArray(payload?.insights) ? payload.insights.map(String) : [],

    // “what to do”
    recommended_actions: Array.isArray(payload?.recommended_actions)
      ? payload.recommended_actions.map(String)
      : [],

    // optional: for the LLM chat panel later
    follow_up_questions: Array.isArray(payload?.follow_up_questions)
      ? payload.follow_up_questions.map(String)
      : [],

    // structured metrics the UI can render as cards
    metrics: payload?.metrics && typeof payload.metrics === "object" ? payload.metrics : {},

    // timestamps
    generated_at: new Date().toISOString(),
  };

  return out;
}

module.exports = { normalizeCopilotResponse, RISK_LEVELS };