// backend/services/copilotReasoner.js
// - Uses ONLY structured summaries
// - Enforces deterministic + interpretive separation
// - Produces SOC-grade, auditable output
// - Supports autonomous insight + governed analyst questions

const crypto = require("crypto");
const { callLocalOllama } = require("./llmProviders/localOllamaProvider");
const QUESTION_TEMPLATES = require("./skills/questionTemplates");

/* -------------------------------------------------
   Utilities
--------------------------------------------------*/

function sha256(obj) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(obj))
    .digest("hex");
}

/* -------------------------------------------------
   Autonomous Insight Prompt
--------------------------------------------------*/

function buildCopilotPrompt(report) {
  return `
You are a SOC-grade Threat Intelligence Copilot.

You are given a VERIFIED SITUATION REPORT composed of:
1) core → deterministic real-time system state (ground truth)
2) behavior → statistical / historical behavior analysis

You MUST:
- Treat core as authoritative truth
- Use behavior ONLY to explain patterns
- NEVER invent IP attribution, malware families, or actor identities
- NEVER change or reinterpret the provided risk score

You MUST respond with STRICT JSON ONLY.
NO markdown. NO commentary outside JSON.

------------------------------------
VERIFIED CORE STATE (AUTHORITATIVE)
------------------------------------
riskScore0to100: ${report.core.riskScore0to100}
state: ${report.core.state}
attackMetrics: ${JSON.stringify(report.core.attackMetrics)}
scanningIndicators: ${JSON.stringify(report.core.scanningIndicators)}
severitySignals: ${JSON.stringify(report.core.severitySignals)}
attackClassification: ${JSON.stringify(report.core.attackClassification)}
riskComponents: ${JSON.stringify(report.core.riskComponents)}


------------------------------------
BEHAVIORAL CONTEXT (INTERPRETIVE)
------------------------------------
${JSON.stringify(report.behavior)}

------------------------------------
YOUR TASKS
------------------------------------
1) Explain what is happening RIGHT NOW
2) Identify likely tactic class (scan, brute-force, probing, flood)
3) Justify claims using ONLY provided fields
4) Recommend analyst actions (clear, prioritized)
5) State uncertainty and missing data explicitly

------------------------------------
OUTPUT JSON SCHEMA (MANDATORY)
------------------------------------
{
  "headline": string,
  "assessment": string,

  "what_changed": [string],

  "top_findings": [
    {
      "finding": string,
      "evidence": [string],
      "confidence": number
    }
  ],

  "likely_tactics": [
    {
      "tactic": string,
      "mapping_note": string,
      "confidence": number
    }
  ],

  "recommended_actions": [
    {
      "action": string,
      "why": string,
      "priority": "P0" | "P1" | "P2"
    }
  ],

  "risk_score_explanation": string,

  "limitations": [string]
}

------------------------------------
RULES
------------------------------------
- confidence must be between 0.0 and 1.0
- evidence MUST reference explicit fields
- If evidence is weak, LOWER confidence
- If data is insufficient, say so

Respond ONLY with valid JSON.
`.trim();
}

/* -------------------------------------------------
   Governed Question Prompt Builder
--------------------------------------------------*/

function buildQuestionPrompt({ summary, template, question }) {
  return `
You are a SOC-grade Threat Intelligence Copilot.

You are answering a SPECIFIC ANALYST QUESTION using a VERIFIED SITUATION REPORT.

You MUST:
- Use ONLY the provided context
- Follow the reasoning instructions EXACTLY
- Avoid attribution or speculation
- State uncertainty explicitly

------------------------------------
VERIFIED SITUATION REPORT
------------------------------------
${JSON.stringify(summary, null, 2)}

------------------------------------
REASONING TASK
------------------------------------
${template.prompt}

------------------------------------
ANALYST QUESTION
------------------------------------
"${question}"

------------------------------------
RESPONSE RULES
------------------------------------
- Answer concisely
- Cite specific fields as evidence
- If required data is missing, say so
- NO external knowledge
- NO speculation

Respond in plain text.
`.trim();
}

/* -------------------------------------------------
   LLM Adapter
--------------------------------------------------*/

async function callLLM({ prompt }) {
  const provider = process.env.COPILOT_LLM_PROVIDER || "stub";

  if (provider === "local") {
    return await callLocalOllama(prompt);
  }

  if (provider === "stub") {
    return JSON.stringify({
      headline: "Insufficient intelligence available",
      assessment:
        "No LLM provider configured. This is a stub response.",
      what_changed: [],
      top_findings: [],
      likely_tactics: [],
      recommended_actions: [
        {
          action: "Configure COPILOT_LLM_PROVIDER",
          why: "Enable LLM-backed reasoning",
          priority: "P2",
        },
      ],
      risk_score_explanation:
        "Risk score was computed deterministically by the system.",
      limitations: ["LLM provider not configured"],
    });
  }

  throw new Error(
    `Unsupported COPILOT_LLM_PROVIDER='${provider}'`
  );
}

/* -------------------------------------------------
   Autonomous Insight Entry Point
--------------------------------------------------*/

async function generateCopilotInsight(summary) {
  const prompt = buildCopilotPrompt(summary);
  const reportHash = sha256(summary);

  const raw = await callLLM({ prompt });

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    return {
      ok: false,
      reportHash,
      error: "LLM returned invalid JSON",
      rawPreview: String(raw).slice(0, 500),
    };
  }

  return {
    ok: true,
    reportHash,
    insight: parsed,
  };
}

/* -------------------------------------------------
   Governed Question Answering
--------------------------------------------------*/

async function answerCopilotQuestion({
  summary,
  templateId,
  question,
  constraints = null,
}) {
  const template = QUESTION_TEMPLATES[templateId];

  if (!template) {
    throw new Error(`Unknown question template: ${templateId}`);
  }

  const prompt = buildQuestionPrompt({
    summary,
    template,
    question,
    constraints,
  });

  const raw = await callLLM({ prompt });

  return {
    ok: true,
    template: templateId,
    answer: raw.trim(),
  };
}

/* -------------------------------------------------
   Exports
--------------------------------------------------*/

module.exports = {
  generateCopilotInsight,
  answerCopilotQuestion,
};