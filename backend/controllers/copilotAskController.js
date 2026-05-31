// backend/controllers/copilotAskController.js
const {
  buildBehaviorSummary,
  buildMultiWindowBehaviorSummary,
} = require("../services/behaviorSummary");

const {
  answerCopilotQuestion,
} = require("../services/copilotReasoner");

const {
  assessQuestionAdmissibility,
} = require("../services/questionAdmissibility");

async function askCopilot(req, res) {
  try {
    const {
      question,
      templateId,
      minutes,
      limit = 5000,
      windows = [15, 60, 240],
    } = req.body;

    if (!question || typeof question !== "string") {
      return res.status(400).json({
        ok: false,
        error: "Missing or invalid question",
      });
    }

    if (!templateId || typeof templateId !== "string") {
      return res.status(400).json({
        ok: false,
        error: "Missing or invalid templateId",
      });
    }

    // Build deterministic context ONLY
    const summary =
      minutes != null
        ? await buildBehaviorSummary({
            minutes: Number(minutes),
            limit: Number(limit),
          })
        : await buildMultiWindowBehaviorSummary({
            windows,
            limit: Number(limit),
          });

    // Governance hard gate
    const decision = assessQuestionAdmissibility({
      summary,
      templateId,
      question,
    });

    //  HARD REFUSAL (no LLM call)
    // HARD REFUSAL (only when explicitly required)
    if (decision.action === "HARD_REFUSE") {
      return res.status(403).json({
        ok: false,
        refusal: true,
        reason: decision.reason,
        answer:
          "I cannot answer this question because it is outside the scope of security analysis.",
      });
    }

    // Allowed — pass constraints into reasoner
    const result = await answerCopilotQuestion({
      summary,
      templateId,
      question,
      constraints: decision.constraint || null,
    });

    return res.json({
      ok: true,
      template: templateId,
      constraints: decision.constraint || null,
      answer: result.answer,
      windowsUsed:
        minutes != null
          ? [`${minutes}m`]
          : windows.map((w) => `${w}m`),
    });
  } catch (err) {
    console.error("Copilot ask error:", err);

    return res.status(500).json({
      ok: false,
      error: err.message || "Copilot failed to answer the question",
    });
  }
}

module.exports = { askCopilot };