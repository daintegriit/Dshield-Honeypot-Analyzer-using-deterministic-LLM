// backend/controllers/copilotAskController.js
// Orchestrates governed Copilot question answering
// - Deterministic summaries
// - Hard governance gates
// - LLM is NEVER a policy layer
// - Returns token + latency metrics for benchmarking

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

  const requestStarted =
    Date.now();

  try {

    const {
      question,
      templateId,
      minutes,
      limit = 5000,
      windows = [15, 60, 240],
      baselineMode = false,
      model = null,
    } = req.body;

    // =====================================================
    // VALIDATION
    // =====================================================

    if (
      !question ||
      typeof question !== "string"
    ) {

      return res.status(400).json({

        ok: false,

        error:
          "Missing or invalid question",
      });
    }

    if (
      !templateId ||
      typeof templateId !== "string"
    ) {

      return res.status(400).json({

        ok: false,

        error:
          "Missing or invalid templateId",
      });
    }

    // =====================================================
    // BUILD DETERMINISTIC CONTEXT
    // =====================================================

    const summary =
      minutes != null

        ? await buildBehaviorSummary({

            minutes:
              Number(minutes),

            limit:
              Number(limit),
          })

        : await buildMultiWindowBehaviorSummary({

            windows,

            limit:
              Number(limit),
          });

    // =====================================================
    // GOVERNANCE GATE
    // =====================================================

    const decision =
      assessQuestionAdmissibility({

        // buildBehaviorSummary returns { core, behavior, ... }; the templates
        // declare paths relative to the behavior object (signals.*,
        // distributions.*). Passing the outer object made hasPath() fail on
        // every required field, so this gate returned INSUFFICIENT_EVIDENCE
        // unconditionally.
        summary: summary.behavior || summary,

        templateId,

        question,
      });

    // =====================================================
    // HARD REFUSAL
    // =====================================================

    if (
      decision.action ===
      "HARD_REFUSE"
    ) {

      return res.status(403).json({

        ok: false,

        refusal: true,

        reason:
          decision.reason,

        answer:
          "I cannot answer this question because it is outside the scope of security analysis.",
      });
    }

    // =====================================================
    // LLM REASONING
    // =====================================================

    const result =
      await answerCopilotQuestion({

        summary,

        templateId,

        question,

        constraints:
          decision.constraint || null,

        baselineMode,

        model,
      });

    // =====================================================
    // LATENCY
    // =====================================================

    const latencyMs =
      Date.now() -
      requestStarted;

    // =====================================================
    // TOKEN METRICS
    // =====================================================

    const tokenMetrics =
      result.tokenMetrics || {

        promptTokens: 0,

        completionTokens: 0,

        totalTokens: 0,

        promptEvalDuration: 0,

        evalDuration: 0,
      };

    // =====================================================
    // RESPONSE
    // =====================================================

    return res.json({

      ok: true,

      template:
        templateId,

      model:
        model || null,

      baselineMode:
        Boolean(baselineMode),

      constraints:
        decision.constraint || null,

      answer:
        result.answer,

      latencyMs,

      tokenMetrics,

      windowsUsed:

        minutes != null

          ? [`${minutes}m`]

          : windows.map(
              (w) => `${w}m`
            ),
    });

  } catch (err) {

    console.error(
      "Copilot ask error:",
      err
    );

    return res.status(500).json({

      ok: false,

      error:
        err.message ||
        "Copilot failed to answer the question",
    });
  }
}

module.exports = {
  askCopilot,
};
