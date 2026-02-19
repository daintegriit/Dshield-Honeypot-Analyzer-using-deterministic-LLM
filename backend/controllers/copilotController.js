// backend/controllers/copilotController.js
const { buildBehaviorSummary } = require("../services/behaviorSummary");
const { buildCopilotCore } = require("../services/copilotCore");
const { generateCopilotInsight } = require("../services/copilotReasoner");


async function getCopilotInsight(req, res) {
  try {
    const minutes = Number(req.query.minutes || 60);
    const limit = Number(req.query.limit || 5000);

    // ---------------------------------------------
    // 1. Historical / statistical behavior summary
    // ---------------------------------------------
    const behaviorSummary = await buildBehaviorSummary({
      minutes: Number.isFinite(minutes) ? minutes : 60,
      limit: Number.isFinite(limit) ? limit : 5000,
    });

    // ---------------------------------------------
    // 2. Deterministic Copilot Core (REAL STATE)
    // ---------------------------------------------
    const coreSummary = await buildCopilotCore();

    // ---------------------------------------------
    // 3. Merge into single situation report
    //    (this is what the LLM reasons over)
    // ---------------------------------------------
    const situationReport = {
      behavior: behaviorSummary,
      core: coreSummary,
    };

    // ---------------------------------------------
    // 4. LLM reasoning
    // ---------------------------------------------
    const copilotInsight = await generateCopilotInsight(situationReport);

    return res.json({
      ok: true,

      // Expose layers explicitly (UI + audit-friendly)
      behaviorSummary,
      coreSummary,

      // LLM output (strict JSON)
      copilot: copilotInsight,
    });
  } catch (err) {
    console.error("Copilot insight error:", err);
    return res.status(500).json({
      ok: false,
      error: err.message || "Copilot failed",
    });
  }
}

module.exports = {
  getCopilotInsight,
};