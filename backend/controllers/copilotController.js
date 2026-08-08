// backend/controllers/copilotController.js
//
// DESIGN: the deterministic core is the product. The LLM is an optional
// explanation layer on top. Neither the behavior summary nor the LLM may take
// down the deterministic analysis — if they fail, we still return coreSummary
// and report their status explicitly.

const { buildBehaviorSummary } = require("../services/behaviorSummary");
const { buildCopilotCore } = require("../services/copilotCore");
const { generateCopilotInsight } = require("../services/copilotReasoner");

const insightCache = require('../services/insightCache');

async function getCopilotInsight(req, res) {
  // Serve the last completed generation immediately. Generation runs on a
  // timer with single-flight; requests never trigger one. Staleness is
  // reported via ageMs rather than hidden behind a blocking call.
  const c = insightCache.get();
  if (c.generatedAt) {
    return res.json({
      ok: true,
      sourceFilter: 'all',
      cached: true,
      generatedAt: c.generatedAt,
      ageMs: c.ageMs,
      refreshing: c.refreshing,
      durationMs: c.durationMs,
      llmStatus: c.llmStatus,
      behaviorStatus: c.behaviorStatus,
      behaviorSummary: c.behaviorSummary,
      coreSummary: c.coreSummary,
      copilot: c.copilot,
    });
  }
  return getCopilotInsightLive(req, res);
}

async function getCopilotInsightLive(req, res) {
  try {
    const minutes = Number(req.query.minutes || 60);
    const limit = Number(req.query.limit || 5000);

    // Experiment isolation: when ?source=replay (or honeypot) is passed, scope the
    // deterministic core to that traffic source only. Absent => score everything.
    const rawSource = (req.query.source || "").toString().toLowerCase();
    const sourceFilter =
      rawSource === "replay" || rawSource === "honeypot" ? rawSource : null;

    const safeMinutes = Number.isFinite(minutes) ? minutes : 60;
    const safeLimit = Number.isFinite(limit) ? limit : 5000;

    // ---------------------------------------------
    // 1. Deterministic Copilot Core (REAL STATE)
    //    Scoped by sourceFilter when provided.
    //    THIS IS THE PRODUCT — if it throws, the request genuinely failed.
    // ---------------------------------------------
    const coreSummary = await buildCopilotCore({
      minutes: safeMinutes,
      sourceFilter,
    });

    // ---------------------------------------------
    // 2. Historical / statistical behavior summary (OPTIONAL)
    //    Feature extraction for the LLM. Must not take down the core.
    // ---------------------------------------------
    let behaviorSummary = null;
    let behaviorStatus = "ok";

    try {
      behaviorSummary = await buildBehaviorSummary({
        minutes: safeMinutes,
        limit: safeLimit,
        sourceFilter,
      });
    } catch (err) {
      console.warn("⚠️ Behavior summary unavailable:", err.message);
      behaviorStatus = "unavailable";
      behaviorSummary = { available: false, reason: err.message };
    }

    // ---------------------------------------------
    // 3. Merge into single situation report
    //    (this is what the LLM reasons over)
    // ---------------------------------------------
    const situationReport = {
      behavior: behaviorSummary,
      core: coreSummary,
    };

    // ---------------------------------------------
    // 4. LLM reasoning (OPTIONAL)
    //    If no model is reachable (e.g. Ollama down), we still return the
    //    deterministic analysis and flag the LLM as unavailable.
    // ---------------------------------------------
    let copilotInsight = null;
    let llmStatus = "ok";

    try {
      copilotInsight = await generateCopilotInsight(situationReport);
      // generateCopilotInsight catches transport errors internally and RETURNS
      // { available:false, reason }. Without this check llmStatus reports "ok"
      // for a request that timed out.
      if (copilotInsight && copilotInsight.available === false) {
        llmStatus = "unavailable";
        console.warn("⚠️ LLM insight unavailable:", copilotInsight.reason);
      }
    } catch (err) {
      console.warn("⚠️ LLM insight unavailable:", err.message);
      llmStatus = "unavailable";
      copilotInsight = { available: false, reason: err.message };
    }

    return res.json({
      ok: true,

      // Echo the applied scope for experiment auditing
      sourceFilter: sourceFilter || "all",

      // Explicit component health — lets the experiment record whether the LLM
      // actually contributed to a given evaluation cycle.
      llmStatus,
      behaviorStatus,

      // Expose layers explicitly (UI + audit-friendly)
      behaviorSummary,
      coreSummary,

      // LLM output (strict JSON) — may be { available: false } when offline
      copilot: copilotInsight,
    });
  } catch (err) {
    // Only reached if the DETERMINISTIC core itself failed.
    console.error("Copilot insight error (core failure):", err);
    return res.status(500).json({
      ok: false,
      error: err.message || "Copilot failed",
    });
  }
}

module.exports = {
  getCopilotInsight,
};
