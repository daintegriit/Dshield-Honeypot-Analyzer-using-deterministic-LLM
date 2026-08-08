// backend/services/insightCache.js
//
// WHY THIS EXISTS
// ---------------
// /api/copilot/insight used to generate synchronously on every request. A
// governed generation takes 60-180s under load, and the dashboard polled every
// 60s, so requests arrived faster than they could be served. Ollama serialises
// per model, so they queued; each one aged toward the backend timeout while
// waiting, and roughly a third returned 500.
//
// The fix is to decouple generation from request serving:
//   - exactly one generation may be in flight at a time (single-flight)
//   - generation runs on a timer, not on request
//   - requests return the last completed result immediately, with its age
//
// The endpoint is now fast and always answers. The cost is staleness, which is
// reported rather than hidden.

const { buildBehaviorSummary } = require("./behaviorSummary");
const { buildCopilotCore } = require("./copilotCore");
const { generateCopilotInsight } = require("./copilotReasoner");
const { validateInsight } = require("./insightValidator");
const { checkCoreConsistency } = require("./coreConsistency");

const REFRESH_MS = Number(process.env.INSIGHT_CACHE_REFRESH_MS || 300000);
const WINDOW_MIN = Number(process.env.INSIGHT_WINDOW_MIN || 60);

let cache = {
  generatedAt: null,
  durationMs: null,
  llmStatus: "pending",
  behaviorStatus: "pending",
  coreSummary: null,
  behaviorSummary: null,
  copilot: null,
  error: null,
};

let inFlight = null;
let timer = null;

async function generateOnce() {
  const started = Date.now();

  const coreSummary = await buildCopilotCore({ minutes: WINDOW_MIN });

  let behaviorSummary = null;
  let behaviorStatus = "ok";
  try {
    behaviorSummary = await buildBehaviorSummary({
      minutes: WINDOW_MIN,
      limit: 5000,
    });
  } catch (err) {
    behaviorStatus = "unavailable";
    behaviorSummary = { available: false, reason: err.message };
  }

  let copilot = null;
  let llmStatus = "ok";
  try {
    copilot = await generateCopilotInsight({
      behavior: behaviorSummary,
      core: coreSummary,
    });
    // generateCopilotInsight catches transport errors internally and RETURNS
    // { available:false, reason }. Without this check llmStatus reports "ok"
    // for a request that timed out.
    if (copilot && copilot.available === false) {
      llmStatus = "unavailable";
    }
  } catch (err) {
    llmStatus = "unavailable";
    copilot = { available: false, reason: err.message };
  }

  // Validate the generation against the report it came from. Syntactic
  // grounding cannot detect a claim that contradicts the core's own
  // determination; this can, for the subjects it knows about.
  // Self-consistency of the deterministic core, independent of the model.
  let consistency = null;
  try {
    consistency = checkCoreConsistency(coreSummary);
    if (consistency && consistency.consistent === false) {
      console.log("core consistency: " + JSON.stringify(consistency.counts));
    }
  } catch (e) {
    consistency = { error: e.message };
  }

  let validation = null;
  try {
    const ins = copilot && copilot.insight ? copilot.insight : copilot;
    validation = validateInsight(ins, { core: coreSummary, behavior: behaviorSummary });
    if (validation && validation.clean === false) {
      console.log("insight validation: " + JSON.stringify(validation.issueCounts));
    }
  } catch (e) {
    validation = { error: e.message };
  }

  cache = {
    generatedAt: new Date().toISOString(),
    validation,
    consistency,
    durationMs: Date.now() - started,
    llmStatus,
    behaviorStatus,
    coreSummary,
    behaviorSummary,
    copilot,
    error: null,
  };

  console.log(
    "insight cache refreshed in " +
      (cache.durationMs / 1000).toFixed(1) +
      "s (llm: " + llmStatus + ")"
  );

  return cache;
}

// Single-flight: concurrent callers share one generation rather than starting
// their own. This is the property that prevents queue collapse.
function refresh() {
  if (inFlight) return inFlight;

  inFlight = generateOnce()
    .catch((err) => {
      console.error("insight cache refresh failed:", err.message);
      cache = Object.assign({}, cache, { error: err.message });
      return cache;
    })
    .finally(() => {
      inFlight = null;
    });

  return inFlight;
}

// Last completed result, with age. Never blocks.
function get() {
  const ageMs = cache.generatedAt
    ? Date.now() - new Date(cache.generatedAt).getTime()
    : null;
  return Object.assign({}, cache, {
    ageMs,
    refreshing: inFlight !== null,
    refreshIntervalMs: REFRESH_MS,
  });
}

function start() {
  if (timer) return;
  console.log(
    "insight cache starting (window " + WINDOW_MIN + "m, refresh " +
      REFRESH_MS / 1000 + "s)"
  );
  refresh();
  timer = setInterval(refresh, REFRESH_MS);
  if (timer.unref) timer.unref();
}

function stop() {
  if (timer) clearInterval(timer);
  timer = null;
}

module.exports = { start, stop, get, refresh };
