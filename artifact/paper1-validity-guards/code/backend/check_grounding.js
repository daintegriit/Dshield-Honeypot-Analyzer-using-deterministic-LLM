/**
 * check_grounding.js
 * ---------------------------------------------------------------------------
 * Measures whether the Copilot's generated explanations cite REAL data.
 *
 * WHAT THIS MEASURES (and what it does not)
 * -----------------------------------------
 * The reasoner asks the model to attach an `evidence` array to each finding,
 * containing FIELD NAMES from the situation report (e.g. "portEntropy",
 * "scanningIndicators.topPorts"). This script resolves each cited path against
 * the actual { core, behavior } object that was fed to the model, and classifies:
 *
 *   RESOLVED_NONZERO  the field exists and carries a meaningful value
 *   RESOLVED_ZERO     the field exists but is 0 / null / empty
 *                     -> cited as evidence while contributing nothing
 *   UNRESOLVED        the path does not exist in the situation report at all
 *                     -> the model invented a field name
 *
 * STRICT, NOT SEMANTIC. This checks that a citation POINTS AT SOMETHING REAL.
 * It cannot check that the cited value SUPPORTS the claim. Observed example:
 * the model cited `burstRatio5mOverHour` as evidence for "repeated connection
 * attempts", and that field does exist and is non-zero (~0.083) — but under a
 * constant-rate replay 0.083 is exactly the uniform-traffic baseline, i.e. it
 * indicates NO burst. That citation passes this check and should not.
 * Semantic support requires a per-field rubric or a judge model; treat this
 * metric as a floor, not a verdict.
 *
 * USAGE
 *   node check_grounding.js --n 20 --window 5 --end 2026-07-15T09:00:00Z \
 *                          --source replay --out grounding_run1.json
 */

require("dotenv").config();
const fs = require("fs");
const mongoose = require("mongoose");

const { buildBehaviorSummary } = require("./services/behaviorSummary");
const { buildCopilotCore } = require("./services/copilotCore");
const { generateCopilotInsight } = require("./services/copilotReasoner");

// ---------------- args ----------------
function arg(name, def = null) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith("--") ? v : true;
}

const N = Number(arg("n", 10));
const WINDOW = Number(arg("window", 5));
const WINDOW_END = arg("end", null);
const SOURCE = arg("source", "replay");
const LIMIT = Number(arg("limit", 5000));
const OUT = arg("out", `grounding_${Date.now()}.json`);
// --governed false runs the ungoverned (faithfulness-stripped) prompt; default governed
const GOVERNED = arg("governed", "true") !== "false";

// ---------------- path resolution ----------------

/**
 * Normalise a citation string before resolution.
 *
 * OBSERVED (n=20 baseline run): 22/122 citations failed a strict lookup, but
 * only 8 were genuine fabrications. The rest were FORMAT errors pointing at
 * real fields:
 *
 *   "attackMetrics:attacksLast1Min"          -> ':' used as separator (10 cases)
 *   "portEntropy: 1.646"                     -> value inlined into the name (4)
 *   "attackMetrics.attacksLast5Min: 10808"   -> ditto, and the value was CORRECT
 *
 * Counting those as hallucinations overstates ungroundedness. We normalise them
 * and record that we had to, so "malformed but real" is reported separately
 * from "invented".
 *
 * Returns { path, malformed, reason }.
 */
function normaliseCitation(raw) {
  if (typeof raw !== "string") return { path: "", malformed: true, reason: "non-string" };

  let p = raw.trim();
  const reasons = [];

  // strip an inlined value:  "portEntropy: 1.646"  ->  "portEntropy"
  // only when what follows the colon looks like DATA (number, quote, bracket),
  // otherwise the colon is probably a separator (see next rule).
  const inlined = p.match(/^([A-Za-z0-9_.\[\]]+)\s*:\s*([\d\-{["'].*)$/);
  if (inlined) {
    p = inlined[1];
    reasons.push("inlined-value");
  }

  // ':' used where '.' belongs:  "attackMetrics:attacksLast1Min"
  if (p.includes(":")) {
    p = p.replace(/:/g, ".");
    reasons.push("colon-separator");
  }

  // prose rather than a field reference — spaces and no dotted structure
  const looksLikeProse = /\s/.test(p) && !/^[A-Za-z0-9_]+(\.[A-Za-z0-9_\[\]]+)+$/.test(p);
  if (looksLikeProse) {
    return { path: p, malformed: true, reason: "prose-not-field" };
  }

  p = p.replace(/^\$?\.?/, "").replace(/\.+$/, "");
  return { path: p, malformed: reasons.length > 0, reason: reasons.join("+") || null };
}

/**
 * Resolve a dotted path against the situation report.
 * The model cites paths inconsistently — sometimes fully qualified
 * ("scanningIndicators.topPorts"), sometimes bare ("portEntropy"). So we try
 * the literal path first, then search for a bare key anywhere in the tree.
 */
function resolvePath(report, path) {
  if (!path || typeof path !== "string") return { found: false };

  const clean = path.trim().replace(/^\$?\.?/, "");

  // 1. literal dotted lookup from a few plausible roots
  const roots = [report, report.core, report.behavior, report.behavior?.behavior];
  for (const root of roots) {
    if (!root) continue;
    let cur = root;
    let ok = true;
    for (const part of clean.split(".")) {
      if (cur && typeof cur === "object" && part in cur) {
        cur = cur[part];
      } else {
        ok = false;
        break;
      }
    }
    if (ok) return { found: true, value: cur, via: "literal" };
  }

  // 2. bare-key search anywhere in the tree (bounded depth)
  const leaf = clean.split(".").pop();
  const seen = new Set();
  function walk(obj, depth) {
    if (!obj || typeof obj !== "object" || depth > 6) return null;
    if (seen.has(obj)) return null;
    seen.add(obj);
    if (leaf in obj) return { found: true, value: obj[leaf], via: "search" };
    for (const k of Object.keys(obj)) {
      const r = walk(obj[k], depth + 1);
      if (r) return r;
    }
    return null;
  }
  const found = walk(report, 0);
  return found || { found: false };
}

/** Is a resolved value actually carrying information? */
function isMeaningful(v) {
  if (v === null || v === undefined) return false;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") return v.trim() !== "" && v !== "none" && v !== "unknown";
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.keys(v).length > 0;
  if (typeof v === "boolean") return true;
  return false;
}

/** Pull every evidence citation out of an insight object. */
function extractCitations(insight) {
  const out = [];
  if (!insight || typeof insight !== "object") return out;

  for (const f of insight.top_findings || []) {
    for (const e of f.evidence || []) {
      out.push({ field: e, claim: f.finding, confidence: f.confidence, section: "top_findings" });
    }
  }
  for (const t of insight.likely_tactics || []) {
    for (const e of t.evidence || []) {
      out.push({ field: e, claim: t.tactic, confidence: t.confidence, section: "likely_tactics" });
    }
  }
  for (const key of ["what_changed", "evidence"]) {
    const v = insight[key];
    if (Array.isArray(v)) {
      for (const e of v) {
        if (typeof e === "string") out.push({ field: e, claim: `(${key})`, section: key });
      }
    }
  }
  return out;
}

// ---------------- main ----------------
(async () => {
  await mongoose.connect(process.env.MONGO_URI, { socketTimeoutMS: 0 });

  console.log("=".repeat(74));
  console.log("   COPILOT GROUNDING CHECK — do cited evidence fields exist?");
  console.log("=".repeat(74));
  console.log(`  generations : ${N}`);
  console.log(`  window      : ${WINDOW} min   source: ${SOURCE}`);
  console.log(`  windowEnd   : ${WINDOW_END || "(live)"}`);
  console.log("-".repeat(74));

  const opts = {
    minutes: WINDOW,
    sourceFilter: SOURCE === "all" ? null : SOURCE,
    ...(WINDOW_END ? { windowEnd: WINDOW_END } : {}),
  };

  // Build the situation report ONCE — identical input for every generation, so
  // any variation is the model's, not the data's.
  const core = await buildCopilotCore(opts);
  const behavior = await buildBehaviorSummary({ ...opts, limit: LIMIT });
  const report = { behavior, core };

  if (core.sourceFilter !== behavior.core?.sourceFilter) {
    console.log(`  ⚠️  SCOPE MISMATCH: core=${core.sourceFilter} behavior.core=${behavior.core?.sourceFilter}`);
    console.log(`      The model is being handed two views of different traffic.`);
  } else {
    console.log(`  ✓ scopes agree: ${core.sourceFilter}`);
  }
  console.log(`  ✓ core risk=${core.riskScore0to100} state=${core.state} ` +
              `dominant=${core.attackClassification.dominantAttack.type}`);
  console.log("-".repeat(74));

  const runs = [];
  report.governed = GOVERNED;
  console.log(`  [config] governed=${GOVERNED}`);
  let totals = { cited: 0, nonzero: 0, zero: 0, unresolved: 0, prose: 0,
                 malformedButReal: 0, failed: 0 };
  const failures = [];

  for (let i = 0; i < N; i++) {
    process.stdout.write(`  [${String(i + 1).padStart(3)}/${N}] `);
    let insight = null;
    try {
      const out = await generateCopilotInsight(report);
      insight = out?.insight || null;
      if (!out?.ok || !insight) {
        // The reasoner returns { ok:false, error, parseError, rawPreview } for
        // malformed LLM JSON rather than throwing — carry that detail through.
        const e = new Error(out?.error || "no insight");
        e.parseError = out?.parseError || null;
        e.rawPreview = out?.rawPreview || null;
        throw e;
      }
    } catch (err) {
      totals.failed++;
      // Capture enough to classify WHY generations fail — a 10% failure rate is
      // an operational number, not noise, and "invalid JSON" vs "timeout" vs
      // "empty response" are different problems.
      const detail = {
        i,
        message: err.message,
        kind: /JSON/i.test(err.message) ? "invalid_json"
            : /timeout|abort/i.test(err.message) ? "timeout"
            : /empty|no insight/i.test(err.message) ? "empty_response"
            : "other",
        parseError: err.parseError || null,
        rawPreview: err.rawPreview || null,
      };
      failures.push(detail);
      console.log(`generation FAILED [${detail.kind}]: ${err.message}`);
      runs.push({ i, ok: false, ...detail });
      continue;
    }

    const cites = extractCitations(insight);
    const results = cites.map((c) => {
      const norm = normaliseCitation(c.field);
      const r = norm.path ? resolvePath(report, norm.path) : { found: false };

      let verdict;
      if (!r.found) {
        // Distinguish "wrote prose instead of a field name" from "named a field
        // that does not exist". Both are schema violations; only the second is
        // a claim about data that is not there.
        verdict = norm.reason === "prose-not-field" ? "PROSE_NOT_FIELD" : "UNRESOLVED";
      } else if (!isMeaningful(r.value)) {
        verdict = "RESOLVED_ZERO";
      } else {
        verdict = "RESOLVED_NONZERO";
      }

      return {
        ...c,
        normalisedPath: norm.path,
        malformed: norm.malformed,
        malformedReason: norm.reason,
        verdict,
        via: r.via || null,
        value: r.found ? JSON.stringify(r.value).slice(0, 120) : null,
      };
    });

    const n = results.length;
    const ok = results.filter((r) => r.verdict === "RESOLVED_NONZERO").length;
    const zero = results.filter((r) => r.verdict === "RESOLVED_ZERO").length;
    const miss = results.filter((r) => r.verdict === "UNRESOLVED").length;
    const prose = results.filter((r) => r.verdict === "PROSE_NOT_FIELD").length;
    const malformedButReal = results.filter((r) => r.malformed && r.verdict === "RESOLVED_NONZERO").length;

    totals.cited += n; totals.nonzero += ok; totals.zero += zero;
    totals.unresolved += miss; totals.prose += prose; totals.malformedButReal += malformedButReal;

    console.log(`cited=${String(n).padStart(2)}  ok=${String(ok).padStart(2)}  ` +
                `zero=${String(zero).padStart(2)}  prose=${String(prose).padStart(2)}  ` +
                `invented=${String(miss).padStart(2)}` +
                (malformedButReal ? `  (${malformedButReal} malformed-but-real)` : "") +
                (miss ? `   <- ${results.filter(r=>r.verdict==="UNRESOLVED").map(r=>r.field).join(", ")}` : ""));

    // Store the report and the full findings so semantic validation can be
    // run over the batch afterwards. The grounding checker records citations
    // and claims only, which is enough for existence checking but not for
    // contradiction checking -- that needs attackIndicators from the report.
    runs.push({
      i,
      ok: true,
      headline: insight.headline,
      citations: results,
      findings: insight.top_findings || [],
      report: { core: report.core, behavior: report.behavior },
    });
  }

  // ---------------- report ----------------
  const denom = totals.cited || 1;
  console.log("\n" + "=".repeat(74));
  console.log("  RESULTS");
  console.log("=".repeat(74));
  console.log(`  generations succeeded : ${N - totals.failed}/${N}  ` +
              `(${(100*(N-totals.failed)/N).toFixed(0)}%)`);
  console.log(`  total citations       : ${totals.cited}`);
  console.log("");
  console.log(`  resolved & non-zero   : ${totals.nonzero}  (${(100*totals.nonzero/denom).toFixed(1)}%)`);
  console.log(`    of which malformed  : ${totals.malformedButReal}  ` +
              `(real field, wrong syntax — e.g. "a:b" or "a: 1.646")`);
  console.log(`  resolved but ZERO     : ${totals.zero}  (${(100*totals.zero/denom).toFixed(1)}%)`);
  console.log(`  prose, not a field    : ${totals.prose}  (${(100*totals.prose/denom).toFixed(1)}%)`);
  console.log(`  INVENTED field name   : ${totals.unresolved}  (${(100*totals.unresolved/denom).toFixed(1)}%)`);
  console.log("");
  console.log(`  GROUNDING RATE        : ${(100*totals.nonzero/denom).toFixed(1)}%`);
  console.log(`    (citations pointing at real, non-empty data)`);
  console.log(`  FABRICATION RATE      : ${(100*totals.unresolved/denom).toFixed(1)}%`);
  console.log(`    (field names with no referent — the honest hallucination measure)`);
  console.log(`  SCHEMA COMPLIANCE     : ${(100*(totals.cited - totals.prose - totals.malformedButReal)/denom).toFixed(1)}%`);
  console.log(`    (well-formed field references, no prose, no inlined values)`);
  console.log("");
  console.log("  NOTE: this is a STRICT existence check, not semantic support.");
  console.log("  A citation can resolve to a real non-zero value that does not");
  console.log("  actually support the claim (e.g. burstRatio5mOverHour ~= 0.083");
  console.log("  is the uniform-traffic baseline, i.e. evidence of NO burst).");
  console.log("=".repeat(74));

  // which fields get cited most, and how they fare
  const byField = {};
  for (const r of runs) {
    for (const c of r.citations || []) {
      byField[c.field] = byField[c.field] || { n: 0, nonzero: 0, zero: 0, unresolved: 0 };
      byField[c.field].n++;
      if (c.verdict === "RESOLVED_NONZERO") byField[c.field].nonzero++;
      else if (c.verdict === "RESOLVED_ZERO") byField[c.field].zero++;
      else byField[c.field].unresolved++;
    }
  }
  console.log("\n  CITED FIELDS");
  console.log("  " + "-".repeat(70));
  Object.entries(byField).sort((a, b) => b[1].n - a[1].n).forEach(([f, s]) => {
    const flag = s.unresolved ? "  <- INVENTED" : (s.zero === s.n ? "  <- always zero" : "");
    console.log(`  ${f.padEnd(38)} n=${String(s.n).padStart(3)}  ok=${s.nonzero}  zero=${s.zero}  miss=${s.unresolved}${flag}`);
  });

  if (failures.length) {
    console.log("\n  GENERATION FAILURES");
    console.log("  " + "-".repeat(70));
    const byKind = {};
    for (const f of failures) byKind[f.kind] = (byKind[f.kind] || 0) + 1;
    Object.entries(byKind).forEach(([k, v]) =>
      console.log(`  ${k.padEnd(20)} ${v}/${N}  (${(100*v/N).toFixed(0)}%)`));
    console.log("");
    for (const f of failures) {
      console.log(`  [gen ${f.i}] ${f.kind}: ${f.message}`);
      if (f.parseError) console.log(`      parseError: ${f.parseError}`);
      if (f.rawPreview) console.log(`      raw: ${String(f.rawPreview).slice(0,200).replace(/\n/g," ")}`);
    }
  }

  fs.writeFileSync(OUT, JSON.stringify({
    config: { n: N, window: WINDOW, windowEnd: WINDOW_END, source: SOURCE },
    coreVersion: core.coreVersion,
    groundTruth: {
      risk: core.riskScore0to100,
      state: core.state,
      riskComponents: core.riskComponents,
      attackTypeScores: core.attackClassification.attackTypeScores,
    },
    totals,
    failures,
    groundingRate: totals.nonzero / denom,
    fabricationRate: totals.unresolved / denom,
    schemaCompliance: (totals.cited - totals.prose - totals.malformedButReal) / denom,
    byField,
    runs,
  }, null, 2));
  console.log(`\n  full results -> ${OUT}`);

  await mongoose.disconnect();
  process.exit(0);
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
