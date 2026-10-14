#!/usr/bin/env node
/**
 * rescore_grounding.js
 * ---------------------------------------------------------------------------
 * OFFLINE re-scoring of an archived Chiron grounding evaluation.
 *
 * Reads ONLY the eval/*.json files produced by check_grounding.js. Does not
 * connect to Mongo, does not call Ollama, does not regenerate anything, and
 * does not write inside the archive. Safe to run against a read-only archive.
 *
 * WHY THIS EXISTS
 * ---------------
 * check_grounding.js reports groundingRate = 1.0 on v3. That number is
 * permissive in two ways this script separates out:
 *
 *   (1) BARE-KEY FALLBACK. resolvePath() first tries a literal dotted lookup;
 *       if that fails it walks the whole report looking for the LAST path
 *       segment anywhere in the tree and returns the first hit, tagged
 *       via:"search". A citation like
 *           "scanningIndicators.scanCandidates.port:53.count"
 *       has no such path (scanCandidates is an array of {port,count}), so the
 *       walker returns some other `count` and the citation is scored
 *       RESOLVED_NONZERO. The citation resolved to a DIFFERENT FIELD than the
 *       one cited. This script reports a STRICT rate that counts only
 *       via:"literal", alongside the permissive rate, so the gap is visible.
 *
 *   (2) NON-VACUITY IS NOT SUPPORT. isMeaningful() passes any non-zero value.
 *       The archive's own MANIFEST documents the counterexample
 *       (burstRatio5mOverHour = 0.083 cited as evidence of burst activity,
 *       where 0.083 IS the uniform baseline). This script does NOT fix that —
 *       semantic support needs a rubric or judge model. What it adds instead is
 *       COVERAGE: given the deterministic ground-truth state vector recorded in
 *       every eval file, which non-zero components did the model's evidence
 *       never touch? That is a completeness measure, computable from what is
 *       already archived, and it is the metric Reviewer 2 asked for.
 *
 * WHAT IT REPORTS
 *   - permissive vs strict grounding rate, with Wilson 95% intervals
 *   - every search-resolved citation, listed, so false passes can be eyeballed
 *   - suspicious-path heuristics (array-index-shaped, colon-in-original)
 *   - coverage of non-zero ground-truth attack classes and risk components
 *   - field concentration (top-k share, HHI, distinct fields) across arms
 *   - malformed-citation breakdown by reason
 *
 * USAGE
 *   node rescore_grounding.js --dir ~/research/results/grounding_20260722T034341Z
 *   node rescore_grounding.js --dir <archive> --out ~/rescore.json
 *   node rescore_grounding.js --dir <archive> --json      # machine-readable only
 *
 * The archive is never modified. Output goes to stdout and, with --out, to a
 * path OUTSIDE the archive.
 */

"use strict";

const fs = require("fs");
const path = require("path");

/* ===========================================================================
   COVERAGE RUBRIC — HAND-DECLARED, EDIT ME
   ===========================================================================
   This maps evidence field paths to the ground-truth components they could
   plausibly support. It is a JUDGEMENT, not a derivation, and it must be
   reported as such in any write-up. Fields not listed here are reported under
   UNMAPPED so the rubric can be extended rather than silently under-counting.

   Matching is by prefix on the normalised path, longest match wins.
=========================================================================== */
const FIELD_TO_COMPONENTS = {
  // scanning evidence
  "scanningIndicators.portEntropy": ["scan"],
  "scanningIndicators.scanCandidates": ["scan"],
  "scanningIndicators.topPorts": ["scan"],
  "scanningIndicators.uniquePorts": ["scan"],
  "scanningIndicators": ["scan"],

  // volume evidence — non-specific, supports dos/scan alike
  "attackMetrics.attacksLast1Min": ["dos", "scan"],
  "attackMetrics.attacksLast5Min": ["dos", "scan"],
  "attackMetrics.burstRatio5mOverHour": ["dos"],
  "attackMetrics": ["dos", "scan"],

  // bare-name variants — the model cites these unqualified (v2 arm, 65+ cases)
  "attacksLast1Min": ["dos", "scan"],
  "attacksLast5Min": ["dos", "scan"],
  "attacksLast15Min": ["dos", "scan"],
  "burstRatio5mOverHour": ["dos"],
  "portEntropy": ["scan"],
  "sourceEntropy": ["scan"],

  // severity / classification
  "severitySignals": ["impact"],
  // A bare citation of the classification block does not demonstrate the model
  // ADDRESSED any particular class — it points at the container. Only
  // per-class sub-paths count as coverage.
  "attackClassification.attackTypeProbabilities.scan": ["scan"],
  "attackClassification.attackTypeProbabilities.dos": ["dos"],
  "attackClassification.attackTypeProbabilities.brute_force": ["brute_force"],
  "attackClassification.attackTypeProbabilities.web_probe": ["web_probe"],
  "attackClassification.attackTypeProbabilities.c2": ["c2"],
  "attackClassification.attackTypeProbabilities.impact": ["impact"],

  // c2 — the class the v3 run never cited
  "riskComponents.c2Bonus": ["c2"],
  "behavior.c2": ["c2"],
  "c2Bonus": ["c2"],

  // brute force
  "attackMetrics.authFailures": ["brute_force"],
  "brute": ["brute_force"],

  // web probe
  "webProbe": ["web_probe"],
  "httpPaths": ["web_probe"],
};

/* Ground-truth components considered "substantive" and therefore expected to be
   addressed by at least one citation. Tunable. */
const ATTACK_SCORE_THRESHOLD = 1.0; // attackTypeScores above this are expected
const RISK_COMPONENT_THRESHOLD = 0.0; // riskComponents strictly above this

/* ========================================================================= */

function arg(name, def = null) {
  const i = process.argv.indexOf(`--${name}`);
  if (i === -1) return def;
  const v = process.argv[i + 1];
  return v && !v.startsWith("--") ? v : true;
}

function fail(msg) {
  console.error(`\nERROR: ${msg}\n`);
  process.exit(1);
}

/* ---------- statistics ---------- */

/** Wilson score interval for a binomial proportion. Returns [lo, hi]. */
function wilson(successes, n, z = 1.96) {
  if (n === 0) return [0, 0];
  const p = successes / n;
  const d = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const half = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [Math.max(0, (centre - half) / d), Math.min(1, (centre + half) / d)];
}

function pct(x) {
  return (100 * x).toFixed(1) + "%";
}

function ci(successes, n) {
  const [lo, hi] = wilson(successes, n);
  return `[${pct(lo)}, ${pct(hi)}]`;
}

/** Herfindahl-Hirschman index over a count map. 1 = all mass on one field. */
function hhi(counts) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return 0;
  return Object.values(counts).reduce((a, c) => a + (c / total) ** 2, 0);
}

/* ---------- citation classification ---------- */

/**
 * A citation is STRICTLY grounded if it resolved to a non-zero value via a
 * literal dotted lookup — i.e. the path the model wrote is a real path.
 * via:"search" means the checker found the leaf key somewhere else in the tree;
 * that is not evidence the cited path exists.
 */
function isStrict(c) {
  return c.verdict === "RESOLVED_NONZERO" && c.via === "literal";
}

function isPermissive(c) {
  return c.verdict === "RESOLVED_NONZERO";
}

/**
 * Heuristics for paths that look structurally impossible against a JSON report.
 * These are flags for human review, not verdicts.
 */
function suspicionFlags(c) {
  const flags = [];
  const raw = String(c.field ?? "");
  const norm = String(c.normalisedPath ?? "");

  // "port:53.count" — an array element addressed as if it were a key
  if (/[A-Za-z0-9_]+[:.]\d+\./.test(raw) || /\.\d+\./.test(norm)) {
    flags.push("array-index-as-key");
  }
  // colon survived into the original citation
  if (raw.includes(":")) flags.push("colon-in-original");
  // deep path resolved by search — the segments above the leaf were never checked
  if (c.via === "search" && norm.includes(".")) flags.push("deep-path-via-search");
  // resolved to an object/array when the claim reads like a scalar comparison
  if (c.via === "search" && /^\[|^\{/.test(String(c.value ?? ""))) {
    flags.push("search-hit-container");
  }
  return flags;
}

/* ---------- coverage ---------- */

function componentsForField(normPath) {
  if (!normPath) return [];
  const keys = Object.keys(FIELD_TO_COMPONENTS).sort((a, b) => b.length - a.length);
  for (const k of keys) {
    if (normPath === k || normPath.startsWith(k + ".")) return FIELD_TO_COMPONENTS[k];
  }
  return null; // null = unmapped, distinct from [] = mapped to nothing
}

/**
 * Minimal re-implementation of check_grounding.js's normaliseCitation, used
 * ONLY for rubric matching on baseline-era records that predate it. Strips an
 * inlined value and converts ':' separators to '.'. This affects coverage
 * accounting only — it never changes a stored verdict.
 */
function normaliseForRubric(raw) {
  if (typeof raw !== "string") return "";
  let p = raw.trim();
  const inlined = p.match(/^([A-Za-z0-9_.\[\]:]+)\s*:\s*([\d\-{["'].*)$/);
  if (inlined) p = inlined[1];
  p = p.replace(/:/g, ".");
  return p.replace(/^\$?\.?/, "").replace(/\.+$/, "");
}

/**
 * Which substantive ground-truth components did ANY citation touch?
 * Coverage is computed per-run as well as pooled, because a pooled hit can be
 * one lucky generation out of twenty.
 */
function coverage(citations, groundTruth) {
  const expected = new Set();

  const scores = groundTruth?.attackTypeScores || {};
  for (const [k, v] of Object.entries(scores)) {
    if (typeof v === "number" && v > ATTACK_SCORE_THRESHOLD) expected.add(k);
  }

  const covered = new Set();
  const unmapped = {};

  for (const c of citations) {
    if (!isPermissive(c)) continue;
    // Baseline-era records predate normaliseCitation() and carry no
    // normalisedPath. Fall back to the raw field so those arms are scored
    // rather than silently mapping to nothing.
    const cited = c.normalisedPath || normaliseForRubric(c.field);
    const comps = componentsForField(cited);
    if (comps === null) {
      unmapped[cited] = (unmapped[cited] || 0) + 1;
      continue;
    }
    for (const comp of comps) if (expected.has(comp)) covered.add(comp);
  }

  const missed = [...expected].filter((e) => !covered.has(e));
  return {
    expected: [...expected],
    covered: [...covered],
    missed,
    rate: expected.size ? covered.size / expected.size : null,
    unmapped,
  };
}

/* ---------- per-arm analysis ---------- */

function analyseArm(name, doc) {
  const runs = Array.isArray(doc.runs) ? doc.runs : [];
  const citations = [];
  for (const r of runs) {
    for (const c of r.citations || []) citations.push({ ...c, run: r.i });
  }

  const n = citations.length;
  const strict = citations.filter(isStrict).length;
  const permissive = citations.filter(isPermissive).length;
  const viaSearch = citations.filter((c) => c.via === "search");
  const malformed = citations.filter((c) => c.malformed);

  // malformed breakdown
  const malformedBy = {};
  for (const c of malformed) {
    const k = c.malformedReason || "(unspecified)";
    malformedBy[k] = (malformedBy[k] || 0) + 1;
  }

  // field distribution
  const fieldCounts = {};
  for (const c of citations) {
    const k = c.normalisedPath || c.field || "(none)";
    fieldCounts[k] = (fieldCounts[k] || 0) + 1;
  }
  const sortedFields = Object.entries(fieldCounts).sort((a, b) => b[1] - a[1]);
  const top3 = sortedFields.slice(0, 3).reduce((a, [, v]) => a + v, 0);

  // suspicion
  const suspicious = [];
  for (const c of citations) {
    const flags = suspicionFlags(c);
    if (flags.length) suspicious.push({ ...c, flags });
  }

  // coverage, pooled and per-run
  const pooled = coverage(citations, doc.groundTruth);
  const perRun = runs.map((r) => {
    const cov = coverage(r.citations || [], doc.groundTruth);
    return { run: r.i, rate: cov.rate, missed: cov.missed };
  });
  const perRunRates = perRun.map((r) => r.rate).filter((x) => typeof x === "number");
  const meanPerRun = perRunRates.length
    ? perRunRates.reduce((a, b) => a + b, 0) / perRunRates.length
    : null;

  return {
    arm: name,
    generations: runs.length,
    okGenerations: runs.filter((r) => r.ok).length,
    citations: n,
    citationsPerGeneration: runs.length ? n / runs.length : 0,

    permissiveGrounded: permissive,
    permissiveRate: n ? permissive / n : 0,
    permissiveCI: wilson(permissive, n),

    strictGrounded: strict,
    strictRate: n ? strict / n : 0,
    strictCI: wilson(strict, n),

    viaSearchCount: viaSearch.length,
    viaSearchRate: n ? viaSearch.length / n : 0,

    malformedCount: malformed.length,
    malformedBy,

    distinctFields: sortedFields.length,
    top3Share: n ? top3 / n : 0,
    hhi: hhi(fieldCounts),
    fieldCounts: Object.fromEntries(sortedFields),

    suspicious,
    searchResolved: viaSearch,

    coverage: pooled,
    coveragePerRunMean: meanPerRun,
    coveragePerRun: perRun,

    reported: {
      groundingRate: doc.groundingRate,
      fabricationRate: doc.fabricationRate,
      schemaCompliance: doc.schemaCompliance,
      totals: doc.totals,
    },
  };
}

/* ---------- reporting ---------- */

function line(ch = "-", w = 78) {
  return ch.repeat(w);
}

function printArm(a) {
  console.log("\n" + line("="));
  console.log(`  ARM: ${a.arm}`);
  console.log(line("="));

  console.log(`  generations        : ${a.generations} (ok: ${a.okGenerations})`);
  console.log(`  citations          : ${a.citations}  (${a.citationsPerGeneration.toFixed(1)}/gen)`);
  console.log("");
  console.log(`  grounding, as reported by check_grounding.js`);
  console.log(`    permissive       : ${pct(a.permissiveRate)}  ${ci(a.permissiveGrounded, a.citations)}   n=${a.permissiveGrounded}/${a.citations}`);
  console.log(`  grounding, strict (literal path only)`);
  console.log(`    strict           : ${pct(a.strictRate)}  ${ci(a.strictGrounded, a.citations)}   n=${a.strictGrounded}/${a.citations}`);
  const gap = a.permissiveRate - a.strictRate;
  console.log(`    gap              : ${pct(gap)}  <- citations resolved by bare-key search`);
  console.log("");
  console.log(`  via:"search"       : ${a.viaSearchCount} (${pct(a.viaSearchRate)})`);
  console.log(`  malformed          : ${a.malformedCount}`);
  for (const [k, v] of Object.entries(a.malformedBy)) {
    console.log(`      ${k.padEnd(24)} ${v}`);
  }
  console.log("");
  console.log(`  distinct fields    : ${a.distinctFields}`);
  console.log(`  top-3 share        : ${pct(a.top3Share)}`);
  console.log(`  HHI                : ${a.hhi.toFixed(3)}   (1.0 = single field)`);

  console.log("");
  console.log(`  COVERAGE of substantive ground-truth attack classes`);
  const cov = a.coverage;
  console.log(`    expected         : ${cov.expected.join(", ") || "(none)"}`);
  console.log(`    covered (pooled) : ${cov.covered.join(", ") || "(none)"}`);
  console.log(`    MISSED           : ${cov.missed.join(", ") || "(none)"}`);
  console.log(`    pooled rate      : ${cov.rate === null ? "n/a" : pct(cov.rate)}`);
  console.log(
    `    per-run mean     : ${a.coveragePerRunMean === null ? "n/a" : pct(a.coveragePerRunMean)}`
  );
  if (Object.keys(cov.unmapped).length) {
    console.log(`    UNMAPPED fields (extend FIELD_TO_COMPONENTS):`);
    for (const [k, v] of Object.entries(cov.unmapped)) {
      console.log(`      ${k}  x${v}`);
    }
  }

  if (a.suspicious.length) {
    console.log("");
    console.log(`  SUSPICIOUS CITATIONS (${a.suspicious.length}) — review by hand`);
    const shown = a.suspicious.slice(0, 15);
    for (const s of shown) {
      console.log(`    run ${String(s.run).padStart(2)}  ${s.field}`);
      console.log(`        -> ${s.normalisedPath}   via:${s.via}  ${s.verdict}`);
      console.log(`        flags: ${s.flags.join(", ")}`);
      console.log(`        claim: ${String(s.claim).slice(0, 68)}`);
      console.log(`        value: ${String(s.value).slice(0, 68)}`);
    }
    if (a.suspicious.length > shown.length) {
      console.log(`    ... ${a.suspicious.length - shown.length} more (see --out JSON)`);
    }
  }
}

function printComparison(arms) {
  console.log("\n" + line("="));
  console.log("  ARM COMPARISON");
  console.log(line("="));

  const cols = ["metric", ...arms.map((a) => a.arm)];
  const w = 22;
  console.log(cols.map((c) => String(c).padEnd(w)).join(""));
  console.log(line("-"));

  const rows = [
    ["citations", (a) => String(a.citations)],
    ["cit/generation", (a) => a.citationsPerGeneration.toFixed(1)],
    ["permissive rate", (a) => pct(a.permissiveRate)],
    ["strict rate", (a) => pct(a.strictRate)],
    ["strict CI", (a) => `${pct(a.strictCI[0])}-${pct(a.strictCI[1])}`],
    ["via:search", (a) => `${a.viaSearchCount} (${pct(a.viaSearchRate)})`],
    ["malformed", (a) => String(a.malformedCount)],
    ["distinct fields", (a) => String(a.distinctFields)],
    ["top-3 share", (a) => pct(a.top3Share)],
    ["HHI", (a) => a.hhi.toFixed(3)],
    ["coverage (pooled)", (a) => (a.coverage.rate === null ? "n/a" : pct(a.coverage.rate))],
    [
      "coverage (per-run)",
      (a) => (a.coveragePerRunMean === null ? "n/a" : pct(a.coveragePerRunMean)),
    ],
    ["missed classes", (a) => a.coverage.missed.join(",") || "-"],
    ["schemaCompliance", (a) => (a.reported.schemaCompliance ?? "n/a").toString().slice(0, 6)],
  ];

  for (const [label, fn] of rows) {
    console.log([label, ...arms.map(fn)].map((c) => String(c).padEnd(w)).join(""));
  }
}

function printCaveats(arms) {
  console.log("\n" + line("="));
  console.log("  CAVEATS — carry these into the write-up");
  console.log(line("="));
  const n = arms[0] ? arms[0].generations : 0;
  console.log(`
  1. STRICT vs PERMISSIVE. The strict rate counts only citations resolved by a
     literal dotted lookup. It is a lower bound: a via:"search" citation is not
     necessarily wrong, it is UNVERIFIED, because the checker never confirmed the
     path above the leaf. Report both rates, never the permissive one alone.

  2. SEMANTIC SUPPORT IS STILL UNMEASURED. Nothing here checks that a cited
     value SUPPORTS its claim. The archive's own burstRatio5mOverHour = 0.083
     example still passes every metric in this script. Coverage measures what was
     NOT cited; it does not validate what was.

  3. THE COVERAGE RUBRIC IS HAND-DECLARED. FIELD_TO_COMPONENTS is a judgement
     call written by the authors. Publish it verbatim. Anything landing in
     UNMAPPED is excluded from coverage and understates it.

  4. ONE SITUATION REPORT. Every arm scores the same windowEnd and the same
     ground-truth state. These numbers describe model variance under one traffic
     condition, not behaviour across conditions.

  5. ARMS DIFFER BY MORE THAN ONE CHANGE. v2 -> v3 altered constrained decoding
     AND the prompt examples together. The archive holds one code_snapshot for
     all arms, so the components cannot be separated post hoc. Any narrowing
     reported here is attributable to the COMBINED change only.

  6. SMALL n. ${n} generations per arm. Wilson intervals are printed for a
     reason — a 0% or 100% rate at this n still admits a wide range.
`);
}

/* ---------- main ---------- */

function main() {
  const dir = arg("dir", null);
  if (!dir) fail("--dir <archive directory> is required");

  const evalDir = fs.existsSync(path.join(dir, "eval")) ? path.join(dir, "eval") : dir;
  if (!fs.existsSync(evalDir)) fail(`no such directory: ${evalDir}`);

  const files = fs
    .readdirSync(evalDir)
    .filter((f) => f.endsWith(".json"))
    .sort();
  if (!files.length) fail(`no .json files in ${evalDir}`);

  const arms = [];
  for (const f of files) {
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(path.join(evalDir, f), "utf8"));
    } catch (e) {
      console.error(`  skipping ${f}: ${e.message}`);
      continue;
    }
    if (!Array.isArray(doc.runs)) {
      console.error(`  skipping ${f}: no runs[] array`);
      continue;
    }
    const name = f.replace(/^grounding_/, "").replace(/\.json$/, "");
    arms.push(analyseArm(name, doc));
  }

  if (!arms.length) fail("no usable eval files");

  console.log("");
  console.log(line("="));
  console.log("  CHIRON GROUNDING — OFFLINE RE-SCORE");
  console.log(line("="));
  console.log(`  archive : ${dir}`);
  console.log(`  arms    : ${arms.map((a) => a.arm).join(", ")}`);
  console.log(`  note    : archive is read-only to this script`);

  for (const a of arms) printArm(a);
  if (arms.length > 1) printComparison(arms);
  printCaveats(arms);

  const out = arg("out", null);
  if (out) {
    const payload = {
      generatedAt: new Date().toISOString(),
      archive: dir,
      rubric: FIELD_TO_COMPONENTS,
      thresholds: { ATTACK_SCORE_THRESHOLD, RISK_COMPONENT_THRESHOLD },
      arms,
    };
    fs.writeFileSync(out, JSON.stringify(payload, null, 2));
    console.log(`\n  wrote ${out}\n`);
  }
}

main();
