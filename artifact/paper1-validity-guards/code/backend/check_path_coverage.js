#!/usr/bin/env node
//
// check_path_coverage.js — does every route to the model pass the same gates?
//
// WHY THIS EXISTS
// ---------------
// Three times in one session a mechanism was added to one code path while
// another path to the same operation stayed open. Each was correct in
// isolation, silently absent elsewhere, and produced no error:
//
//   1. The insight cache short-circuited before the controller read
//      req.query.source, so every scoped request received an unscoped result.
//      The replay harness asked for ?source=replay and was served scores
//      computed over live honeypot traffic. Found only because the numbers
//      happened to match the honeypot's.
//
//   2. assessQuestionAdmissibility was passed the outer summary object while
//      its templates declare paths relative to .behavior, so the only
//      non-keyword governance check returned INSUFFICIENT_EVIDENCE on every
//      question. All required fields were present one level down.
//
//   3. checkStateSupportsNarration was wired into the cached generation path.
//      The live scoped path was not gated, and continued to answer a request
//      for a window with zero events with "Potential Scanning Activity
//      Detected".
//
// A guard placed on one route is absent from every other route to the same
// operation, and neither route reports that anything is missing. This checks
// the property directly rather than waiting to be bitten a fourth time.
//
// WHAT THIS CHECKS
// For each call to a generation function, which gates appear in the enclosing
// function. Purely syntactic: it does not verify a gate is reached, only that
// it is present in the same scope. A gate behind a condition that never fires
// would pass here.
//
// USAGE
//   node check_path_coverage.js            # from ~/backend
//   node check_path_coverage.js --json
// Exit status 1 if any unexempted site is missing a required gate, so this can
// run as a pre-commit or CI check.

"use strict";

const fs = require("fs");
const path = require("path");

// Calls that reach the model.
const GENERATION_CALLS = [
  "generateCopilotInsight",
  "answerCopilotQuestion",
  "callLocalOllama",
];

// Gates every generation site should pass through.
const REQUIRED_GATES = {
  checkStateSupportsNarration:
    "refuse states that support no claim (stateDegeneracy.js)",
  checkCoreConsistency:
    "verify the core does not contradict itself (coreConsistency.js)",
  validateInsight:
    "verify generated claims against the core (insightValidator.js)",
};

// Deliberate exemptions. Each needs a reason: an unexplained exemption is the
// same failure this script exists to catch, one level up.
const EXEMPT = {
  "copilotAskController.js": {
    reason:
      "validateInsight only. buildQuestionPrompt rule 15 forbids exposing " +
      "field names in analyst answers, so there are no citations to validate. " +
      "The two prompts impose opposite requirements: the insight path mandates " +
      "field citations, this one forbids them. The analyst-facing path is " +
      "therefore unvalidated by construction, which is a finding rather than a " +
      "gap to close here.",
    gates: ["validateInsight"],
  },
  "check_grounding.js": {
    reason:
      "evaluation harness. Measures unconstrained model behaviour, so gating " +
      "it would change the thing being measured. Its results describe the " +
      "model, not the deployed pipeline, and must be labelled as such.",
    gates: ["checkStateSupportsNarration", "checkCoreConsistency", "validateInsight"],
  },
  "copilotReasoner.js": {
    reason:
      "the generation functions themselves. Gating here would place the check " +
      "inside the thing being gated.",
    gates: ["checkStateSupportsNarration", "checkCoreConsistency", "validateInsight"],
  },
  "localOllamaProvider.js": {
    reason: "transport layer. Has no access to a core summary to check.",
    gates: ["checkStateSupportsNarration", "checkCoreConsistency", "validateInsight"],
  },
};

const SCAN_DIRS = ["controllers", "services", "services/llmProviders", "."];

function jsFilesIn(dir) {
  let out = [];
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (e.name === "node_modules" || e.name.startsWith(".")) continue;
    const full = path.join(dir, e.name);
    if (e.isFile() && e.name.endsWith(".js") && !e.name.includes(".bak")) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Function spans by brace matching. Crude but adequate: we need to know which
 * function a call sits in, not to parse JavaScript correctly.
 */
function functionSpans(src) {
  const lines = src.split("\n");
  const decl = /^\s*(?:async\s+)?function\s+([A-Za-z0-9_$]+)|^\s*const\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(/;
  const spans = [];

  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(decl);
    if (!m) continue;
    const name = m[1] || m[2];

    let depth = 0;
    let started = false;
    let end = i;
    for (let j = i; j < lines.length; j++) {
      for (const ch of lines[j]) {
        if (ch === "{") { depth++; started = true; }
        else if (ch === "}") depth--;
      }
      if (started && depth <= 0) { end = j; break; }
      end = j;
    }
    spans.push({ name, start: i, end });
  }
  return spans;
}

function enclosing(spans, lineIdx) {
  // Innermost span containing the line.
  let best = null;
  for (const s of spans) {
    if (lineIdx >= s.start && lineIdx <= s.end) {
      if (!best || s.end - s.start < best.end - best.start) best = s;
    }
  }
  return best;
}

function analyseFile(file) {
  const src = fs.readFileSync(file, "utf8");
  const lines = src.split("\n");
  const spans = functionSpans(src);
  const base = path.basename(file);
  const sites = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("//") || line.trim().startsWith("*")) continue;

    for (const call of GENERATION_CALLS) {
      // A call, not an import or an export.
      const isCall = new RegExp(`\\b${call}\\s*\\(`).test(line);
      const isImport = /require\s*\(/.test(line) || /^\s*(module\.)?exports/.test(line);
      if (!isCall || isImport) continue;

      const fn = enclosing(spans, i);
      const body = fn ? lines.slice(fn.start, fn.end + 1).join("\n") : "";

      const present = {};
      for (const gate of Object.keys(REQUIRED_GATES)) {
        present[gate] = new RegExp(`\\b${gate}\\s*\\(`).test(body);
      }

      sites.push({
        file: base,
        path: file,
        line: i + 1,
        call,
        fn: fn ? fn.name : "(top level)",
        gates: present,
        missing: Object.keys(REQUIRED_GATES).filter((g) => !present[g]),
      });
    }
  }
  return sites;
}

function main() {
  const files = [];
  for (const d of SCAN_DIRS) files.push(...jsFilesIn(d));

  let sites = [];
  for (const f of [...new Set(files)]) sites.push(...analyseFile(f));

  // Apply exemptions.
  for (const s of sites) {
    const ex = EXEMPT[s.file];
    s.exempt = !!ex;
    s.exemptReason = ex ? ex.reason : null;
    s.unexcused = ex
      ? s.missing.filter((g) => !ex.gates.includes(g))
      : s.missing;
  }

  if (process.argv.includes("--json")) {
    console.log(JSON.stringify({ sites }, null, 2));
  } else {
    console.log("=".repeat(78));
    console.log("  GENERATION PATH COVERAGE");
    console.log("=".repeat(78));
    console.log(`  ${sites.length} call site(s) reaching the model\n`);

    const gateNames = Object.keys(REQUIRED_GATES);
    const short = { checkStateSupportsNarration: "narration",
                    checkCoreConsistency: "consistency",
                    validateInsight: "validation" };

    console.log(
      `  ${"file:line".padEnd(38)} ${"function".padEnd(24)} ` +
      gateNames.map((g) => short[g].padEnd(11)).join("")
    );
    console.log("  " + "-".repeat(74));

    for (const s of sites) {
      const loc = `${s.file}:${s.line}`.padEnd(38);
      const fn = s.fn.slice(0, 23).padEnd(24);
      const marks = gateNames
        .map((g) => (s.gates[g] ? "yes" : s.exempt ? "n/a" : "NO ").padEnd(11))
        .join("");
      console.log(`  ${loc} ${fn} ${marks}`);
    }

    const failures = sites.filter((s) => s.unexcused.length);
    console.log();

    if (!failures.length) {
      console.log("  Every unexempted generation site passes all gates.\n");
    } else {
      console.log("  " + "!".repeat(74));
      console.log(`  ${failures.length} site(s) missing gates`);
      console.log("  " + "!".repeat(74));
      for (const s of failures) {
        console.log(`\n    ${s.file}:${s.line}  in ${s.fn}()  calls ${s.call}`);
        for (const g of s.unexcused) {
          console.log(`      missing ${g}`);
          console.log(`              ${REQUIRED_GATES[g]}`);
        }
      }
      console.log();
      console.log("  A gate present on one route is absent from every other route to the");
      console.log("  same operation. Neither route reports that anything is missing.");
      console.log();
    }

    const exempted = sites.filter((s) => s.exempt);
    if (exempted.length) {
      console.log("  EXEMPT");
      const seen = new Set();
      for (const s of exempted) {
        if (seen.has(s.file)) continue;
        seen.add(s.file);
        console.log(`    ${s.file}`);
        console.log(`      ${EXEMPT[s.file].reason}`);
      }
      console.log();
    }

    console.log("  NOTE: syntactic. A gate present in the enclosing function passes here");
    console.log("  even if it sits behind a condition that never fires.\n");

    if (failures.length) process.exit(1);
  }
}

main();
