const fs = require("fs");
const path = require("path");
const { validateInsight } =
  require("/home/ubuntu/backend/services/insightValidator.js");

const file = process.argv[2];
if (!file) { console.error("usage: node validate_batch.js <grounding.json>"); process.exit(1); }

const d = JSON.parse(fs.readFileSync(file, "utf8"));
const runs = (d.runs || []).filter((r) => r.ok && r.report && r.findings);

if (!runs.length) {
  console.error("no runs carry report+findings; harness must store them");
  process.exit(1);
}

let findings = 0, flagged = 0;
const counts = {};
const bySubject = {};
const examples = [];

for (const r of runs) {
  const v = validateInsight({ top_findings: r.findings }, r.report);
  findings += v.findingsChecked;
  flagged += v.findingsWithIssues;
  for (const [k, n] of Object.entries(v.issueCounts || {})) counts[k] = (counts[k] || 0) + n;
  for (const f of v.perFinding) {
    for (const i of f.issues) {
      if (i.subject) bySubject[i.subject] = (bySubject[i.subject] || 0) + 1;
      if (examples.length < 12)
        examples.push({ run: r.i, type: i.type, finding: String(f.finding).slice(0, 70),
                        evidence: f.evidence, detail: i.detail.slice(0, 100) });
    }
  }
}

const pct = (a, b) => (b ? (100 * a / b).toFixed(1) + "%" : "n/a");

console.log("\n" + "=".repeat(70));
console.log("  SEMANTIC VALIDATION OVER BATCH");
console.log("=".repeat(70));
console.log("  file            :", path.basename(file));
console.log("  runs scored     :", runs.length, "of", (d.runs || []).length);
console.log("  findings        :", findings);
console.log("  findings flagged:", flagged, "(" + pct(flagged, findings) + ")");
console.log("  issue counts    :", JSON.stringify(counts));
console.log("  by subject      :", JSON.stringify(bySubject));
console.log("\n  EXAMPLES");
for (const e of examples) {
  console.log(`  [run ${e.run}] ${e.type}`);
  console.log(`     ${e.finding}`);
  console.log(`     ev: ${JSON.stringify(e.evidence)}`);
  console.log(`     ${e.detail}`);
}
console.log("\n  NOTE: keyword matching against a hand-declared subject map that");
console.log("  was corrected three times against observed output. Any rate here");
console.log("  is a lower bound on a rubric fitted to these observations.");
