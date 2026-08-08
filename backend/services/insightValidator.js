// backend/services/insightValidator.js
//
// The grounding checker verifies a cited field EXISTS and is non-vacuous. It
// cannot verify the cited value SUPPORTS the claim. Measured on live honeypot
// traffic (2026-08-08, n=20): the model produced the finding
//
//     "Traffic burst ratio exceeded normal baseline behavior"
//
// in four separate generations, citing attackClassification.dominantAttackScore
// and .dominantAttackType. Both resolved through the checker's leaf-key
// fallback. Neither is a burst field. The report contained, explicitly:
//
//     reasoning.attackIndicators.burstDetected: false
//     attackMetrics.burstRatio5mOverHour: 0.294   (threshold 0.35)
//
// The core had already determined no burst occurred. The model contradicted a
// boolean in the report it was told to treat as authoritative, and every
// syntactic metric passed: 91.5% strict grounding, 100% coverage, 0 malformed.
//
// CHECKS: contradiction, path validity (literal only), evidence relevance.
//
// This is keyword matching against a hand-declared map, not semantic
// understanding. A clean result means no contradiction was DETECTED.

"use strict";

const SUBJECTS = {
  burst: {
    keywords: ["burst", "spike", "surge", "sudden increase",
      "exceeded baseline", "above baseline", "abnormal rate"],
    indicator: "burstDetected",
    validEvidence: ["attackMetrics.burstRatio5mOverHour",
      "attackMetrics.burstRatio15mOverHour"],
  },
  scanning: {
    // "port entropy" and "probing" removed: the core's scanningDetected rule
    // is (dominantAttack.type==="scan" || scanCandidates.length>0) and does not
    // consider entropy, so an accurate entropy claim was being flagged.
    keywords: ["scan", "scanning", "enumeration", "port sweep"],
    indicator: "scanningDetected",
    validEvidence: ["scanningIndicators.portEntropy",
      "scanningIndicators.scanCandidates", "scanningIndicators.topPorts",
      "scanningIndicators.uniquePorts"],
  },
  c2: {
    keywords: ["command-and-control", "command and control", "c2", "c&c",
      "beacon", "beaconing", "periodic communication"],
    indicator: "c2BehaviorDetected",
    validEvidence: ["attackClassification.c2Signals", "riskComponents.c2Bonus",
      "attackClassification.attackTypeScores.c2",
      "attackClassification.attackTypeProbabilities.c2"],
  },
  authentication: {
    keywords: ["brute force", "brute-force", "credential", "login attempt",
      "authentication", "password"],
    indicator: "authenticationTargeting",
    validEvidence: ["scanningIndicators.authPortPressure"],
  },
  web: {
    keywords: ["web probe", "web-probe", "http probing", "web infrastructure"],
    indicator: "webInfrastructureTargeting",
    validEvidence: ["scanningIndicators.webPortPressure"],
  },
  database: {
    keywords: ["database targeting", "sql", "database service"],
    indicator: "databaseTargeting",
    validEvidence: ["scanningIndicators.dbPortPressure"],
  },
  volume: {
    keywords: ["high volume", "high-volume", "elevated volume", "volumetric"],
    indicator: "highVolumeDetected",
    validEvidence: ["attackMetrics.attacksLast1Min",
      "attackMetrics.attacksLast5Min", "attackMetrics.attacksLast15Min"],
  },
  severity: {
    keywords: ["critical severity", "severity escalation", "severe"],
    indicator: "severityEscalationDetected",
    validEvidence: ["severitySignals.criticalCountWindow",
      "severitySignals.highCountWindow"],
  },
};

// A claim asserting ABSENCE agrees with indicator=false. Deliberately
// conservative: any negation cue suppresses the flag, missing some real ones.
const NEGATION_CUES = ["no ", "not ", "without", "absence of", "lack of",
  "did not", "does not", "none ", "zero ", "no evidence", "unlikely",
  "absent", "below"];

function isNegated(text) {
  const t = text.toLowerCase();
  return NEGATION_CUES.some((c) => t.includes(c));
}

function mentionsSubject(text, subject) {
  const t = text.toLowerCase();
  return SUBJECTS[subject].keywords.some((k) => t.includes(k));
}

// Literal lookup only. No leaf-key fallback -- that fallback is exactly what
// let six invalid citations score as grounded on the live run.
function resolveLiteral(report, path) {
  if (!path || typeof path !== "string") return { found: false };
  const clean = path.trim().replace(/^\$?\.?/, "");
  const roots = [report, report.core, report.behavior];
  for (const root of roots) {
    if (!root) continue;
    let cur = root;
    let ok = true;
    for (const part of clean.split(".")) {
      if (cur && typeof cur === "object" && part in cur) cur = cur[part];
      else { ok = false; break; }
    }
    if (ok) return { found: true, value: cur };
  }
  return { found: false };
}

function indicatorsFrom(report) {
  return (report && report.core && report.core.reasoning &&
          report.core.reasoning.attackIndicators) ||
         (report && report.reasoning && report.reasoning.attackIndicators) ||
         {};
}

function validateFinding(finding, report) {
  const issues = [];
  const text = String(finding.finding || "");
  const evidence = Array.isArray(finding.evidence) ? finding.evidence : [];
  const indicators = indicatorsFrom(report);

  for (const name of Object.keys(SUBJECTS)) {
    const spec = SUBJECTS[name];
    if (!mentionsSubject(text, name)) continue;

    if (indicators[spec.indicator] === false && !isNegated(text)) {
      issues.push({
        type: "CONTRADICTION",
        subject: name,
        detail: "claim asserts " + name + " but core determined " +
                "attackIndicators." + spec.indicator + " = false",
      });
    }

    const relevant = evidence.filter((e) =>
      spec.validEvidence.some((v) =>
        e === v || e.indexOf(v + ".") === 0 || v.indexOf(e + ".") === 0));
    if (evidence.length > 0 && relevant.length === 0) {
      issues.push({
        type: "IRRELEVANT_EVIDENCE",
        subject: name,
        detail: "claim is about " + name +
                "; no cited field relates to it (cited: " +
                evidence.join(", ") + ")",
      });
    }
  }

  for (const e of evidence) {
    if (!resolveLiteral(report, e).found) {
      issues.push({
        type: "UNRESOLVED_PATH",
        detail: "cited path does not exist by literal lookup: " + e,
      });
    }
  }

  return issues;
}

function validateInsight(insight, report) {
  const findings = (insight && Array.isArray(insight.top_findings))
    ? insight.top_findings : [];

  const perFinding = findings.map((f, i) => ({
    index: i,
    finding: f.finding,
    evidence: f.evidence,
    issues: validateFinding(f, report),
  }));

  const all = perFinding.reduce((a, f) => a.concat(f.issues), []);
  const counts = all.reduce((acc, x) => {
    acc[x.type] = (acc[x.type] || 0) + 1;
    return acc;
  }, {});

  return {
    checkedAt: new Date().toISOString(),
    findingsChecked: findings.length,
    findingsWithIssues: perFinding.filter((f) => f.issues.length > 0).length,
    issueCounts: counts,
    clean: all.length === 0,
    perFinding,
    note: "Keyword matching against a hand-declared subject map. A clean " +
          "result means no contradiction was detected, not that the claims " +
          "are correct.",
  };
}

module.exports = { validateInsight, validateFinding, SUBJECTS };
