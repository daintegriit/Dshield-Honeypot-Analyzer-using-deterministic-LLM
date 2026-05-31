// backend/services/questionAdmissibility.js
// Deterministic governance gate for analyst questions
// Runs BEFORE any LLM call

const QUESTION_TEMPLATES = require("./skills/questionTemplates");

/* --------------------------------------------------
 * Helpers
 * -------------------------------------------------- */

function normalize(text) {
  return String(text || "").toLowerCase().trim();
}

function hasPath(obj, path) {
  return path.split(".").every((p) => {
    if (obj == null) return false;
    obj = obj[p];
    return obj !== undefined;
  });
}

/* --------------------------------------------------
 * Main admissibility decision
 * -------------------------------------------------- */

function assessQuestionAdmissibility({ summary, templateId, question }) {
  const q = normalize(question);

  /* --------------------------------------------------
   * 0. Template validity
   * -------------------------------------------------- */
  const template = QUESTION_TEMPLATES[templateId];
  if (!template) {
    return {
      allowed: false,
      action: "HARD_REFUSE",
      reason: `Unknown or unsupported question template '${templateId}'`,
    };
  }

  /* --------------------------------------------------
   * 1. Instruction / role override protection
   * (Prompt injection defense)
   * -------------------------------------------------- */
  const ROLE_OVERRIDE_PATTERNS = [
    "ignore all previous",
    "ignore previous instructions",
    "you are now",
    "act as",
    "pretend to be",
    "roleplay",
    "assume the role",
    "forget your rules",
  ];

  if (ROLE_OVERRIDE_PATTERNS.some((p) => q.includes(p))) {
    return {
      allowed: false,
      action: "HARD_REFUSE",
      reason: "Instruction or role override attempts are not permitted",
    };
  }

  /* --------------------------------------------------
   * 2. Domain alignment
   * Is this question even answerable from security telemetry?
   * -------------------------------------------------- */
  const SECURITY_CONCEPTS = [
    "attack",
    "traffic",
    "scan",
    "scanning",
    "port",
    "protocol",
    "ip",
    "source",
    "destination",
    "behavior",
    "activity",
    "telemetry",
    "severity",
    "risk",
    "threat",
    "pattern",
  ];

  const isSecurityDomain = SECURITY_CONCEPTS.some((k) => q.includes(k));

  if (!isSecurityDomain) {
    return {
      allowed: false,
      action: "HARD_REFUSE",
      reason:
        "Question is outside the security telemetry domain and cannot be answered using system state",
    };
  }

  /* --------------------------------------------------
   * 3. Evidence satisfiability
   * Do required fields exist in the summary?
   * -------------------------------------------------- */
  const missingFields = [];

  for (const field of template.requires || []) {
    if (!hasPath(summary, field)) {
      missingFields.push(field);
    }
  }

  if (missingFields.length > 0) {
    return {
      allowed: true,
      constraint: "INSUFFICIENT_EVIDENCE",
      reason: `Required evidence missing: ${missingFields.join(", ")}`,
    };
  }

  /* --------------------------------------------------
   * 4. Authority boundary enforcement
   * LLM may NOT decide or prescribe actions
   * -------------------------------------------------- */
  const AUTHORITY_VIOLATIONS = [
    "block",
    "unblock",
    "mitigate",
    "shut down",
    "remediate",
    "patch",
    "fix",
    "allow",
    "deny",
    "change risk",
    "set risk",
    "override score",
  ];

  if (AUTHORITY_VIOLATIONS.some((k) => q.includes(k))) {
    return {
      allowed: true,
      constraint: "NO_PRESCRIPTIVE_ACTION",
      reason:
        "Question requests operational or decision authority outside Copilot scope",
    };
  }

  /* --------------------------------------------------
   * 5. Attribution & blame control
   * -------------------------------------------------- */
  const ATTRIBUTION_TERMS = [
    "apt",
    "actor",
    "threat actor",
    "country",
    "nation",
    "state-sponsored",
    "malware family",
    "who is behind",
    "responsible for",
  ];

  if (ATTRIBUTION_TERMS.some((k) => q.includes(k))) {
    const hasAttributionEvidence =
      summary?.signals?.iocMatches?.length > 0 ||
      summary?.signals?.malwareSignatures?.length > 0;

    if (!hasAttributionEvidence) {
      return {
        allowed: true,
        constraint: "NO_ATTRIBUTION",
        reason:
          "Attribution requested without sufficient supporting evidence",
      };
    }
  }

  /* --------------------------------------------------
   * 6. Knowledge source integrity
   * -------------------------------------------------- */
  const EXTERNAL_KNOWLEDGE_TERMS = [
    "look up",
    "search",
    "google",
    "news",
    "cve",
    "wikipedia",
    "external",
  ];

  if (EXTERNAL_KNOWLEDGE_TERMS.some((k) => q.includes(k))) {
    return {
      allowed: true,
      constraint: "NO_EXTERNAL_KNOWLEDGE",
      reason:
        "System operates only on ingested telemetry and cached intelligence",
    };
  }

  /* --------------------------------------------------
   * 7. Default: admissible
   * -------------------------------------------------- */
  return {
    allowed: true,
  };
}

module.exports = {
  assessQuestionAdmissibility,
};