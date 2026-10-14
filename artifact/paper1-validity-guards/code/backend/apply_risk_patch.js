const fs = require("fs");
const F = "services/copilotCore.js";
let s = fs.readFileSync(F, "utf8");

function sub(name, oldStr, newStr) {
  const n = s.split(oldStr).length - 1;
  if (n !== 1) {
    console.error(`FAIL [${name}]: anchor matched ${n} times, expected 1. Aborting.`);
    process.exit(1);
  }
  s = s.replace(oldStr, newStr);
  console.log(`ok   [${name}]`);
}

/* ---------- 1. config block ---------- */
sub("config",
`const CORE_VERSION = "copilotCore-v4.3-dos-burst-only";`,
`const CORE_VERSION = "copilotCore-v4.3-dos-burst-only";

/**
 * RISK BUDGET REACHABILITY
 * ---------------------------------------------------------------------------
 * Each risk component has a nominal point budget. A component is REACHABLE in a
 * deployment only if that deployment supplies its inputs. The severity component
 * is driven by events labelled \`critical\`, and severity is assigned by a
 * target-port heuristic (22/23/445/3389) encoding a HONEYPOT assumption --
 * nothing legitimate touches those ports on a honeypot. Replayed NetFlow corpora
 * do not share that assumption: measured 1,062 critical of 257,646 CTU-13 botnet
 * flows (0.41%), so the component is present in code and ~0 in practice.
 *
 * Scoring against the nominal budget in an environment that cannot supply it
 * yields a ceiling below the state thresholds. That is a units mismatch, not a
 * detection failure.
 *
 * DEPLOYMENT CONFIGURATION, like LOCAL_NETWORKS. Declared per environment and
 * held CONSTANT across every window in a run. Never recompute per window: a
 * window with no critical events would get a smaller denominator and therefore
 * an inflated score, inflating benign windows specifically and manufacturing
 * apparent recall.
 *
 * No value here is chosen by looking at detection results.
 */
const RISK_BUDGET = Object.freeze({
  severity: 25,
  behavior: 20,
  entropy: 20,
  concentration: 15,
  amplifier: 25,
  c2: 20,
  impact: 12,
  coupling: 5,
});

const REACHABILITY_PROFILES = Object.freeze({
  honeypot: {
    severity: true,
    behavior: true,
    entropy: true,
    concentration: false, // retired v4.0 -- falsified, rho = -0.42
    amplifier: true,
    c2: true,
    impact: false,        // inputs not wired
    coupling: false,      // inputs not wired
  },
  netflow: {
    severity: false,      // measured 0.41% critical on CTU-13
    behavior: false,      // auth-port pressure absent
    entropy: true,
    concentration: false,
    amplifier: true,
    c2: true,
    impact: false,
    coupling: false,
  },
});

const RISK_PROFILE = process.env.RISK_PROFILE || "honeypot";
const RISK_NORMALISE = process.env.RISK_NORMALISE === "1";`);

/* ---------- 2. risk calculation ---------- */
sub("riskcalc",
`  const riskScore = clamp(
    Math.round(
      severityComponent +`,
`  const riskScoreRaw = clamp(
    Math.round(
      severityComponent +`);

sub("riskcalc-tail",
`      couplingBonus
    ),
    0,
    100
  );

  let state = "stable";`,
`      couplingBonus
    ),
    0,
    100
  );

  // Budget normalisation. Denominator derived from input availability only.
  // honeypot profile sums to 110 -> capped at 100 -> normalised == raw, so
  // existing behaviour and archives are unchanged.
  const reachProfile =
    REACHABILITY_PROFILES[RISK_PROFILE] || REACHABILITY_PROFILES.honeypot;
  const reachableBudget = Object.entries(RISK_BUDGET)
    .filter(([k]) => reachProfile[k])
    .reduce((a, [, v]) => a + v, 0);
  const referenceBudget = Math.min(reachableBudget, 100);
  const riskScoreNormalised =
    referenceBudget > 0
      ? clamp(Math.round((riskScoreRaw / referenceBudget) * 100), 0, 100)
      : 0;

  const riskScore = RISK_NORMALISE ? riskScoreNormalised : riskScoreRaw;

  let state = "stable";`);

/* ---------- 3. surface in return ---------- */
sub("return",
`      couplingBonus,

    },

    // v4.0 rate-independent feature diagnostics (for analysis / auditing)`,
`      couplingBonus,

    },

    // Which fraction of the scoring this deployment can actually exercise.
    // Reported on every window so a zero-recall result is readable as
    // "the corpus could not supply N% of the budget".
    riskBudget: {
      profile: RISK_PROFILE,
      normalised: RISK_NORMALISE,
      nominalBudget: Object.values(RISK_BUDGET).reduce((a, b) => a + b, 0),
      reachableBudget,
      referenceBudget,
      reachable: reachProfile,
      riskScoreRaw,
      riskScoreNormalised,
    },

    // v4.0 rate-independent feature diagnostics (for analysis / auditing)`);

fs.copyFileSync(F, F + ".bak");
fs.writeFileSync(F, s);
console.log("\nwrote " + F + "  (backup: " + F + ".bak)");
