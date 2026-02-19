// backend/services/skills/scoreRisk.js
function scoreRisk({ metrics, topASN }) {
  const attackRate = metrics.attackRate5m || 0;
  const critical = metrics.criticalCount || 0;

  const asnOrg = topASN?.org || "";
  const asnCount = Number(topASN?.count || 0);

  let score = 0;
  score += Math.min(50, attackRate / 2);        // 0..50
  score += Math.min(25, critical / 20);         // 0..25
  score += Math.min(15, asnCount / 250);        // 0..15

  const bigProviderBoost = ["Akamai", "OVH", "Hetzner", "DigitalOcean", "Amazon", "Google"].some(
    (p) => asnOrg.includes(p)
  );
  if (bigProviderBoost) score += 10;

  score = Math.max(0, Math.min(100, Math.floor(score)));

  let risk = "low";
  if (score >= 85) risk = "critical";
  else if (score >= 65) risk = "high";
  else if (score >= 35) risk = "elevated";

  // Confidence: higher when signal is strong and consistent
  const confidence = Math.max(
    0.35,
    Math.min(0.95, 0.45 + score / 200)
  );

  return { score, risk, confidence };
}

module.exports = { scoreRisk };