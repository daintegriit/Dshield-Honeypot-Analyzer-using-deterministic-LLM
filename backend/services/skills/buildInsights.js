// backend/services/skills/buildInsights.js
function buildInsights({ metrics, summary, topASN, riskScore }) {
  const insights = [];
  const evidence = [];
  const actions = [];

  const attackRate = metrics.attackRate5m || 0;
  const topPort = metrics.topPort || "N/A";

  evidence.push(`Attack rate: ${attackRate} events / 5 minutes`);
  evidence.push(`Most targeted port: ${topPort}`);
  if (topASN?.asn) evidence.push(`Top ASN: AS${topASN.asn} (${topASN.org || "Unknown"})`);

  if (attackRate >= 80) insights.push("📈 Attack spike detected in the last 5 minutes.");
  if (metrics.criticalCount >= 50) insights.push("💀 Elevated critical severity volume detected.");
  if (String(topPort) === "22") insights.push("🔐 SSH brute-force pattern likely.");
  if (String(topPort) === "3389") insights.push("🖥️ RDP probing pattern likely.");
  if (String(topPort) === "5900") insights.push("🖥️ VNC probing pattern likely.");

  // Actions that look “SOC-ready”
  if (riskScore.risk === "critical" || riskScore.risk === "high") {
    actions.push("Block top attacker IPs at the edge (temporary deny for 15–60 minutes).");
    actions.push("Rate-limit inbound traffic to targeted ports (WAF/firewall thresholds).");
    actions.push("Enable/verify SSH hardening: disable password auth, fail2ban, non-standard port (optional).");
    actions.push("Snapshot and preserve logs for incident review (hash + archive).");
  } else {
    actions.push("Continue monitoring; keep enrichments running (ASN/Geo/IOC).");
    actions.push("Review top ports and add targeted honeypot services to increase attribution fidelity.");
  }

  const headline =
    riskScore.risk === "critical"
      ? "Critical escalation detected in live attack telemetry"
      : riskScore.risk === "high"
      ? "High threat posture — active probing and elevated volumes"
      : riskScore.risk === "elevated"
      ? "Elevated activity — monitor targeted services"
      : "Stable posture — baseline hostile background noise";

  return { headline, insights, evidence, recommended_actions: actions };
}

module.exports = { buildInsights };