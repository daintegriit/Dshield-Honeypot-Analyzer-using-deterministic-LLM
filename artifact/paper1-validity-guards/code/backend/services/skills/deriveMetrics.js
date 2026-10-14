// backend/services/skills/deriveMetrics.js
function toMs(ts) {
  const t = new Date(ts).getTime();
  return Number.isFinite(t) ? t : 0;
}

function deriveMetrics({ logs = [], summary = {}, severity = [], trends = [] }) {
  const now = Date.now();
  const windowMs = 5 * 60 * 1000;
  const since = now - windowMs;

  const recentLogs = logs.filter((l) => toMs(l.timestamp) >= since);
  const attackRate5m = recentLogs.length;

  // Top live IP / Port
  const ipCounts = {};
  const portCounts = {};

  for (const log of recentLogs) {
    if (log?.source_ip) ipCounts[log.source_ip] = (ipCounts[log.source_ip] || 0) + 1;
    if (log?.target_port) portCounts[log.target_port] = (portCounts[log.target_port] || 0) + 1;
  }

  const topLiveIP =
    Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;

  const topLivePort =
    Object.entries(portCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || null;

  const topIP = topLiveIP || summary?.topIP?._id || "N/A";
  const topPort = topLivePort || summary?.topPort?._id || "N/A";

  // Trend series (safe fallback)
  const trendSeries =
    Array.isArray(trends) && trends.length
      ? trends.map((t) => Number(t.count || 0)).slice(-24)
      : [];

  const lastTrend = trendSeries[trendSeries.length - 1] ?? 0;
  const prevTrend = trendSeries[trendSeries.length - 2] ?? 0;

  // Severity (critical count)
  const criticalCount =
    severity.find((s) => s?.severity === "critical")?.count || 0;

  return {
    window: "5m",
    attackRate5m,
    topIP,
    topPort,
    criticalCount,
    trendSeries: trendSeries.length ? trendSeries : [prevTrend, lastTrend, attackRate5m],
  };
}

module.exports = { deriveMetrics };