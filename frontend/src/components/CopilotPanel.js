import React, { useEffect, useState, useRef } from "react";
import axios from "axios";
import { Sparklines, SparklinesLine } from "react-sparklines";

const CopilotPanel = () => {
  const [summary, setSummary] = useState(null);

  // Core telemetry
  const [logs, setLogs] = useState([]);
  const [trends, setTrends] = useState([]);

  const [lastUpdate, setLastUpdate] = useState(Date.now());

  // Copilot chat
  const [conversation, setConversation] = useState([]);
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [copilotError, setCopilotError] = useState(null);
  const [question, setQuestion] = useState("");

  // UI helpers
  const [copied, setCopied] = useState(false);
  const [insightsExpanded, setInsightsExpanded] = useState(false);

  // --------------------------------
  // Fetch Intel
  // --------------------------------
  useEffect(() => {
    const loadIntel = async () => {
      try {
        const [
          summaryRes,
          logsRes,
          trendRes,
        ] = await Promise.all([
          axios.get("/api/charts/threat-summary"),
          axios.get("/api/charts/recent-logs"),
          axios.get("/api/charts/attack-trends"),
        ]);

        setSummary(summaryRes.data);
        setLogs(logsRes.data || []);
        setTrends(trendRes.data || []);
        setLastUpdate(Date.now());
      } catch (err) {
        console.error("Copilot Intel Error:", err);
      }
    };

    loadIntel();
    const interval = setInterval(loadIntel, 5000);
    return () => clearInterval(interval);
  }, []);

  // --------------------------------
  // Loading
  // --------------------------------
  if (!summary) {
    return (
      <div className="bg-gray-900 text-white p-4 rounded-lg">
        <p className="animate-pulse">Loading Copilot Intelligence…</p>
      </div>
    );
  }

  // --------------------------------
  // Real-time analytics
  // --------------------------------
  const now = Date.now();
  const fiveMinutesAgo = now - 5 * 60 * 1000;

  const recentAttackRate = logs.filter(
    (l) => new Date(l.timestamp).getTime() >= fiveMinutesAgo
  ).length;

  const ipCounts = {};
  const portCounts = {};

  logs.forEach((l) => {
    if (l.source_ip)
      ipCounts[l.source_ip] = (ipCounts[l.source_ip] || 0) + 1;
    if (l.target_port)
      portCounts[l.target_port] = (portCounts[l.target_port] || 0) + 1;
  });

  const topIP =
    Object.entries(ipCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "N/A";

  const topPort =
    Object.entries(portCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || "N/A";

  const attackTrend =
    trends.length > 0
      ? trends.map((t) => t.count).slice(-12)
      : [5, 8, 10, 12, recentAttackRate];

  const asnOrg = summary.topASN?.org || "Unknown";
  const asnCount = summary.topASN?.count || 0;

  const threatScore = Math.min(
    100,
    Math.floor(
      recentAttackRate / 2 +
        asnCount / 150 +
        (["Google LLC", "Akamai", "OVH", "Hetzner", "DigitalOcean"].includes(asnOrg)
          ? 20
          : 0)
    )
  );

  let threatBadge = "🟢 Stable";
  if (threatScore >= 90) threatBadge = "🔴 Critical";
  else if (threatScore >= 70) threatBadge = "🟠 High";
  else if (threatScore >= 40) threatBadge = "🟡 Elevated";

  const riskGlow =
    threatScore >= 90
      ? "border-red-500 shadow-[0_0_18px_#ff4444]"
      : threatScore >= 70
      ? "border-orange-500 shadow-[0_0_18px_#ff8800]"
      : threatScore >= 40
      ? "border-yellow-500 shadow-[0_0_18px_#ffee00]"
      : "border-green-500 shadow-[0_0_18px_#00ff88]";

  const secondsAgo = Math.floor((Date.now() - lastUpdate) / 1000);

  // --------------------------------
  // Rule-based Insights (deterministic)
  // --------------------------------
  const insights = [];

  if (recentAttackRate > 200)
    insights.push("🚨 Extremely high attack volume detected in the last 5 minutes.");
  else if (recentAttackRate > 50)
    insights.push("⚠️ Noticeable surge in attack traffic detected.");
  else insights.push("✅ Attack activity currently stable.");

  if ([22, 23, 445, 3389].includes(parseInt(topPort))) {
    insights.push(
      `🔍 Critical service port ${topPort} is the primary target — likely brute-force or exploit scanning.`
    );
  }

  if (asnOrg !== "Unknown") {
    insights.push(`🌐 Majority of traffic originates from ASN: ${asnOrg}.`);
  }

  insights.push(`🎯 Top attacking IP observed: ${topIP}`);

  // --------------------------------
  // Ask Copilot
  // --------------------------------
  const askCopilot = async () => {
    if (!question.trim()) return;

    setConversation((c) => [
      ...c,
      { role: "user", content: question, ts: Date.now() },
    ]);
    setQuestion("");

    try {
      setCopilotLoading(true);
      setCopilotError(null);

      const res = await axios.post("/api/copilot/ask", { question, templateId: "ATTACK_INTENT" });

      setConversation((c) => [
        ...c,
        {
          role: "assistant",
          headline: "Copilot Response",
          content: res.data?.answer || "No response generated.",
          ts: Date.now(),
        },
      ]);
    } catch {
      setCopilotError("Copilot failed to answer the question");
    } finally {
      setCopilotLoading(false);
    }
  };

  // --------------------------------
  // Render
  // --------------------------------
  return (
    <div
      className={`h-full flex flex-col bg-gradient-to-b from-gray-800 to-black text-white p-6 rounded-lg border ${riskGlow} overflow-hidden`}
    >
      {/* Header */}
      <div className="flex items-center justify-between mb-4 shrink-0">
        <span className="px-3 py-1 rounded-full bg-gray-900 border border-green-600 text-sm">
          {threatBadge}
        </span>

        <p className="text-xs text-gray-400">
          Updated {secondsAgo}s ago
        </p>
      </div>

      {/* Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-5 shrink-0">
        <div className="bg-gray-900 p-4 rounded border border-gray-700">
          <div className="flex justify-between items-center">
            <p className="text-green-300 text-sm">Top Attacker IP</p>
            <button
              onClick={() => {
                navigator.clipboard.writeText(topIP);
                setCopied(true);
                setTimeout(() => setCopied(false), 1200);
              }}
              className="text-xs text-gray-400 hover:text-green-400"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <p className="text-xl font-bold">{topIP}</p>
        </div>

        <div className="bg-gray-900 p-4 rounded border border-gray-700">
          <p className="text-green-300 text-sm">Most Targeted Port</p>
          <p className="text-xl font-bold">{topPort}</p>
        </div>

        <div className="bg-gray-900 p-4 rounded border border-gray-700">
          <p className="text-green-300 text-sm">Live Attack Rate</p>
          <p className="text-xl font-bold">{recentAttackRate}/5 min</p>
          <Sparklines data={attackTrend} height={28}>
            <SparklinesLine color="#00ff88" />
          </Sparklines>
        </div>

        <div className="bg-gray-900 p-4 rounded border border-gray-700 text-center">
          <p className="text-red-400 font-bold">
            Threat Score: {threatScore}/100
          </p>
        </div>
      </div>

      {/* Rule-based Insights */}
      <div className="bg-black p-4 rounded border border-green-600 mb-4 shrink-0">
        <h3 className="text-green-300 font-bold mb-2">
          📌 Copilot Insights (Rule-Based)
        </h3>

        <div className="space-y-1">
          {insights.map((line, idx) => (
            <p
              key={idx}
              className="text-gray-300 text-sm leading-snug"
            >
              {line}
            </p>
          ))}
        </div>
      </div>

      {/* Copilot Chat */}
      <div className="flex flex-col flex-1 min-h-0 bg-black p-5 rounded border border-green-600 overflow-hidden">
        <h3 className="text-green-300 font-bold mb-3 shrink-0">
          Copilot Assessment
        </h3>

        <div className="flex-1 overflow-y-auto space-y-4 pr-2">
          {conversation.map((m, i) => (
            <div
              key={i}
              className={`p-3 rounded ${
                m.role === "user"
                  ? "bg-gray-900 border border-gray-700"
                  : "bg-black border border-green-500"
              }`}
            >
              {m.role === "assistant" && (
                <p className="text-green-300 font-semibold mb-1">
                  {m.headline || "Copilot Response"}
                </p>
              )}
              <p className="text-sm text-gray-300 whitespace-pre-wrap">
                {m.content}
              </p>
            </div>
          ))}
        </div>

        {copilotLoading && (
          <p className="text-gray-400 animate-pulse mt-2">
            Generating analyst-grade response…
          </p>
        )}

        {copilotError && (
          <p className="text-red-400 mt-2">{copilotError}</p>
        )}

        <div className="mt-4 flex gap-2 shrink-0">
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="Why is port 22 being targeted?"
            className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-white"
          />
          <button
            onClick={askCopilot}
            className="bg-green-600 hover:bg-green-500 px-4 py-2 rounded font-semibold"
          >
            Ask
          </button>
        </div>
      </div>
    </div>
  );
};

export default CopilotPanel;