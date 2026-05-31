import React, {
  useEffect,
  useState,
  useRef,
  useMemo,
} from "react";

import {
  FaShieldAlt,
  FaSkullCrossbones,
  FaNetworkWired,
  FaBug,
  FaRobot,
  FaExclamationTriangle,
  FaTerminal,
  FaBrain,
  FaFingerprint,
} from "react-icons/fa";

import {
  Sparklines,
  SparklinesLine,
} from "react-sparklines";

import apiService from "../services/apiService";

// ======================================================
// CONFIG
// ======================================================

const REFRESH_MS = 3000;

// ======================================================
// HELPERS
// ======================================================

const severityConfig = {
  stable: {
    label: "STABLE",
    icon: <FaShieldAlt />,
    border:
      "border-green-500 shadow-[0_0_12px_rgba(34,197,94,0.25)]",
    badge:
      "bg-green-500/10 text-green-400 border border-green-500/30",
  },

  elevated: {
    label: "ELEVATED",
    icon: <FaExclamationTriangle />,
    border:
      "border-yellow-500 shadow-[0_0_12px_rgba(250,204,21,0.25)]",
    badge:
      "bg-yellow-500/10 text-yellow-300 border border-yellow-500/30",
  },

  high: {
    label: "HIGH",
    icon: <FaBug />,
    border:
      "border-orange-500 shadow-[0_0_12px_rgba(249,115,22,0.25)]",
    badge:
      "bg-orange-500/10 text-orange-300 border border-orange-500/30",
  },

  critical: {
    label: "CRITICAL",
    icon: <FaSkullCrossbones />,
    border:
      "border-red-500 shadow-[0_0_14px_rgba(239,68,68,0.35)]",
    badge:
      "bg-red-500/10 text-red-400 border border-red-500/30",
  },
};

const safeArray = (v) =>
  Array.isArray(v) ? v : [];

// ======================================================
// COMPONENT
// ======================================================

const CopilotPanel = () => {
  const [summary, setSummary] =
    useState(null);

  const [logs, setLogs] =
    useState([]);

  const [trends, setTrends] =
    useState([]);

  const [conversation, setConversation] =
    useState([]);

  const [question, setQuestion] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const [error, setError] =
    useState(null);

  const [lastUpdate, setLastUpdate] =
    useState(Date.now());

  const mountedRef = useRef(true);

  // ======================================================
  // LIVE FETCH ENGINE
  // ======================================================

  useEffect(() => {
    mountedRef.current = true;

    const loadIntel = async () => {
      try {
        const [
          summaryRes,
          logsRes,
          trendsRes,
        ] = await Promise.allSettled([
          apiService.getThreatSummary(),
          apiService.getRecentLogs(),
          apiService.getAttackTrends(60),
        ]);

        if (!mountedRef.current) return;

        if (
          summaryRes.status === "fulfilled"
        ) {
          setSummary(summaryRes.value || {});
        }

        if (
          logsRes.status === "fulfilled"
        ) {
          setLogs(
            safeArray(logsRes.value)
          );
        }

        if (
          trendsRes.status === "fulfilled"
        ) {
          setTrends(
            safeArray(trendsRes.value)
          );
        }

        setLastUpdate(Date.now());
      } catch (err) {
        console.error(
          "Copilot Intel Error:",
          err
        );
      }
    };

    loadIntel();

    const interval = setInterval(
      loadIntel,
      REFRESH_MS
    );

    return () => {
      mountedRef.current = false;
      clearInterval(interval);
    };
  }, []);

  // ======================================================
  // ANALYTICS ENGINE
  // ======================================================

  const analytics = useMemo(() => {
    const core = summary?.coreSummary || {};
    const reasoning = core?.reasoning || {};

    const topIP =
      core?.scanningIndicators?.topSourceIp?.ip ||
      summary?.topIP?._id ||
      "N/A";

    const attackTrend = trends
      .map((t) => Number(t.count || 0))
      .slice(-20);

    const dominantAttack =
      reasoning?.dominantAttackType ||
      core?.attackClassification?.dominantAttack?.type ||
      "unknown";

    const riskScore =
      Number(core?.riskScore0to100 ?? 0);

    const severity =
      core?.state?.toLowerCase?.() ||
      "stable";

    const attackDetected =
      reasoning?.attackDetected === true;

    const attackConfidence =
      reasoning?.attackConfidence ||
      "unknown";

    const analystSummary =
      reasoning?.analystSummary ||
      "No active intelligence summary available.";

    return {
      topIP,

      attackTrend,

      recentAttackRate:
        Number(
          core?.attackMetrics?.attacksLast5Min ||
          summary?.recentAttackRate ||
          0
        ),

      threatScore:
        Number(riskScore || 0),

      severity:
        String(severity || "stable"),

      dominantAttack:
        String(dominantAttack || "unknown"),

      attackDetected:
        Boolean(attackDetected),

      analystSummary,

      attackConfidence,
    };
  }, [trends, summary]);

  // ======================================================
  // INSIGHTS
  // ======================================================

  const insights = useMemo(() => {
    const list = [];

    if (analytics.attackDetected) {
      list.push({
        icon: (
          <FaExclamationTriangle />
        ),
        text:
          "Deterministic malicious activity detected.",
      });
    } else {
      list.push({
        icon: <FaShieldAlt />,
        text:
          "Telemetry stable within expected thresholds.",
      });
    }

    if (
      analytics.dominantAttack &&
      analytics.dominantAttack !==
        "unknown"
    ) {
      list.push({
        icon: <FaFingerprint />,
        text: `Dominant attack classification: ${analytics.dominantAttack}`,
      });
    }

    return list.slice(0, 2);
  }, [analytics]);

  // ======================================================
  // COPILOT ASK
  // ======================================================

  const askCopilot = async () => {
    if (!question.trim()) return;

    const currentQuestion =
      question;

    setConversation((c) => [
      ...c,
      {
        role: "user",
        content: currentQuestion,
      },
    ]);

    setQuestion("");

    try {
      setLoading(true);
      setError(null);

      const response = await fetch(
        `${process.env.REACT_APP_API_BASE_URL}/api/copilot/ask`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",
          },

          body: JSON.stringify({
            question:
              currentQuestion,
            templateId:
              "ATTACK_INTENT",
          }),
        }
      );

      const data =
        await response.json();

      setConversation((c) => [
        ...c,
        {
          role: "assistant",
          content:
            data?.answer ||
            "No intelligence response available.",
        },
      ]);
    } catch (err) {
      console.error(err);

      setError(
        "Copilot inference failed."
      );
    } finally {
      setLoading(false);
    }
  };

  // ======================================================
  // LOADING
  // ======================================================

  if (!summary) {
    return (
      <div className="h-full bg-gray-900 rounded-lg flex items-center justify-center text-gray-400 text-xs">
        <div className="animate-pulse flex items-center gap-2">
          <FaRobot />
          Loading intelligence...
        </div>
      </div>
    );
  }

  const severityData =
    severityConfig[
      analytics.severity
    ] ||
    severityConfig.stable;

  const secondsAgo = Math.floor(
    (Date.now() - lastUpdate) /
      1000
  );

  // ======================================================
  // UI
  // ======================================================

  return (
    <div
      className={`
        h-full flex flex-col
        bg-gray-900
        rounded-lg
        border
        overflow-hidden
        ${severityData.border}
      `}
    >
      {/* HEADER */}

      <div className="border-b border-gray-800 px-3 py-2 bg-black/30">

        <div className="flex items-center justify-between">

          <div className="flex items-center gap-2">

            <FaBrain className="text-cyan-400 text-sm" />

            <div>
              <div className="text-xs font-bold text-white">
                Threat Intelligence
              </div>

              <div className="text-[9px] text-gray-500">
                Deterministic real-time threat analysis
              </div>
            </div>
          </div>

          <div
            className={`
              px-2 py-[2px]
              rounded-md
              text-[9px]
              flex items-center gap-1
              font-semibold tracking-wide
              ${severityData.badge}
            `}
          >
            {severityData.icon}
            {severityData.label}
          </div>
        </div>
      </div>

      {/* METRICS */}

      <div className="grid grid-cols-4 gap-1 p-2">

        <MetricCard
          icon={<FaNetworkWired />}
          label="Attacker"
          value={analytics.topIP}
        />

        <MetricCard
          icon={<FaBug />}
          label="Attack"
          value={
            analytics.dominantAttack
              ?.toUpperCase?.() || "UNKNOWN"
          }
          danger={
            analytics.attackDetected
          }
        />

        <MetricCard
          icon={<FaTerminal />}
          label="Rate"
          value={`${analytics.recentAttackRate}/5m`}
        />

        <MetricCard
          icon={<FaShieldAlt />}
          label="Score"
          value={`${analytics.threatScore}/100`}
          danger={
            analytics.threatScore >= 70
          }
        />
      </div>

      {/* TREND */}

      <div className="px-2 pb-2">

        <div className="bg-black rounded-lg border border-gray-800 p-1 h-[70px]">

          <div className="flex items-center justify-between mb-1">

            <span className="text-[9px] text-gray-500">
              Threat Acceleration
            </span>

            <span className="text-[9px] text-gray-500">
              {secondsAgo}s ago
            </span>
          </div>

          <div className="h-[40px] overflow-hidden rounded">

            <Sparklines
              data={
                analytics.attackTrend
              }
            >
              <SparklinesLine
                color="#00ff88"
              />
            </Sparklines>
          </div>
        </div>
      </div>

      {/* INSIGHTS */}

      <div className="px-2 pb-2">

        <div className="bg-black rounded-lg border border-gray-800 p-2 space-y-1">

          {insights.map(
            (item, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2 text-[10px] text-gray-300"
              >
                <div className="mt-[1px] text-cyan-400">
                  {item.icon}
                </div>

                <div>{item.text}</div>
              </div>
            )
          )}
        </div>
      </div>

      {/* CHAT */}

      <div className="flex-1 min-h-0 flex flex-col px-2 pb-2">

        <div className="h-[110px] overflow-y-auto bg-black rounded-lg border border-gray-800 p-2 space-y-2">

          {conversation.length ===
            0 && (
            <div className="text-[10px] text-gray-500">
              Ask about attack
              behavior, ports,
              scans, anomalies,
              replay telemetry,
              or threat reasoning.
            </div>
          )}

          {conversation.map(
            (m, idx) => (
              <div
                key={idx}
                className={`text-[10px] ${
                  m.role ===
                  "assistant"
                    ? "text-cyan-300"
                    : "text-green-400"
                }`}
              >
                <span className="font-bold">
                  {m.role ===
                  "assistant"
                    ? "COPILOT"
                    : "USER"}
                  :
                </span>{" "}
                {m.content}
              </div>
            )
          )}

          {loading && (
            <div className="text-[10px] text-yellow-400 animate-pulse">
              Processing...
            </div>
          )}

          {error && (
            <div className="text-[10px] text-red-400">
              {error}
            </div>
          )}
        </div>

        {/* INPUT */}

        <div className="mt-2 flex gap-1">

          <input
            value={question}
            onChange={(e) =>
              setQuestion(
                e.target.value
              )
            }
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                askCopilot();
              }
            }}
            placeholder="Ask copilot..."
            className="
              flex-1
              bg-black
              border border-gray-700
              rounded-md
              px-2 py-1
              text-[10px] text-white
              outline-none
              focus:border-cyan-500
            "
          />

          <button
            onClick={askCopilot}
            disabled={loading}
            className="
              bg-green-600 hover:bg-green-500
              px-2 py-1
              rounded-md
              text-[10px]
              font-semibold
              transition
              disabled:opacity-50
            "
          >
            Ask
          </button>
        </div>
      </div>
    </div>
  );
};

// ======================================================
// METRIC CARD
// ======================================================

const MetricCard = ({
  icon,
  label,
  value,
  danger,
}) => (
  <div
    className={`
      rounded-lg
      border
      p-1.5
      bg-black
      ${
        danger
          ? "border-red-500/40"
          : "border-gray-800"
      }
    `}
  >
    <div className="flex items-center gap-1 text-[9px] text-gray-400 mb-1">
      {icon}
      {label}
    </div>

    <div
      className={`
        text-[10px]
        font-bold
        truncate
        ${
          danger
            ? "text-red-400"
            : "text-white"
        }
      `}
    >
      {value}
    </div>
  </div>
);

export default CopilotPanel;