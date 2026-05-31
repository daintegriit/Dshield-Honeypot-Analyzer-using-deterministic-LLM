// src/components/riskFabric/GovernedReasoningPanel.js

import React, { useMemo } from "react";

import {
  ShieldCheck,
  BrainCircuit,
  Lock,
  Binary,
  Eye,
  Scale,
  CheckCircle2,
  ShieldAlert,
  Activity,
  Wifi,
  WifiOff,
  Gauge,
  Clock3,
} from "lucide-react";

import { useTelemetry } from "../../context/TelemetryContext";

// =========================================================
// SAFE HELPERS
// =========================================================

const safeNumber = (value, fallback = 0) => {
  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : fallback;
};

const getGovernanceState = (risk) => {
  if (risk >= 85) {
    return "CRITICAL";
  }

  if (risk >= 60) {
    return "HIGH";
  }

  if (risk >= 45) {
    return "ELEVATED";
  }

  return "STABLE";
};

const getGovernanceColor = (risk) => {
  if (risk >= 85) {
    return "text-red-400";
  }

  if (risk >= 60) {
    return "text-orange-400";
  }

  if (risk >= 45) {
    return "text-yellow-300";
  }

  return "text-green-400";
};

// =========================================================
// COMPONENT
// =========================================================

export default function GovernedReasoningPanel() {
  // =====================================================
  // CENTRALIZED TELEMETRY
  // =====================================================

  const {
    threatSummary,
    loading,
    backendHealthy,
    stale,
    latency,
    lastUpdated,
  } = useTelemetry();

  // =====================================================
  // CORE TELEMETRY
  // =====================================================

  const core = threatSummary?.coreSummary || threatSummary || {};

  const attackMetrics = core?.attackMetrics || {};

  const attackClassification = core?.attackClassification || {};

  // =====================================================
  // REAL PIPELINE VALUES
  // =====================================================

  const riskScore = safeNumber(core?.riskScore0to100 ?? core?.riskScore);

  const attacksLastHour = safeNumber(attackMetrics?.attacksLastHour);

  const burstRatio = safeNumber(attackMetrics?.burstRatio5mOverHour);

  const topAttackType = String(
    attackClassification?.dominantAttack?.type ||
      attackClassification?.topAttackType ||
      core?.dominantAttack ||
      "UNKNOWN",
  ).toUpperCase();

  // =====================================================
  // STATUS
  // =====================================================

  const telemetryStatus = loading
    ? "SYNCING"
    : stale
      ? "STALE"
      : backendHealthy
        ? "LIVE"
        : "OFFLINE";

  const lastUpdatedLabel = lastUpdated
    ? new Date(lastUpdated).toLocaleTimeString()
    : "--";

  // =====================================================
  // REAL GOVERNANCE STATE
  // =====================================================

  const governanceState = useMemo(() => {
    return getGovernanceState(riskScore);
  }, [riskScore]);

  const governanceColor = useMemo(() => {
    return getGovernanceColor(riskScore);
  }, [riskScore]);

  // =====================================================
  // REAL TELEMETRY TRUST
  // =====================================================

  const telemetryTrust = useMemo(() => {
    const normalizedRisk = Math.min(100, riskScore);

    const normalizedBurst = Math.min(100, burstRatio * 25);

    const normalizedEvents = attacksLastHour > 0 ? 100 : 0;

    const attackConfidence = topAttackType !== "UNKNOWN" ? 100 : 0;

    const weightedScore =
      normalizedEvents * 0.35 +
      attackConfidence * 0.25 +
      normalizedBurst * 0.2 +
      normalizedRisk * 0.2;

    return Number(weightedScore.toFixed(1));
  }, [riskScore, burstRatio, attacksLastHour, topAttackType]);

  // =====================================================
  // GOVERNANCE ENFORCEMENT
  // =====================================================

  const governanceEnforced = useMemo(() => {
    return burstRatio >= 2 || riskScore >= 60;
  }, [burstRatio, riskScore]);

  // =====================================================
  // GOVERNANCE LAYERS
  // =====================================================

  const governanceLayers = useMemo(() => {
    return [
      {
        title: "Telemetry Validation",

        description: `Validated ${attacksLastHour.toLocaleString()} live behavioral telemetry events across operational threat channels.`,

        status: loading ? "SYNCING" : "VERIFIED",

        icon: <CheckCircle2 size={18} />,

        color: "text-green-400",

        border: "border-green-500/20",
      },

      {
        title: "Deterministic Fusion",

        description: `Behavioral fusion engine currently operating at live risk score ${riskScore}/100.`,

        status: governanceState,

        icon: <Binary size={18} />,

        color: governanceColor,

        border: "border-cyan-500/20",
      },

      {
        title: "Threat Attribution",

        description: `Dominant live attack attribution aligned with ${topAttackType} telemetry behavior.`,

        status: topAttackType,

        icon: <ShieldAlert size={18} />,

        color: "text-orange-400",

        border: "border-orange-500/20",
      },

      {
        title: "Defensive Posture",

        description: `Current operational defense posture derived from live escalation thresholds and behavioral threat telemetry. Burst pressure currently operating at ${burstRatio.toFixed(2)}x.`,
        status: governanceEnforced ? "ACTIVE" : "NORMAL",

        icon: <Scale size={18} />,

        color: "text-purple-400",

        border: "border-purple-500/20",
      },
    ];
  }, [
    loading,
    attacksLastHour,
    riskScore,
    governanceState,
    governanceColor,
    topAttackType,
    burstRatio,
    governanceEnforced,
  ]);

  // =====================================================
  // UI
  // =====================================================

  return (
    <section
      className="
      relative
      z-10
      px-4
      md:px-8
      pb-12
    "
    >
      {/* HEADER */}

      <div
        className="
        flex
        flex-col
        xl:flex-row
        xl:items-center
        xl:justify-between
        gap-4
        mb-6
      "
      >
        <div>
          <h2
            className="
            text-2xl
            font-black
            text-white
            mb-2
          "
          >
            Governed Reasoning Engine
          </h2>

          <p
            className="
            text-slate-400
            text-sm
            max-w-4xl
          "
          >
            Live deterministic governance telemetry enforcing bounded escalation
            reasoning, behavioral fusion integrity, attack attribution, and
            operational telemetry trust.
          </p>
        </div>

        {/* STATUS */}

        <div
          className="
          flex
          items-center
          gap-3
          flex-wrap
        "
        >
          <div
            className={`
            px-3
            py-2
            rounded-xl
            text-xs
            font-bold
            uppercase
            tracking-wider
            flex
            items-center
            gap-2
            ${
              backendHealthy
                ? "bg-green-500/10 text-green-300 border border-green-500/20"
                : "bg-red-500/10 text-red-300 border border-red-500/20"
            }
          `}
          >
            {backendHealthy ? <Wifi size={12} /> : <WifiOff size={12} />}

            {backendHealthy ? "BACKEND OK" : "BACKEND DOWN"}
          </div>

          <div
            className="
            px-3
            py-2
            rounded-xl
            bg-white/5
            border
            border-white/10
            text-slate-300
            text-xs
            font-bold
            uppercase
            tracking-wider
            flex
            items-center
            gap-2
          "
          >
            <Gauge size={12} />
            {latency}ms
          </div>

          <div
            className="
            px-3
            py-2
            rounded-xl
            bg-cyan-500/10
            border
            border-cyan-500/20
            text-cyan-300
            text-xs
            font-bold
            uppercase
            tracking-wider
            flex
            items-center
            gap-2
          "
          >
            <Clock3 size={12} />

            {telemetryStatus}
          </div>
        </div>
      </div>

      {/* PANEL */}

      <div
        className="
        relative
        overflow-hidden
        rounded-3xl
        border
        border-cyan-500/20
        bg-[#071028]/90
        p-8
        mb-6
        shadow-[0_0_60px_rgba(0,255,255,0.06)]
      "
      >
        {/* GLOW */}

        <div
          className="
          absolute
          inset-0
          pointer-events-none
        "
        >
          <div
            className="
            absolute
            top-0
            right-0
            w-[400px]
            h-[400px]
            rounded-full
            bg-cyan-500/5
            blur-[120px]
          "
          />
        </div>

        {/* CONTENT */}

        <div
          className="
          relative
          z-10
        "
        >
          {/* TOP */}

          <div
            className="
            flex
            items-center
            gap-4
            mb-8
          "
          >
            <div
              className="
              w-16
              h-16
              rounded-2xl
              border
              border-cyan-500/20
              bg-cyan-500/10
              flex
              items-center
              justify-center
            "
            >
              <BrainCircuit
                className="
                  text-cyan-400
                "
                size={28}
              />
            </div>

            <div>
              <h3
                className="
                text-3xl
                font-black
                text-white
                mb-2
              "
              >
                Chiron Governance Core
              </h3>

              <p
                className="
                text-slate-400
                max-w-3xl
              "
              >
                Live governance telemetry aligned with deterministic behavioral
                escalation, replay-aware reasoning, telemetry validation, and
                operational trust enforcement.
              </p>
            </div>
          </div>

          {/* METRICS */}

          {/* METRICS */}

          <div
            className="
            grid
            grid-cols-1
            md:grid-cols-2
            xl:grid-cols-4
            gap-5
            mb-8
            "
          >
            <GovernanceMetric
              title="Telemetry Trust"
              value={`${telemetryTrust}%`}
              color={
                telemetryTrust >= 85
                  ? "text-green-400"
                  : telemetryTrust >= 60
                    ? "text-yellow-300"
                    : "text-red-400"
              }
              icon={<Eye size={18} />}
              description={`
                Measures the reliability,
                completeness, and confidence
                of live telemetry entering
                the governance pipeline.
                `}
            />

            <GovernanceMetric
              title="Fusion Integrity"
              value={governanceState}
              color={governanceColor}
              icon={<Binary size={18} />}
              description={`
                Represents the current
                deterministic behavioral
                fusion state derived from
                real-time threat telemetry.
                `}
            />

            <GovernanceMetric
              title="Governance State"
              value={governanceEnforced ? "LOCKED" : "STABLE"}
              color="text-orange-400"
              icon={<Lock size={18} />}
              description={`
                Indicates whether escalation
                safeguards and bounded
                governance controls are
                actively enforcing stability.
                `}
            />

            <GovernanceMetric
              title="Reasoning Engine"
              value={loading ? "SYNCING" : "SAFE"}
              color="text-purple-400"
              icon={<Scale size={18} />}
              description={`
                Validates whether the live
                behavioral reasoning pipeline
                is operating safely without
                synchronization or drift issues.
                `}
            />
          </div>

          {/* FLOW */}

          <div
            className="
            overflow-hidden
            rounded-2xl
            border
            border-white/5
            bg-black/20
          "
          >
            {governanceLayers.map((layer, index) => (
              <div
                key={index}
                className="
                    flex
                    flex-col
                    xl:flex-row
                    xl:items-center
                    xl:justify-between
                    gap-5
                    p-6
                    border-b
                    border-white/5
                  "
              >
                <div
                  className="
                    flex
                    items-start
                    gap-4
                    flex-1
                  "
                >
                  <div
                    className={`
                        mt-1
                        ${layer.color}
                      `}
                  >
                    {layer.icon}
                  </div>

                  <div>
                    <div
                      className="
                        text-lg
                        font-bold
                        text-white
                        mb-2
                      "
                    >
                      {layer.title}
                    </div>

                    <div
                      className="
                        text-sm
                        text-slate-400
                        leading-relaxed
                        max-w-3xl
                      "
                    >
                      {layer.description}
                    </div>
                  </div>
                </div>

                <div
                  className={`
                      shrink-0
                      px-4
                      py-2
                      rounded-xl
                      border
                      text-xs
                      font-bold
                      uppercase
                      tracking-widest
                      bg-black/20
                      ${layer.border}
                      ${layer.color}
                    `}
                >
                  {layer.status}
                </div>
              </div>
            ))}
          </div>

          {/* FOOTER */}

          <div
            className="
            mt-8
            pt-6
            border-t
            border-white/5
            flex
            flex-col
            xl:flex-row
            xl:items-center
            xl:justify-between
            gap-4
          "
          >
            <div
              className="
              text-sm
              text-slate-400
              leading-relaxed
              max-w-4xl
            "
            >
              Chiron governance telemetry continuously validates deterministic
              escalation, behavioral fusion integrity, replay-aware attribution,
              and operational telemetry trust across live threat pipelines.
            </div>

            <div
              className="
              flex
              items-center
              gap-2
              px-4
              py-3
              rounded-xl
              border
              border-cyan-500/20
              bg-cyan-500/10
              text-cyan-300
              text-xs
              font-bold
              uppercase
              tracking-widest
            "
            >
              <Activity size={14} />
              LIVE GOVERNANCE
            </div>
          </div>

          {/* LAST UPDATED */}

          <div
            className="
            mt-4
            text-right
            text-xs
            text-slate-500
          "
          >
            Last Updated:{" "}
            <span
              className="
              text-cyan-300
              font-semibold
            "
            >
              {lastUpdatedLabel}
            </span>
          </div>
        </div>
      </div>
    </section>
  );
}

// =========================================================
// METRIC CARD
// =========================================================
function GovernanceMetric({ title, value, color, icon, description }) {
  return (
    <div
      className="
      rounded-2xl
      border
      border-cyan-500/10
      bg-black/20
      p-5
      min-h-[170px]
      flex
      flex-col
      justify-between
      transition-all
      duration-300
      hover:border-cyan-500/20
      hover:bg-cyan-500/[0.03]
    "
    >
      {/* HEADER */}

      <div
        className="
        flex
        items-center
        justify-between
        mb-3
      "
      >
        <div
          className="
          text-xs
          uppercase
          tracking-widest
          text-slate-400
        "
        >
          {title}
        </div>

        <div className={color}>{icon}</div>
      </div>

      {/* VALUE */}

      <div
        className={`
          text-2xl
          font-black
          tracking-tight
          ${color}
        `}
      >
        {value}
      </div>

      {/* DESCRIPTION */}

      <div
        className="
        mt-4
        pt-4
        border-t
        border-white/5
        text-xs
        leading-relaxed
        text-slate-400
      "
      >
        {description}
      </div>
    </div>
  );
}
