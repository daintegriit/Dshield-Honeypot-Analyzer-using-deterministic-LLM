// src/components/riskFabric/MathematicalProvenance.js

import React, { useMemo, useState } from "react";

import {
  Sigma,
  BrainCircuit,
  ShieldCheck,
  Activity,
  Radar,
  Workflow,
  Binary,
  Database,
  ChevronRight,
  RefreshCw,
  ShieldAlert,
  Wifi,
  WifiOff,
  Gauge,
  Clock3,
} from "lucide-react";

import { useTelemetry } from "../../context/TelemetryContext";


// ======================================================
// SAFE HELPERS
// ======================================================

const safeNumber = (value, fallback = 0) => {
  const parsed = Number(value);

  return Number.isFinite(parsed) ? parsed : fallback;
};

const clamp = (value, min = 0, max = 100) => {
  return Math.min(max, Math.max(min, value));
};

const getStateFromRisk = (risk) => {
  if (risk >= 85) {
    return "critical";
  }

  if (risk >= 60) {
    return "elevated";
  }

  if (risk >= 45) {
    return "active";
  }

  return "validated";
};

// ======================================================
// STATE STYLES
// ======================================================

const stateStyles = {
  validated: {
    border: "border-green-500/20",

    badge: "bg-green-500/10 text-green-300 border border-green-500/20",

    glow: "shadow-[0_0_30px_rgba(34,197,94,0.06)]",
  },

  active: {
    border: "border-cyan-500/20",

    badge: "bg-cyan-500/10 text-cyan-300 border border-cyan-500/20",

    glow: "shadow-[0_0_30px_rgba(0,229,255,0.06)]",
  },

  elevated: {
    border: "border-yellow-500/20",

    badge: "bg-yellow-500/10 text-yellow-300 border border-yellow-500/20",

    glow: "shadow-[0_0_30px_rgba(234,179,8,0.06)]",
  },

  critical: {
    border: "border-red-500/20",

    badge: "bg-red-500/10 text-red-300 border border-red-500/20",

    glow: "shadow-[0_0_40px_rgba(239,68,68,0.08)]",
  },
};

// ======================================================
// COMPONENT
// ======================================================

export default function MathematicalProvenance() {
  // ====================================================
  // CENTRALIZED TELEMETRY
  // ====================================================

  const {
    threatSummary,
    loading,
    backendHealthy,
    stale,
    latency,
    lastUpdated,
  } = useTelemetry();

  // ====================================================
  // COMPONENT PARTICIPATION
  // ====================================================

  const [activeToggles, setActiveToggles] = useState({
    V: true,
    E: true,
    B: true,
    A: true,
    C: true,
    I: true,
    K: true,
  });

  // ====================================================
  // CORE SUMMARY
  // ====================================================

  const core = useMemo(() => {
    return threatSummary?.coreSummary || threatSummary || {};
  }, [threatSummary]);

  const riskComponents = core?.riskComponents || {};

  const attackMetrics = core?.attackMetrics || {};

  const attackClassification = core?.attackClassification || {};

  // ====================================================
  // LIVE COMPONENTS
  // ====================================================

  const liveComponents = useMemo(() => {
    return {
      V: safeNumber(riskComponents?.volumeComponent),

      E: safeNumber(riskComponents?.severityComponent),

      B: safeNumber(riskComponents?.behaviorComponent),

      A: safeNumber(riskComponents?.signalAmplifier),

      C: safeNumber(riskComponents?.c2Bonus),

      I: safeNumber(riskComponents?.impactBonus),

      K: safeNumber(riskComponents?.couplingBonus),
    };
  }, [riskComponents]);

  // ====================================================
  // ACTIVE COMPONENTS
  // ====================================================

  const activeComponents = useMemo(() => {
    return {
      V: activeToggles.V ? liveComponents.V : 0,

      E: activeToggles.E ? liveComponents.E : 0,

      B: activeToggles.B ? liveComponents.B : 0,

      A: activeToggles.A ? liveComponents.A : 0,

      C: activeToggles.C ? liveComponents.C : 0,

      I: activeToggles.I ? liveComponents.I : 0,

      K: activeToggles.K ? liveComponents.K : 0,
    };
  }, [activeToggles, liveComponents]);

  // ====================================================
  // LIVE EQUATION
  // ====================================================

  const calculatedRisk = useMemo(() => {
    const result =
      activeComponents.V +
      activeComponents.E +
      activeComponents.B +
      activeComponents.A +
      activeComponents.C +
      activeComponents.I +
      activeComponents.K;

    return clamp(Number(result.toFixed(2)), 0, 100);
  }, [activeComponents]);

  // ====================================================
  // BACKEND RISK
  // ====================================================

  const backendRisk = safeNumber(core?.riskScore0to100 ?? core?.riskScore);

  // ====================================================
  // DELTA
  // ====================================================

  const delta = Number(Math.abs(calculatedRisk - backendRisk).toFixed(2));

  // ====================================================
  // ATTACK TYPE
  // ====================================================

  const topAttackType = String(
    attackClassification?.dominantAttack?.type ||
      attackClassification?.topAttackType ||
      core?.dominantAttack ||
      "UNKNOWN",
  ).toUpperCase();

  // ====================================================
  // TELEMETRY STATUS
  // ====================================================

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

  // ====================================================
  // EQUATION
  // ====================================================

  const fusionEquation = `R = V + E + B + A + C + I + K

V = volume amplification
E = severity escalation
B = behavioral pressure
A = signal amplification
C = command-and-control escalation
I = impact escalation
K = behavioral coupling`;

  // ====================================================
  // PROVENANCE NODES
  // ====================================================

  const provenanceNodes = useMemo(() => {
    return [
      {
        title: "Telemetry Ingestion",

        icon: <Database size={18} className="text-cyan-400" />,

        description: `Live telemetry window: ${safeNumber(
          attackMetrics?.attacksLast5Min,
        ).toLocaleString()} events in 5m, ${safeNumber(
          attackMetrics?.attacksLastHour,
        ).toLocaleString()} events in 1h.`,

        state: backendHealthy ? "validated" : "critical",
      },

      {
        title: "Volume Amplification",

        icon: <Activity size={18} className="text-orange-400" />,

        description: `V = ${activeComponents.V}. Driven by live event volume and burst escalation.`,

        state: getStateFromRisk(activeComponents.V),
      },

      {
        title: "Severity Escalation",

        icon: <ShieldAlert size={18} className="text-red-400" />,

        description: `E = ${activeComponents.E}. Derived from live critical severity accumulation.`,

        state: getStateFromRisk(activeComponents.E),
      },

      {
        title: "Behavioral Pressure",

        icon: <Radar size={18} className="text-yellow-300" />,

        description: `B = ${activeComponents.B}. Driven by live authentication and service targeting pressure.`,

        state: getStateFromRisk(activeComponents.B),
      },

      {
        title: "Signal Amplification",

        icon: <Binary size={18} className="text-purple-400" />,

        description: `A = ${activeComponents.A}. Driven by strongest live attack classification agreement.`,

        state: getStateFromRisk(activeComponents.A * 4),
      },

      {
        title: "C2 Escalation",

        icon: <BrainCircuit size={18} className="text-cyan-300" />,

        description: `C = ${activeComponents.C}. Derived from live command-and-control behavioral indicators.`,

        state: getStateFromRisk(activeComponents.C * 4),
      },

      {
        title: "Impact Escalation",

        icon: <ShieldCheck size={18} className="text-green-400" />,

        description: `I = ${activeComponents.I}. Derived from cumulative live severity impact.`,

        state: getStateFromRisk(activeComponents.I * 10),
      },

      {
        title: "Behavioral Coupling",

        icon: <Sigma size={18} className="text-cyan-300" />,

        description: `K = ${activeComponents.K}. Triggered when volume and behavioral pressure escalate together.`,

        state: activeComponents.K > 0 ? "active" : "validated",
      },

      {
        title: "Final Risk Fusion",

        icon: <Workflow size={18} className="text-red-400" />,

        description: `R = ${calculatedRisk}/100. Backend reported ${backendRisk}/100. Delta = ${delta}. Dominant attack: ${topAttackType}.`,

        state: getStateFromRisk(calculatedRisk),
      },
    ];
  }, [
    attackMetrics,
    activeComponents,
    calculatedRisk,
    backendHealthy,
    backendRisk,
    delta,
    topAttackType,
  ]);

  // ====================================================
  // RESET
  // ====================================================

  const resetToggles = () => {
    setActiveToggles({
      V: true,
      E: true,
      B: true,
      A: true,
      C: true,
      I: true,
      K: true,
    });
  };

  // ====================================================
  // UI
  // ====================================================

  return (
    <section
      className="
      relative
      z-10
      px-4
      md:px-8
      pb-20
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
        mb-8
      "
      >
        <div>
          <div
            className="
            flex
            items-center
            gap-3
            mb-3
          "
          >
            <Workflow className="text-cyan-400" size={26} />

            <h2
              className="
              text-3xl
              font-black
              text-white
            "
            >
              Mathematical Provenance
            </h2>
          </div>

          <p
            className="
            text-slate-400
            max-w-4xl
            text-sm
            leading-relaxed
          "
          >
            Fully synchronized with the centralized Chiron telemetry engine and
            Master Risk Fabric.
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

            {loading ? "SYNCING" : stale ? "STALE" : telemetryStatus}
          </div>

          <div
            className="
            flex
            items-center
            gap-2
            px-4
            py-2
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
            <Workflow size={14} />
            Deterministic Mode
          </div>

          <button
            onClick={resetToggles}
            className="
              flex
              items-center
              gap-2
              px-4
              py-2
              rounded-xl
              border
              border-white/10
              bg-black/20
              text-slate-300
              text-xs
              font-bold
              uppercase
              tracking-widest
            "
          >
            <RefreshCw size={14} />
            Reset
          </button>
        </div>
      </div>

      {/* EQUATION BLOCK */}

      <div
        className="
    mb-8
    rounded-2xl
    border
    border-cyan-500/20
    bg-[#071028]/90
    p-6
    shadow-[0_0_50px_rgba(0,255,255,0.04)]
    "
      >
        <div
          className="
        flex
        flex-wrap
        items-center
        justify-between
        gap-4
        mb-6
    "
        >
          <div
            className="
        flex
        items-center
        gap-3
        "
          >
            <Sigma className="text-cyan-400" size={22} />

            <div>
              <div
                className="
            text-white
            font-bold
            text-lg
            "
              >
                Live Risk Fabric Equation
              </div>

              <div
                className="
            text-slate-400
            text-sm
            "
              >
                R = V + E + B + A + C + I + K
              </div>
            </div>
          </div>

          <div
            className="
        text-right
        "
          >
            <div
              className="
            text-xs
            uppercase
            tracking-[0.25em]
            text-slate-500
            mb-1
        "
            >
              Last Updated
            </div>

            <div
              className="
            text-cyan-300
            font-bold
        "
            >
              {lastUpdatedLabel}
            </div>
          </div>
        </div>

        {/* EQUATION */}

        <pre
          className="
        overflow-x-auto
        text-cyan-300
        text-sm
        leading-relaxed
        font-mono
        whitespace-pre-wrap
    "
        >
          {fusionEquation}
        </pre>

        {/* METRICS */}

        <div
          className="
        mt-6
        grid
        grid-cols-2
        md:grid-cols-4
        xl:grid-cols-8
        gap-4
    "
        >
          <EquationMetric
            label="R"
            value={calculatedRisk.toFixed(2)}
            color="text-red-400"
          />

          <EquationMetric
            label="V"
            value={activeComponents.V.toFixed(2)}
            color="text-orange-400"
          />

          <EquationMetric
            label="E"
            value={activeComponents.E.toFixed(2)}
            color="text-red-300"
          />

          <EquationMetric
            label="B"
            value={activeComponents.B.toFixed(2)}
            color="text-yellow-300"
          />

          <EquationMetric
            label="A"
            value={activeComponents.A.toFixed(2)}
            color="text-purple-400"
          />

          <EquationMetric
            label="C"
            value={activeComponents.C.toFixed(2)}
            color="text-cyan-300"
          />

          <EquationMetric
            label="I"
            value={activeComponents.I.toFixed(2)}
            color="text-green-400"
          />

          <EquationMetric
            label="K"
            value={activeComponents.K.toFixed(2)}
            color="text-blue-400"
          />
        </div>

        {/* VALIDATION */}

        <div
          className="
        mt-6
        pt-5
        border-t
        border-white/5
    "
        >
          <div
            className="
        flex
        flex-wrap
        items-center
        gap-x-5
        gap-y-3
        text-sm
        "
          >
            {/* BACKEND */}

            <div
              className="
            flex
            items-center
            gap-2
        "
            >
              <div
                className="
            text-slate-500
            uppercase
            tracking-wider
            text-xs
            "
              >
                Backend Risk
              </div>

              <div
                className="
            text-white
            font-black
            "
              >
                {backendRisk.toFixed(2)}
              </div>
            </div>

            {/* RECOMPUTED */}

            <div
              className="
            flex
            items-center
            gap-2
        "
            >
              <div
                className="
            text-slate-500
            uppercase
            tracking-wider
            text-xs
            "
              >
                Recomputed
              </div>

              <div
                className="
            text-cyan-300
            font-black
            "
              >
                {calculatedRisk.toFixed(2)}
              </div>
            </div>

            {/* DELTA */}

            <div
              className="
            flex
            items-center
            gap-2
        "
            >
              <div
                className="
            text-slate-500
            uppercase
            tracking-wider
            text-xs
            "
              >
                Delta
              </div>

              <div
                className={`
            font-black
            ${
              delta <= 1
                ? "text-green-400"
                : delta <= 5
                  ? "text-yellow-300"
                  : "text-red-400"
            }
            `}
              >
                {delta.toFixed(2)}
              </div>
            </div>

            {/* INTEGRITY */}

            <div
              className="
            flex
            items-center
            gap-2
        "
            >
              <div
                className="
            text-slate-500
            uppercase
            tracking-wider
            text-xs
            "
              >
                Fusion Integrity
              </div>

              <div
                className={`
            px-3
            py-1
            rounded-lg
            text-[10px]
            font-black
            uppercase
            tracking-[0.2em]
            border
            ${
              delta <= 1
                ? "bg-green-500/10 text-green-300 border-green-500/20"
                : delta <= 5
                  ? "bg-yellow-500/10 text-yellow-300 border-yellow-500/20"
                  : "bg-red-500/10 text-red-300 border-red-500/20"
            }
            `}
              >
                {delta <= 1
                  ? "VALIDATED"
                  : delta <= 5
                    ? "DIVERGENT"
                    : "DESYNCHRONIZED"}
              </div>
            </div>

            {/* DOMINANT ATTACK */}

            <div
              className="
            flex
            items-center
            gap-2
        "
            >
              <div
                className="
            text-slate-500
            uppercase
            tracking-wider
            text-xs
            "
              >
                Dominant Attack
              </div>

              <div
                className="
            text-red-300
            font-black
            uppercase
            tracking-wider
            "
              >
                {topAttackType}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* COMPONENT PARTICIPATION */}

      <div
        className="
        mb-8
        rounded-2xl
        border
        border-cyan-500/20
        bg-[#071028]/90
        p-6
      "
      >
        <div
          className="
          text-white
          font-bold
          text-lg
          mb-5
        "
        >
          Behavioral Contribution Controls
        </div>

        <div
          className="
          grid
          grid-cols-1
          md:grid-cols-2
          xl:grid-cols-4
          gap-5
        "
        >
          {[
            ["V", "Volume Amplification"],
            ["E", "Severity Escalation"],
            ["B", "Behavioral Pressure"],
            ["A", "Signal Amplification"],
            ["C", "C2 Escalation"],
            ["I", "Impact Escalation"],
            ["K", "Behavioral Coupling"],
          ].map(([key, label]) => (
            <ComponentToggleCard
              key={key}
              componentKey={key}
              label={label}
              value={liveComponents[key]}
              enabled={activeToggles[key]}
              onToggle={() =>
                setActiveToggles((prev) => ({
                  ...prev,
                  [key]: !prev[key],
                }))
              }
            />
          ))}
        </div>
      </div>

      {/* PROVENANCE NODES */}

      <div
        className="
        grid
        grid-cols-1
        xl:grid-cols-2
        gap-6
      "
      >
        {provenanceNodes.map((node, index) => {
          const style = stateStyles[node.state] || stateStyles.validated;

          return (
            <div
              key={index}
              className={`
                    relative
                    overflow-hidden
                    rounded-2xl
                    border
                    bg-[#071028]/90
                    p-6
                    transition-all
                    duration-300
                    ${style.border}
                    ${style.glow}
                  `}
            >
              <div
                className="
                    relative
                    z-10
                  "
              >
                <div
                  className="
                      flex
                      items-start
                      justify-between
                      gap-4
                      mb-5
                    "
                >
                  <div
                    className="
                        flex
                        items-start
                        gap-4
                      "
                  >
                    <div
                      className="
                          flex
                          items-center
                          justify-center
                          w-12
                          h-12
                          rounded-xl
                          bg-black/30
                          border
                          border-white/5
                        "
                    >
                      {node.icon}
                    </div>

                    <div>
                      <h3
                        className="
                            text-xl
                            font-bold
                            text-white
                            mb-2
                          "
                      >
                        {node.title}
                      </h3>

                      <p
                        className="
                            text-slate-400
                            text-sm
                            leading-relaxed
                            max-w-xl
                          "
                      >
                        {node.description}
                      </p>
                    </div>
                  </div>

                  <div
                    className={`
                          shrink-0
                          px-3
                          py-1
                          rounded-lg
                          text-[10px]
                          font-bold
                          uppercase
                          tracking-widest
                          ${style.badge}
                        `}
                  >
                    {node.state}
                  </div>
                </div>

                <div
                  className="
                      mt-5
                      pt-4
                      border-t
                      border-white/5
                      flex
                      items-center
                      justify-between
                    "
                >
                  <div
                    className="
                        flex
                        items-center
                        gap-2
                        text-xs
                        text-slate-500
                      "
                  >
                    <ShieldCheck size={13} />
                    Deterministic reasoning validated
                  </div>

                  <ChevronRight size={16} className="text-slate-600" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ======================================================
// EQUATION METRIC
// ======================================================

function EquationMetric({ label, value, color }) {
  return (
    <div
      className="
      rounded-xl
      border
      border-white/5
      bg-black/20
      p-4
    "
    >
      <div
        className="
        text-xs
        uppercase
        tracking-widest
        text-slate-500
        mb-2
      "
      >
        {label}
      </div>

      <div
        className={`
          text-2xl
          font-black
          ${color}
        `}
      >
        {value}
      </div>
    </div>
  );
}

// ======================================================
// COMPONENT TOGGLE CARD
// ======================================================

function ComponentToggleCard({
  componentKey,
  label,
  value,
  enabled,
  onToggle,
}) {
  return (
    <div
      className={`
      rounded-xl
      border
      p-5
      transition-all
      duration-300
      ${
        enabled
          ? "border-cyan-500/20 bg-cyan-500/[0.03]"
          : "border-white/5 bg-black/20 opacity-60"
      }
    `}
    >
      <div
        className="
        flex
        items-start
        justify-between
        gap-3
        mb-4
      "
      >
        <div>
          <div
            className="
            text-xs
            uppercase
            tracking-widest
            text-slate-500
            mb-2
          "
          >
            {componentKey}
          </div>

          <div
            className="
            text-sm
            font-semibold
            text-white
            leading-snug
          "
          >
            {label}
          </div>
        </div>

        <button
          onClick={onToggle}
          className={`
            px-3
            py-1
            rounded-lg
            text-[10px]
            font-bold
            uppercase
            tracking-widest
            transition-all
            duration-300
            ${
              enabled
                ? "bg-green-500/10 text-green-300 border border-green-500/20"
                : "bg-red-500/10 text-red-300 border border-red-500/20"
            }
          `}
        >
          {enabled ? "ACTIVE" : "DISABLED"}
        </button>
      </div>

      <div
        className="
        text-3xl
        font-black
        text-cyan-300
        mb-3
      "
      >
        {enabled ? value : 0}
      </div>

      <div
        className="
        text-xs
        leading-relaxed
        text-slate-400
      "
      >
        {enabled
          ? "Participating in deterministic risk recomputation."
          : "Excluded from live behavioral risk fusion."}
      </div>
    </div>
  );
}
