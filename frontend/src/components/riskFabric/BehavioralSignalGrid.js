// src/components/riskFabric/BehavioralSignalGrid.js

import React, {
  useMemo,
} from "react";

import {
  Activity,
  Radar,
  ShieldAlert,
  Brain,
  TrendingUp,
  Shield,
  Binary,
  ServerCrash,
  Gauge,
  Wifi,
  WifiOff,
  Clock3,
} from "lucide-react";

import BehavioralSignalCard
from "./BehavioralSignalCard";

import {
  useTelemetry,
} from "../../context/TelemetryContext";

// =====================================================
// SAFE HELPERS
// =====================================================

const safeNumber = (
  value,
  fallback = 0
) => {

  const parsed =
    Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;

};

const getSeverity =
  (
    value,
    elevated,
    high,
    critical
  ) => {

    if (value >= critical) {
      return "critical";
    }

    if (value >= high) {
      return "high";
    }

    if (value >= elevated) {
      return "elevated";
    }

    return "stable";

  };

// =====================================================
// COMPONENT
// =====================================================

export default function BehavioralSignalGrid() {

  // ===================================================
  // CENTRALIZED TELEMETRY
  // ===================================================

  const {

    threatSummary,
    backendHealthy,
    stale,
    latency,
    loading,
    lastUpdated,
    refreshCount,

  } = useTelemetry();

  // ===================================================
  // CORE
  // ===================================================

  const core =
    useMemo(() => {

      return (
        threatSummary?.coreSummary ||
        threatSummary ||
        {}
      );

    }, [threatSummary]);

  // ===================================================
  // SHARED PIPELINE OBJECTS
  // ===================================================

  const reasoning =
    core?.reasoning || {};

  const attackMetrics =
    core?.attackMetrics || {};

  const attackClassification =
    core?.attackClassification || {};

  const behaviorSummary =
    core?.behaviorSummary || {};

  const scanningIndicators =
    core?.scanningIndicators || {};

  const riskComponents =
    core?.riskComponents || {};

  // ===================================================
  // SYNCHRONIZED RISK SCORE
  // ===================================================

  const riskScore =
    safeNumber(
      core?.riskScore0to100 ??
      core?.riskScore
    );

  // ===================================================
  // SYNCHRONIZED STATE
  // ===================================================

  const state =
    String(

      reasoning?.state ||

      core?.state ||

      core?.riskState ||

      "stable"

    ).toLowerCase();

  // ===================================================
  // ATTACK METRICS
  // ===================================================

  const attacksLast5Min =
    safeNumber(
      attackMetrics?.attacksLast5Min
    );

  const attacksLastHour =
    safeNumber(
      attackMetrics?.attacksLastHour
    );

  const burstRatio5m =
    safeNumber(
      attackMetrics?.burstRatio5mOverHour
    );

  // ===================================================
  // ATTACK CLASSIFICATION
  // ===================================================

  const dominantAttack =
    String(

      reasoning?.dominantAttackType ||

      attackClassification?.dominantAttack?.type ||

      attackClassification?.topAttackType ||

      core?.dominantAttack ||

      "unknown"

    ).toUpperCase();

  const dosScore =
    safeNumber(
      attackClassification
        ?.attackTypeScores?.dos
    );

  const scanScore =
    safeNumber(
      attackClassification
        ?.attackTypeScores?.scan
    );

  const bruteForceScore =
    safeNumber(
      attackClassification
        ?.attackTypeScores
        ?.brute_force
    );

  const c2Score =
    safeNumber(
      attackClassification
        ?.attackTypeScores?.c2
    );

  // ===================================================
  // BEHAVIORAL SIGNALS
  // ===================================================

  const authPressure =
    safeNumber(
      behaviorSummary?.authPressure
    );

  const webPressure =
    safeNumber(
      behaviorSummary?.webPressure
    );

  const dbPressure =
    safeNumber(
      behaviorSummary?.dbPressure
    );

  const portEntropy =
    safeNumber(
      behaviorSummary?.portEntropy
    );

  // ===================================================
  // SCANNING
  // ===================================================

  const topPort =
    scanningIndicators
      ?.topPorts?.[0]?.port || "N/A";

  // ===================================================
  // RISK FABRIC COMPONENTS
  // ===================================================

  const volumeComponent =
    safeNumber(
      riskComponents?.volumeComponent
    );

  const severityComponent =
    safeNumber(
      riskComponents?.severityComponent
    );

  const behaviorComponent =
    safeNumber(
      riskComponents?.behaviorComponent
    );

  const signalAmplifier =
    safeNumber(
      riskComponents?.signalAmplifier
    );

  const c2Bonus =
    safeNumber(
      riskComponents?.c2Bonus
    );

  const impactBonus =
    safeNumber(
      riskComponents?.impactBonus
    );

  const couplingBonus =
    safeNumber(
      riskComponents?.couplingBonus
    );

  // ===================================================
  // TELEMETRY STATUS
  // ===================================================

  const telemetryStatus =
    loading
      ? "SYNCING"
      : stale
      ? "STALE"
      : backendHealthy
      ? "LIVE"
      : "OFFLINE";

  const lastUpdatedLabel =
    lastUpdated
      ? new Date(
          lastUpdated
        ).toLocaleTimeString()
      : "--";

  // ===================================================
  // UI
  // ===================================================

  return (

    <section className="
      relative
      z-10
      mb-10
    ">

      {/* HEADER */}

      <div className="
        flex
        items-center
        justify-between
        mb-6
        gap-4
        flex-wrap
      ">

        <div>

          <h2 className="
            text-2xl
            font-black
            text-white
            mb-2
          ">
            Behavioral Signal Grid
          </h2>

          <p className="
            text-slate-400
            text-sm
            max-w-3xl
          ">
            Fully synchronized with the
            centralized Chiron telemetry
            engine and Master Risk Fabric.
          </p>

        </div>

        <div className="
          flex
          items-center
          gap-3
          flex-wrap
        ">

          <div className="
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
          ">
            LIVE CONTEXT
          </div>

          <div className={`
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
          `}>

            {
              backendHealthy
                ? <Wifi size={12} />
                : <WifiOff size={12} />
            }

            {
              backendHealthy
                ? "BACKEND OK"
                : "BACKEND DOWN"
            }

          </div>

          <div className="
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
          ">
            <Gauge size={12} />
            {latency}ms
          </div>

          <div className="
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
          ">
            <Clock3 size={12} />
            {telemetryStatus}
          </div>

        </div>

      </div>

      {/* GRID */}

      <div className="
        grid
        grid-cols-1
        md:grid-cols-2
        xl:grid-cols-4
        gap-5
      ">

        <BehavioralSignalCard
          title="Risk Score"
          value={`${riskScore.toFixed(2)}/100`}
          subtitle="Shared deterministic escalation score."
          severity={state}
          trend={`${burstRatio5m.toFixed(2)}x`}
          icon={
            <Activity
              className="text-cyan-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Dominant Attack"
          value={dominantAttack}
          subtitle="Highest weighted live attack classification."
          severity={state}
          trend={`${attacksLast5Min} events`}
          icon={
            <Radar
              className="text-cyan-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="DOS Score"
          value={dosScore.toFixed(2)}
          subtitle="Real DOS classification confidence."
          severity={
            getSeverity(
              dosScore,
              0.35,
              0.55,
              0.75
            )
          }
          icon={
            <ShieldAlert
              className="text-red-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Scan Score"
          value={scanScore.toFixed(2)}
          subtitle="Reconnaissance classification confidence."
          severity={
            getSeverity(
              scanScore,
              0.35,
              0.55,
              0.75
            )
          }
          icon={
            <Radar
              className="text-cyan-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Brute Force"
          value={bruteForceScore.toFixed(2)}
          subtitle="Authentication attack confidence."
          severity={
            getSeverity(
              bruteForceScore,
              0.35,
              0.55,
              0.75
            )
          }
          icon={
            <Shield
              className="text-orange-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="C2 Probability"
          value={c2Score.toFixed(2)}
          subtitle="Command-and-control synchronization confidence."
          severity={
            getSeverity(
              c2Score,
              0.25,
              0.45,
              0.65
            )
          }
          icon={
            <ServerCrash
              className="text-red-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Auth Pressure"
          value={authPressure}
          subtitle="Authentication escalation pressure."
          severity={
            getSeverity(
              authPressure,
              10,
              25,
              50
            )
          }
          icon={
            <Shield
              className="text-purple-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Web Pressure"
          value={webPressure}
          subtitle="HTTP exploitation pressure."
          severity={
            getSeverity(
              webPressure,
              10,
              25,
              50
            )
          }
          icon={
            <Activity
              className="text-cyan-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="DB Pressure"
          value={dbPressure}
          subtitle="Database attack escalation pressure."
          severity={
            getSeverity(
              dbPressure,
              5,
              15,
              30
            )
          }
          icon={
            <Binary
              className="text-green-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Port Entropy"
          value={portEntropy.toFixed(2)}
          subtitle="Real Shannon entropy from hostile ports."
          severity={
            getSeverity(
              portEntropy,
              1.5,
              2.5,
              3.5
            )
          }
          icon={
            <Brain
              className="text-purple-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Top Target Port"
          value={`${topPort}`}
          subtitle="Most targeted operational port."
          severity="elevated"
          icon={
            <Radar
              className="text-cyan-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Volume Component"
          value={volumeComponent.toFixed(2)}
          subtitle="Risk Fabric volume amplification."
          severity={
            getSeverity(
              volumeComponent,
              10,
              20,
              35
            )
          }
          icon={
            <TrendingUp
              className="text-cyan-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Severity Component"
          value={severityComponent.toFixed(2)}
          subtitle="Critical severity accumulation."
          severity={
            getSeverity(
              severityComponent,
              5,
              10,
              20
            )
          }
          icon={
            <ShieldAlert
              className="text-red-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Behavior Component"
          value={behaviorComponent.toFixed(2)}
          subtitle="Behavioral targeting pressure."
          severity={
            getSeverity(
              behaviorComponent,
              5,
              10,
              20
            )
          }
          icon={
            <Brain
              className="text-yellow-300"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Signal Amplifier"
          value={signalAmplifier.toFixed(2)}
          subtitle="Attack confidence amplification."
          severity={
            getSeverity(
              signalAmplifier,
              5,
              10,
              20
            )
          }
          icon={
            <Activity
              className="text-purple-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="C2 Bonus"
          value={c2Bonus.toFixed(2)}
          subtitle="C2 escalation contribution."
          severity={
            getSeverity(
              c2Bonus,
              2,
              5,
              10
            )
          }
          icon={
            <ServerCrash
              className="text-cyan-300"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Impact Bonus"
          value={impactBonus.toFixed(2)}
          subtitle="Severity impact escalation."
          severity={
            getSeverity(
              impactBonus,
              1,
              3,
              6
            )
          }
          icon={
            <Shield
              className="text-green-400"
              size={18}
            />
          }
        />

        <BehavioralSignalCard
          title="Coupling Bonus"
          value={couplingBonus.toFixed(2)}
          subtitle="Behavioral coupling amplification."
          severity={
            getSeverity(
              couplingBonus,
              1,
              2,
              4
            )
          }
          icon={
            <Binary
              className="text-blue-400"
              size={18}
            />
          }
        />

      </div>

      {/* FOOTER */}

      <div className="
        mt-6
        pt-4
        border-t
        border-white/5
        flex
        flex-wrap
        items-center
        gap-6
        text-xs
        text-slate-500
      ">

        <div>
          Refresh Count:
          <span className="
            text-cyan-300
            ml-2
            font-bold
          ">
            {refreshCount}
          </span>
        </div>

        <div>
          Last Updated:
          <span className="
            text-cyan-300
            ml-2
            font-bold
          ">
            {lastUpdatedLabel}
          </span>
        </div>

        <div>
          Backend Latency:
          <span className="
            text-cyan-300
            ml-2
            font-bold
          ">
            {latency}ms
          </span>
        </div>

      </div>

    </section>

  );

}