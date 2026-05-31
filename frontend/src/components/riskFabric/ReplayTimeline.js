// src/components/riskFabric/ReplayTimeline.js

import React, {
  useMemo,
} from "react";

import {
  Play,
  ShieldAlert,
  Radar,
  Activity,
  Clock3,
  CheckCircle2,
  PauseCircle,
  Wifi,
  WifiOff,
  Gauge,
  Workflow,
  AlertTriangle,
  Database,
  FileWarning,
} from "lucide-react";

import {
  useTelemetry,
} from "../../context/TelemetryContext";

// =========================================================
// REPLAY PHASE CONFIG
// =========================================================

const replayPhaseConfig = {

  baseline: {

    label:
      "Baseline",

    color:
      "bg-green-500/10 border-green-500/30",

    text:
      "text-green-300",

    glow:
      "shadow-[0_0_30px_rgba(34,197,94,0.08)]",

    icon:
      <CheckCircle2 size={15} />,

  },

  injection: {

    label:
      "Injection",

    color:
      "bg-red-500/10 border-red-500/30",

    text:
      "text-red-300",

    glow:
      "shadow-[0_0_40px_rgba(239,68,68,0.12)]",

    icon:
      <ShieldAlert size={15} />,

  },

  cooldown: {

    label:
      "Cooldown",

    color:
      "bg-cyan-500/10 border-cyan-500/30",

    text:
      "text-cyan-300",

    glow:
      "shadow-[0_0_30px_rgba(0,229,255,0.08)]",

    icon:
      <Clock3 size={15} />,

  },

};

// =========================================================
// OVERLAY CONFIG
// =========================================================

const overlayConfig = {

  stable: {

    label:
      "Stable",

    color:
      "text-green-300",

    icon:
      <CheckCircle2 size={14} />,

  },

  elevated: {

    label:
      "Elevated",

    color:
      "text-yellow-300",

    icon:
      <Radar size={14} />,

  },

  high: {

    label:
      "High",

    color:
      "text-orange-300",

    icon:
      <Activity size={14} />,

  },

  critical: {

    label:
      "Critical",

    color:
      "text-red-300",

    icon:
      <ShieldAlert size={14} />,

  },

};

// =========================================================
// HELPERS
// =========================================================

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

const normalizePhase = (
  value
) => {

  return String(
    value || "unknown"
  )
    .trim()
    .toLowerCase();

};

const formatNumber = (
  value
) => {

  return safeNumber(value)
    .toLocaleString();

};

const formatDuration = (
  minutes
) => {

  const value =
    safeNumber(minutes);

  if (value < 1) {

    return `${(value * 60).toFixed(0)}s`;

  }

  if (value >= 60) {

    return `${(value / 60).toFixed(1)}h`;

  }

  return `${value.toFixed(1)}m`;

};

// =========================================================
// COMPONENT
// =========================================================

export default function ReplayTimeline() {

  const {

    threatSummary,

    loading,

    backendHealthy,

    stale,

    latency,

    lastUpdated,

  } = useTelemetry();

  // =====================================================
  // CORE
  // =====================================================

  const core = useMemo(() => {

    return (

      threatSummary?.coreSummary ||

      threatSummary ||

      {}

    );

  }, [threatSummary]);

  // =====================================================
  // ATTACK METRICS
  // =====================================================

  const attackMetrics =
    core?.attackMetrics || {};

  // =====================================================
  // REPLAY
  // =====================================================

  const replay =
    core?.replay || {};

  const replayMode =
    replay?.replayMode ||

    core?.replayMode ||

    "unknown";

  // =====================================================
  // GLOBAL OVERLAY
  // =====================================================

  const replayOverlay =

    core?.replayOverlay ||

    {};

  // =====================================================
  // REPLAY DATA
  // =====================================================

  const replayData = useMemo(() => {

    const timeline =

      replay?.timeline ||

      core?.replayTimeline ||

      [];

    if (!Array.isArray(timeline)) {

      return [];

    }

    return timeline

      .filter(Boolean)

      .map((item, index) => {

        const phase =
          normalizePhase(
            item.phase
          );

        // ============================================
        // PHASE OVERLAY
        // ============================================

        const phaseOverlay =

          item?.overlay ||

          item?.phaseOverlay ||

          {};

        // ============================================
        // TIMESTAMPS
        // ============================================

        const startedAt =

          item.startedAt ||

          item.startTime ||

          item.timestamp ||

          null;

        const endedAt =

          item.endedAt ||

          item.endTime ||

          null;

        // ============================================
        // PCAP NAME
        // ============================================

        const pcapName =

          item?.metadata?.pcapName ||

          item?.pcapName ||

          replay?.pcapName ||

          replay?.metadata?.pcapName ||

          core?.pcapName ||

          core?.activePcap ||

          "unknown";

        // ============================================
        // IDS
        // ============================================

        const replayId =

          item.replayId ||

          item.sessionId ||

          item.runId ||

          null;

        // ============================================
        // WINDOWING
        // ============================================

        let startMinute =
          safeNumber(
            item.startMinute,
            index
          );

        let endMinute =
          safeNumber(
            item.endMinute,
            startMinute + 1
          );

        let derivedDurationMinutes =
          Math.max(
            0,
            endMinute - startMinute
          );

        // ============================================
        // REAL DURATION DERIVATION
        // ============================================

        if (
          startedAt &&
          endedAt
        ) {

          const startMs =
            new Date(
              startedAt
            ).getTime();

          const endMs =
            new Date(
              endedAt
            ).getTime();

          if (
            Number.isFinite(startMs) &&
            Number.isFinite(endMs)
          ) {

            derivedDurationMinutes =
              Math.max(
                0,
                (endMs - startMs) /
                60000
              );

          }

        }

        // ============================================
        // PHASE TELEMETRY
        // ============================================

        const events =
          safeNumber(

            phaseOverlay?.attacksLast5Min ??

            phaseOverlay?.events ??

            0

          );

        const eps =
          safeNumber(

            phaseOverlay?.attacksPerSecond ??

            phaseOverlay?.eps ??

            0

          );

        const risk =
          safeNumber(

            phaseOverlay?.riskScore0to100 ??

            phaseOverlay?.risk ??

            0

          );

        const overlayState =
          normalizePhase(

            phaseOverlay?.state ||

            "stable"

          );

        const dominantAttack =

          phaseOverlay?.dominantAttack ||

          phaseOverlay?.dominantThreat ||

          "none";

        const attackConfidence =

          phaseOverlay?.attackConfidence ||

          "low";

        const attackDetected =
          Boolean(

            phaseOverlay?.attackDetected

          );

        // ============================================
        // GROUND TRUTH
        // ============================================

        const truthLabel =

          item?.groundTruth ||

          item?.truth ||

          (
            phase === "injection"
              ? "Attack"
              : phase === "cooldown"
              ? "Residual"
              : "Normal"
          );
        return {

          id:
            `${phase}-${index}-${pcapName}`,

          phase,

          replayId,

          pcapName,

          startMinute,

          endMinute,

          durationMinutes:
            Number(
              derivedDurationMinutes.toFixed(2)
            ),

          replayMode:
            item?.metadata?.replayMode ||
            replayMode,

          currentWindow:
            item?.metadata?.currentWindow ||
            null,

          // ========================================
          // PHASE OVERLAY
          // ========================================

          events,

          eps,

          risk,

          overlayState,

          dominantAttack,

          attackConfidence,

          attackDetected,

          truthLabel,

          // ========================================
          // STATUS
          // ========================================

          isReplayActive:
            Boolean(
              item.isActive
            ),

          isCooldown:
            phase === "cooldown",

          isActive:
            Boolean(
              item.isActive
            ),

          // ========================================
          // TIMESTAMPS
          // ========================================

          startedAt,

          endedAt,

        };

      });

  }, [

    core,

    replay,

    replayMode,

    replayOverlay,

  ]);

  // =====================================================
  // CURRENT REPLAY PHASE
  // =====================================================

  const currentReplayPhase = useMemo(() => {

    return normalizePhase(

      replay?.state ||

      core?.replayState ||

      "idle"

    );

  }, [

    replay,

    core,

  ]);

  // =====================================================
  // GLOBAL OVERLAY STATE
  // =====================================================

  const overlayState = useMemo(() => {

    return normalizePhase(

      replayOverlay?.state ||

      core?.state ||

      "stable"

    );

  }, [

    replayOverlay,

    core,

  ]);

  // =====================================================
  // TOTAL EVENTS
  // =====================================================

  const totalEvents = useMemo(() => {

    return replayData.reduce(

      (total, item) => {

        return (
          total +
          safeNumber(item.events)
        );

      },

      0

    );

  }, [replayData]);

  // =====================================================
  // GLOBAL ATTACK RATE
  // =====================================================

  const attackRate =
    safeNumber(

      replayOverlay?.attacksPerSecond ??

      (
        safeNumber(
          attackMetrics?.attacksLast5Min,
          0
        ) / 300
      )

    );

  // =====================================================
  // REPLAY STATE
  // =====================================================

  const replayState = useMemo(() => {

    if (loading) {

      return "SYNCING";

    }

    if (
      currentReplayPhase ===
      "injection"
    ) {

      return "ACTIVE";

    }

    if (
      currentReplayPhase ===
      "cooldown"
    ) {

      return "COOLDOWN";

    }

    if (
      replayData.length > 0
    ) {

      return "COMPLETE";

    }

    return "IDLE";

  }, [

    loading,

    currentReplayPhase,

    replayData,

  ]);

  // =====================================================
  // TELEMETRY STATUS
  // =====================================================

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

  const hasRealReplayData =
    replayData.length > 0;

  // =====================================================
  // UI
  // =====================================================

  return (

    <section className="
      relative
      z-10
      px-4
      md:px-8
      pb-12
    ">

      {/* ================================================= */}
      {/* HEADER */}
      {/* ================================================= */}

      <div className="
        flex
        flex-col
        xl:flex-row
        xl:items-center
        xl:justify-between
        gap-4
        mb-6
      ">

        <div>

          <div className="
            flex
            items-center
            gap-3
            mb-3
          ">

            <Workflow
              className="
                text-cyan-400
              "
              size={24}
            />

            <h2 className="
              text-2xl
              font-black
              text-white
            ">
              Replay Timeline
            </h2>

          </div>

          <p className="
            text-slate-400
            text-sm
            max-w-5xl
            leading-relaxed
          ">

            Real replay telemetry driven entirely by backend replay orchestration,
            forensic injection lifecycle tracking,
            cooldown monitoring,
            and live threat-intelligence overlays.

          </p>

        </div>

        <div className="
          flex
          items-center
          gap-3
          flex-wrap
        ">

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
          ">

            <Clock3 size={12} />

            {telemetryStatus}

          </div>

          <div className="text-right">

            <div className="
              text-[10px]
              uppercase
              tracking-[0.25em]
              text-slate-500
              mb-1
            ">
              Last Sync
            </div>

            <div className="
              text-cyan-300
              text-sm
              font-bold
            ">
              {lastUpdatedLabel}
            </div>

          </div>

        </div>

      </div>

      {/* ================================================= */}
      {/* METRICS */}
      {/* ================================================= */}

      <div className="
        grid
        grid-cols-1
        md:grid-cols-2
        xl:grid-cols-7
        gap-4
        mb-6
      ">

        <ReplayMetric
          title="Replay State"
          value={replayState}
          color="text-cyan-300"
          icon={<Play size={16} />}
        />

        <ReplayMetric
          title="Replay Phase"
          value={currentReplayPhase}
          color="text-red-400"
          icon={<ShieldAlert size={16} />}
        />

        <ReplayMetric
          title="Threat State"
          value={overlayState}
          color={
            overlayConfig[
              overlayState
            ]?.color || "text-cyan-300"
          }
          icon={
            overlayConfig[
              overlayState
            ]?.icon
          }
        />

        <ReplayMetric
          title="Replay Events"
          value={formatNumber(totalEvents)}
          color="text-orange-300"
          icon={<Activity size={16} />}
        />

        <ReplayMetric
          title="Attack Rate"
          value={`${formatNumber(attackRate)} EPS`}
          color="text-yellow-300"
          icon={<Radar size={16} />}
        />

        <ReplayMetric
          title="Replay Mode"
          value={replayMode}
          color="text-green-300"
          icon={<PauseCircle size={16} />}
        />

        <ReplayMetric
          title="Replay Phases"
          value={formatNumber(
            replayData.length
          )}
          color="text-cyan-300"
          icon={<Database size={16} />}
        />

      </div>

      {/* ================================================= */}
      {/* EMPTY */}
      {/* ================================================= */}

      {

        !hasRealReplayData ? (

          <div className="
            rounded-3xl
            border
            border-yellow-500/20
            bg-yellow-500/10
            p-8
            text-yellow-300
            shadow-[0_0_40px_rgba(234,179,8,0.08)]
          ">

            <div className="
              flex
              items-start
              gap-4
            ">

              <AlertTriangle
                size={24}
                className="
                  shrink-0
                  mt-1
                "
              />

              <div>

                <div className="
                  text-xl
                  font-black
                  text-white
                  mb-2
                ">
                  No Replay Data Available
                </div>

                <p className="
                  text-sm
                  leading-relaxed
                  text-yellow-100/80
                  max-w-5xl
                ">

                  Backend replay orchestration telemetry
                  is not currently available.

                </p>

              </div>

            </div>

          </div>

        ) : (

          <div className="
            overflow-hidden
            rounded-3xl
            border
            border-cyan-500/20
            bg-[#071028]/90
            shadow-[0_0_60px_rgba(0,255,255,0.06)]
          ">

            <div className="
              relative
              grid
              grid-cols-1
              xl:grid-cols-[repeat(auto-fit,minmax(280px,1fr))]
            ">

              {

                replayData.map(
                  (item) => {

                    const config =

                      replayPhaseConfig[
                        item.phase
                      ] ||

                      replayPhaseConfig.cooldown;

                    const isActive =

                      Boolean(item.isActive) ||

                      (
                        item.phase === currentReplayPhase &&
                        replayState === "ACTIVE"
                      );

                    return (

                      <div
                        key={item.id}
                        className={`
                          relative
                          border-r
                          border-white/5
                          transition-all
                          duration-500
                          ${config.glow}
                        `}
                      >

                        <div
                          className={`
                            absolute
                            inset-0
                            ${config.color}
                            ${
                              isActive
                                ? "opacity-100"
                                : "opacity-60"
                            }
                          `}
                        />

                        <div className="
                          relative
                          z-10
                          p-6
                          min-h-[360px]
                          flex
                          flex-col
                        ">

                          {/* ================================= */}
                          {/* HEADER */}
                          {/* ================================= */}

                          <div className="
                            flex
                            items-center
                            justify-between
                            mb-6
                          ">

                            <div className="
                              flex
                              items-center
                              gap-2
                            ">

                              <div className={
                                config.text
                              }>
                                {config.icon}
                              </div>

                              <div className={`
                                font-bold
                                ${config.text}
                              `}>

                                {config.label}

                              </div>

                            </div>

                            <div className="
                              text-[10px]
                              uppercase
                              tracking-widest
                              text-slate-400
                            ">

                              {

                                item.currentWindow
                                  ? `WINDOW ${item.currentWindow}`
                                  : "REPLAY"

                              }

                            </div>

                          </div>

                          {/* ================================= */}
                          {/* ACTIVE BADGE */}
                          {/* ================================= */}

                          {

                            isActive && (

                              <div className="
                                mb-5
                              ">

                                <div className="
                                  inline-flex
                                  items-center
                                  gap-2
                                  px-3
                                  py-1
                                  rounded-lg
                                  bg-red-500/10
                                  border
                                  border-red-500/20
                                  text-red-300
                                  text-[10px]
                                  font-black
                                  uppercase
                                  tracking-[0.2em]
                                ">

                                  ACTIVE REPLAY

                                </div>

                              </div>

                            )

                          }

                          {/* ================================= */}
                          {/* VALUES */}
                          {/* ================================= */}

                          <TimelineValue
                            label="Ground Truth"
                            value={item.truthLabel}
                            color={
                              item.truthLabel === "Attack"
                                ? "text-red-300"
                                : "text-green-300"
                            }
                          />

                          <TimelineValue
                            label="Risk Score"
                            value={item.risk}
                            color={config.text}
                            large
                          />

                          <TimelineValue
                            label="Events"
                            value={formatNumber(
                              item.events
                            )}
                            color="text-white"
                          />

                          <TimelineValue
                            label="EPS"
                            value={formatNumber(
                              item.eps
                            )}
                            color="text-cyan-300"
                          />

                          <TimelineValue
                            label="Dominant Threat"
                            value={item.dominantAttack}
                            color="text-yellow-300"
                          />

                          <TimelineValue
                            label="PCAP"
                            value={item.pcapName}
                            color={
                              item.pcapName === "unknown"
                                ? "text-red-300"
                                : "text-orange-300"
                            }
                          />

                          {/* ================================= */}
                          {/* FOOTER */}
                          {/* ================================= */}

                          <div className="
                            mt-auto
                            pt-4
                            border-t
                            border-white/5
                          ">

                            <div className="
                              text-xs
                              text-slate-500
                              mb-2
                            ">
                              Replay Window
                            </div>

                            <div className="
                              text-sm
                              font-semibold
                              text-white
                            ">

                              Duration:
                              {" "}
                              {
                                formatDuration(
                                  item.durationMinutes
                                )
                              }

                            </div>

                            {

                              item.startedAt && (

                                <div className="
                                  mt-2
                                  text-xs
                                  text-slate-500
                                ">

                                  Start:
                                  {" "}

                                  {
                                    new Date(
                                      item.startedAt
                                    ).toLocaleTimeString()
                                  }

                                </div>

                              )

                            }

                            {

                              item.endedAt && (

                                <div className="
                                  mt-1
                                  text-xs
                                  text-slate-500
                                ">

                                  End:
                                  {" "}

                                  {
                                    new Date(
                                      item.endedAt
                                    ).toLocaleTimeString()
                                  }

                                </div>

                              )

                            }

                          </div>

                        </div>

                      </div>

                    );

                  }
                )

              }

            </div>

          </div>

        )

      }

    </section>

  );

}

// =========================================================
// TIMELINE VALUE
// =========================================================

function TimelineValue({

  label,

  value,

  color,

  large = false,

}) {

  return (

    <div className="mb-5">

      <div className="
        text-slate-500
        text-xs
        mb-2
      ">

        {label}

      </div>

      <div className={`
        font-black
        ${large ? "text-4xl" : "text-xl"}
        ${color}
        break-words
      `}>

        {value}

      </div>

    </div>

  );

}

// =========================================================
// METRIC CARD
// =========================================================

function ReplayMetric({

  title,

  value,

  color,

  icon,

}) {

  return (

    <div className="
      rounded-2xl
      border
      border-cyan-500/20
      bg-[#071028]/90
      p-5
      shadow-[0_0_30px_rgba(0,229,255,0.04)]
    ">

      <div className="
        flex
        items-center
        justify-between
        mb-3
      ">

        <div className="
          text-slate-400
          text-xs
          uppercase
          tracking-wider
        ">

          {title}

        </div>

        <div className="
          text-cyan-400
        ">

          {icon}

        </div>

      </div>

      <div className={`
        text-2xl
        font-black
        ${color}
        break-words
      `}>

        {value}

      </div>

    </div>

  );

}