// src/components/riskFabric/ThreatTimeline.js

import React, {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Activity,
  ShieldAlert,
  Radar,
  Clock3,
  AlertTriangle,
  CheckCircle2,
} from "lucide-react";

// =========================================================
// PHASE HELPERS
// =========================================================

const PHASES = [

  {
    key: "baseline",
    label: "Baseline",
    color:
      "from-green-500/20 to-green-500/5",
    border:
      "border-green-500/30",
    icon:
      <CheckCircle2
        size={16}
        className="text-green-400"
      />,
  },

  {
    key: "recon",
    label: "Recon",
    color:
      "from-yellow-500/20 to-yellow-500/5",
    border:
      "border-yellow-500/30",
    icon:
      <Radar
        size={16}
        className="text-yellow-300"
      />,
  },

  {
    key: "escalation",
    label: "Escalation",
    color:
      "from-orange-500/20 to-orange-500/5",
    border:
      "border-orange-500/30",
    icon:
      <Activity
        size={16}
        className="text-orange-400"
      />,
  },

  {
    key: "attack",
    label: "Attack",
    color:
      "from-red-500/20 to-red-500/5",
    border:
      "border-red-500/30",
    icon:
      <ShieldAlert
        size={16}
        className="text-red-400"
      />,
  },

  {
    key: "cooldown",
    label: "Cooldown",
    color:
      "from-cyan-500/20 to-cyan-500/5",
    border:
      "border-cyan-500/30",
    icon:
      <Clock3
        size={16}
        className="text-cyan-400"
      />,
  },

];

// =========================================================
// MOCK TIMELINE
// =========================================================

const buildTimeline =
  () => [

    {
      phase: "baseline",
      start: 0,
      end: 20,
      risk: 8,
      events: 12,
    },

    {
      phase: "recon",
      start: 21,
      end: 40,
      risk: 28,
      events: 84,
    },

    {
      phase: "escalation",
      start: 41,
      end: 58,
      risk: 56,
      events: 210,
    },

    {
      phase: "attack",
      start: 59,
      end: 90,
      risk: 92,
      events: 1442,
    },

    {
      phase: "cooldown",
      start: 91,
      end: 120,
      risk: 34,
      events: 63,
    },

  ];

// =========================================================
// COMPONENT
// =========================================================

export default function ThreatTimeline() {

  const [timeline, setTimeline] =
    useState([]);

  // =====================================================
  // LOAD TIMELINE
  // =====================================================

  useEffect(() => {

    // later:
    // websocket
    // replay orchestrator
    // injectionStart
    // attackStartEffective
    // copilotCore
    // behaviorSummary

    setTimeline(
      buildTimeline()
    );

  }, []);

  // =====================================================
  // CURRENT PHASE
  // =====================================================

  const currentPhase =
    useMemo(() => {

      if (!timeline.length) {
        return null;
      }

      return timeline.find(
        (t) =>
          t.phase === "attack"
      );

    }, [timeline]);

  // =====================================================
  // UI
  // =====================================================

  return (

    <section className="
      relative
      z-10
      px-4
      md:px-8
      pb-10
    ">

      {/* ===================================== */}
      {/* HEADER */}
      {/* ===================================== */}

      <div className="
        flex
        items-center
        justify-between
        mb-6
      ">

        <div>

          <h2 className="
            text-2xl
            font-black
            text-white
            mb-2
          ">
            Threat Timeline
          </h2>

          <p className="
            text-slate-400
            text-sm
            max-w-3xl
          ">
            Deterministic attack lifecycle
            visualization showing behavioral
            escalation, replay alignment,
            telemetry progression,
            and operational attack phases.
          </p>

        </div>

        <div className="
          flex
          items-center
          gap-2
          px-3
          py-2
          rounded-xl
          bg-red-500/10
          border
          border-red-500/20
          text-red-300
          text-xs
          font-bold
          uppercase
          tracking-wider
        ">

          <AlertTriangle
            size={14}
          />

          Attack Lifecycle

        </div>

      </div>

      {/* ===================================== */}
      {/* TIMELINE */}
      {/* ===================================== */}

      <div className="
        relative
        overflow-hidden
        rounded-3xl
        border
        border-cyan-500/20
        bg-[#071028]/90
        shadow-[0_0_60px_rgba(0,255,255,0.06)]
      ">

        {/* ================================= */}
        {/* TOP BAR */}
        {/* ================================= */}

        <div className="
          px-6
          py-5
          border-b
          border-white/5
          flex
          items-center
          justify-between
        ">

          <div>

            <div className="
              text-xs
              uppercase
              tracking-[0.3em]
              text-slate-500
              mb-2
            ">
              Live Replay State
            </div>

            <div className="
              text-2xl
              font-black
              text-white
            ">

              {
                currentPhase
                  ?.phase
              }

            </div>

          </div>

          <div className="
            text-right
          ">

            <div className="
              text-xs
              text-slate-500
              mb-2
            ">
              Active Risk
            </div>

            <div className="
              text-3xl
              font-black
              text-red-400
            ">
              {
                currentPhase
                  ?.risk || 0
              }
            </div>

          </div>

        </div>

        {/* ================================= */}
        {/* PHASES */}
        {/* ================================= */}

        <div className="
          grid
          grid-cols-1
          xl:grid-cols-5
        ">

          {timeline.map(
            (
              item,
              index
            ) => {

              const phaseConfig =
                PHASES.find(
                  (p) =>
                    p.key ===
                    item.phase
                );

              return (

                <div
                  key={index}
                  className={`
                    relative
                    overflow-hidden
                    border-r
                    border-white/5
                    bg-gradient-to-b
                    ${phaseConfig?.color}
                  `}
                >

                  {/* GLOW */}

                  <div className="
                    absolute
                    inset-0
                    pointer-events-none
                  ">

                    <div className="
                      absolute
                      top-0
                      right-0
                      w-32
                      h-32
                      rounded-full
                      bg-white/5
                      blur-3xl
                    " />

                  </div>

                  {/* CONTENT */}

                  <div className="
                    relative
                    z-10
                    p-6
                    h-full
                    min-h-[260px]
                    flex
                    flex-col
                  ">

                    {/* HEADER */}

                    <div className="
                      flex
                      items-center
                      justify-between
                      mb-5
                    ">

                      <div className="
                        flex
                        items-center
                        gap-2
                      ">

                        {phaseConfig?.icon}

                        <div className="
                          text-white
                          font-bold
                        ">
                          {
                            phaseConfig
                              ?.label
                          }
                        </div>

                      </div>

                      <div className={`
                        px-2
                        py-1
                        rounded-md
                        border
                        text-[10px]
                        uppercase
                        tracking-wide
                        font-bold
                        ${phaseConfig?.border}
                      `}>

                        T+
                        {item.start}

                      </div>

                    </div>

                    {/* RISK */}

                    <div className="
                      mb-5
                    ">

                      <div className="
                        text-slate-400
                        text-xs
                        mb-2
                      ">
                        Risk Level
                      </div>

                      <div className="
                        text-4xl
                        font-black
                        text-white
                      ">
                        {item.risk}
                      </div>

                    </div>

                    {/* EVENTS */}

                    <div className="
                      mb-6
                    ">

                      <div className="
                        text-slate-400
                        text-xs
                        mb-2
                      ">
                        Telemetry Events
                      </div>

                      <div className="
                        text-xl
                        font-bold
                        text-cyan-300
                      ">
                        {
                          item.events
                        }
                      </div>

                    </div>

                    {/* WINDOW */}

                    <div className="
                      mt-auto
                      pt-4
                      border-t
                      border-white/5
                    ">

                      <div className="
                        text-xs
                        text-slate-500
                        leading-relaxed
                      ">

                        Timeline Window

                      </div>

                      <div className="
                        text-sm
                        text-white
                        font-semibold
                        mt-1
                      ">

                        Minute
                        {" "}
                        {item.start}
                        {" "}
                        →
                        {" "}
                        {item.end}

                      </div>

                    </div>

                  </div>

                </div>

              );

            }
          )}

        </div>

      </div>

    </section>

  );

}