// src/components/riskFabric/BehavioralSignalCard.js

import React from "react";

import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  TrendingUp,
  Radar,
  BrainCircuit,
  Wifi,
} from "lucide-react";

// =========================================================
// SEVERITY CONFIG
// =========================================================

const severityStyles = {

  stable: {

    border:
      "border-green-500/20",

    glow:
      "shadow-[0_0_30px_rgba(34,197,94,0.08)]",

    value:
      "text-green-400",

    badge:
      "bg-green-500/10 text-green-300 border border-green-500/20",

    pulse:
      "bg-green-400",

    icon:
      (
        <ShieldCheck
          size={16}
          className="
            text-green-400
          "
        />
      ),

  },

  elevated: {

    border:
      "border-yellow-500/20",

    glow:
      "shadow-[0_0_30px_rgba(234,179,8,0.08)]",

    value:
      "text-yellow-300",

    badge:
      "bg-yellow-500/10 text-yellow-200 border border-yellow-500/20",

    pulse:
      "bg-yellow-300",

    icon:
      (
        <AlertTriangle
          size={16}
          className="
            text-yellow-300
          "
        />
      ),

  },

  high: {

    border:
      "border-orange-500/20",

    glow:
      "shadow-[0_0_35px_rgba(249,115,22,0.12)]",

    value:
      "text-orange-400",

    badge:
      "bg-orange-500/10 text-orange-300 border border-orange-500/20",

    pulse:
      "bg-orange-400",

    icon:
      (
        <ShieldAlert
          size={16}
          className="
            text-orange-400
          "
        />
      ),

  },

  critical: {

    border:
      "border-red-500/20",

    glow:
      "shadow-[0_0_45px_rgba(239,68,68,0.16)]",

    value:
      "text-red-400",

    badge:
      "bg-red-500/10 text-red-300 border border-red-500/20",

    pulse:
      "bg-red-400",

    icon:
      (
        <Radar
          size={16}
          className="
            text-red-400
          "
        />
      ),

  },

};

// =========================================================
// COMPONENT
// =========================================================

export default function BehavioralSignalCard({

  title = "Unknown Signal",

  value = "0",

  subtitle =
    "No telemetry available",

  severity = "stable",

  trend = null,

  icon = null,

  live = true,

  footer =
    "Deterministic telemetry validated",

}) {

  // =====================================================
  // SAFE CONFIG
  // =====================================================

  const normalizedSeverity =
    String(severity || "stable")
      .toLowerCase();

  const config =
    severityStyles[
      normalizedSeverity
    ] ||
    severityStyles.stable;

  // =====================================================
  // UI
  // =====================================================

  return (

    <div
      className={`
        relative
        overflow-hidden
        rounded-2xl
        border
        bg-[#071028]/95
        p-5
        transition-all
        duration-300
        ${config.border}
        ${config.glow}
      `}
    >

      {/* ===================================== */}
      {/* CYBER BACKGROUND GLOW */}
      {/* ===================================== */}

      <div className="
        absolute
        inset-0
        opacity-40
        pointer-events-none
      ">

        <div className="
          absolute
          -top-10
          -right-10
          w-32
          h-32
          rounded-full
          bg-cyan-500/10
          blur-3xl
        " />

      </div>

      {/* ===================================== */}
      {/* LIVE PULSE */}
      {/* ===================================== */}

      {live && (

        <div className="
          absolute
          top-4
          right-4
          flex
          items-center
          gap-2
          z-20
        ">

          <div
            className={`
              w-2
              h-2
              rounded-full
              animate-pulse
              ${config.pulse}
            `}
          />

          <span className="
            text-[10px]
            uppercase
            tracking-wider
            text-slate-500
            font-semibold
          ">
            live
          </span>

        </div>

      )}

      {/* ===================================== */}
      {/* HEADER */}
      {/* ===================================== */}

      <div className="
        relative
        z-10
        flex
        items-start
        justify-between
        mb-5
      ">

        {/* LEFT */}

        <div className="
          pr-4
        ">

          <div className="
            text-slate-400
            text-xs
            uppercase
            tracking-[0.18em]
            mb-2
          ">
            {title}
          </div>

          <div
            className={`
              text-3xl
              font-black
              leading-none
              break-words
              ${config.value}
            `}
          >
            {value}
          </div>

        </div>

        {/* RIGHT */}

        <div className="
          flex
          items-center
          justify-center
          shrink-0
          w-11
          h-11
          rounded-xl
          bg-black/30
          border
          border-white/5
          backdrop-blur-sm
        ">

          {icon || (

            <Activity
              className="
                text-cyan-400
              "
              size={18}
            />

          )}

        </div>

      </div>

      {/* ===================================== */}
      {/* SUBTITLE */}
      {/* ===================================== */}

      <div className="
        relative
        z-10
        text-slate-400
        text-xs
        leading-relaxed
        min-h-[42px]
        mb-5
      ">

        {subtitle}

      </div>

      {/* ===================================== */}
      {/* TELEMETRY BAR */}
      {/* ===================================== */}

      <div className="
        relative
        z-10
        flex
        items-center
        justify-between
        gap-3
      ">

        {/* LEFT */}

        <div className="
          flex
          items-center
          gap-2
          text-[11px]
          text-slate-500
        ">

          <Wifi
            size={12}
          />

          Telemetry Active

        </div>

        {/* RIGHT */}

        <div
          className={`
            shrink-0
            px-2.5
            py-1
            rounded-md
            text-[10px]
            font-bold
            uppercase
            tracking-wide
            ${config.badge}
          `}
        >

          {trend ? (

            <div className="
              flex
              items-center
              gap-1
            ">

              <TrendingUp
                size={10}
              />

              {trend}

            </div>

          ) : (

            normalizedSeverity

          )}

        </div>

      </div>

      {/* ===================================== */}
      {/* GOVERNANCE STRIP */}
      {/* ===================================== */}

      <div className="
        relative
        z-10
        mt-5
        pt-4
        border-t
        border-white/5
        flex
        items-center
        justify-between
        gap-2
      ">

        <div className="
          flex
          items-center
          gap-2
          text-[11px]
          text-slate-500
        ">

          <BrainCircuit
            size={12}
          />

          {footer}

        </div>

        <div>

          {config.icon}

        </div>

      </div>

    </div>

  );

}