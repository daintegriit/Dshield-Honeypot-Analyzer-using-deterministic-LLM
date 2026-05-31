import React, {
  useState,
  useMemo
} from "react";

import ThreeJSGlobe
from "./ThreeDGlobe";

import RealTimeThreatMap
from "./RealTimeThreatMap";

import {
  Globe,
  Map,
  Activity,
  Shield,
  Wifi,
  AlertTriangle,
  CheckCircle2
} from "lucide-react";

import {
  useTelemetry
} from "../context/TelemetryContext";

const ThreatVisualization = () => {

  // ====================================================
  // 🔥 STATE
  // ====================================================

  const [view,
    setView] =
      useState("globe");

  // ====================================================
  // TELEMETRY
  // ====================================================

  const {

    geo,

    loading,

    stale,

    backendHealthy,

    latency

  } = useTelemetry();

  // ====================================================
  // 🔥 METRICS
  // ====================================================

  const {

    totalEvents,

    countries,

    topCountry

  } = useMemo(() => {

    const totalEvents =
      geo.reduce(
        (sum, item) =>
          sum +
          Number(
            item.count || 0
          ),
        0
      );

    const uniqueCountries =
      new Set(
        geo
          .map(
            (g) =>
              g.country
          )
          .filter(Boolean)
      );

    const sorted =
      [...geo].sort(
        (a, b) =>
          Number(
            b.count || 0
          ) -
          Number(
            a.count || 0
          )
      );

    return {

      totalEvents,

      countries:
        uniqueCountries.size,

      topCountry:
        sorted[0]
          ?.country ||
        "Unknown",

    };

  }, [geo]);

  // ====================================================
  // 🔥 STATUS
  // ====================================================

  let statusText =
    "ONLINE";

  let statusColor =
    "text-green-400";

  let statusBorder =
    "border-green-500/30";

  let statusIcon =
    <CheckCircle2
      size={9}
    />;

  if (!backendHealthy) {

    statusText =
      "OFFLINE";

    statusColor =
      "text-red-400";

    statusBorder =
      "border-red-500/30";

    statusIcon =
      <AlertTriangle
        size={9}
      />;

  } else if (stale) {

    statusText =
      "STALE";

    statusColor =
      "text-yellow-400";

    statusBorder =
      "border-yellow-500/30";

    statusIcon =
      <Wifi
        size={9}
      />;
  }

  // ====================================================
  // 🔥 BUTTON STYLE
  // ====================================================

  const buttonStyle =
    (active) =>
      `
        flex
        items-center
        justify-center
        gap-1
        px-2
        py-[4px]
        rounded-md
        text-[9px]
        font-semibold
        transition-all
        duration-200
        border
        ${
          active
            ? `
              bg-cyan-500/15
              text-cyan-300
              border-cyan-400/30
            `
            : `
              bg-slate-900/70
              text-slate-400
              border-slate-700
              hover:text-slate-200
            `
        }
      `;

  // ====================================================
  // 🔥 METRIC CARD
  // ====================================================

  const statCard =
    `
      rounded-md
      border
      border-cyan-500/10
      bg-[#071426]
      px-1
      py-[5px]
      backdrop-blur-md
    `;

  // ====================================================
  // RENDER
  // ====================================================

  return (

    <div className="
      relative
      w-full
      h-full
      overflow-hidden
      rounded-xl
      border
      border-slate-800
      bg-gradient-to-br
      from-slate-950
      via-[#071426]
      to-black
      flex
      flex-col
    ">

      {/* ================================================= */}
      {/* TOP BAR */}
      {/* ================================================= */}

      <div className="
        shrink-0
        flex
        items-center
        justify-between
        px-1.5
        py-1
        border-b
        border-slate-800/50
        bg-black/10
      ">

        {/* LEFT */}

        <div className="
          flex
          items-center
          gap-1
        ">

          <button
            onClick={() =>
              setView(
                "globe"
              )
            }
            className={
              buttonStyle(
                view ===
                  "globe"
              )
            }
          >

            <Globe
              size={10}
            />

            Globe

          </button>

          <button
            onClick={() =>
              setView(
                "map"
              )
            }
            className={
              buttonStyle(
                view ===
                  "map"
              )
            }
          >

            <Map
              size={10}
            />

            Map

          </button>

        </div>

        {/* RIGHT */}

        <div className={`
          flex
          items-center
          gap-1
          px-1
          py-[3px]
          rounded-md
          text-[8px]
          font-mono
          border
          bg-black/40
          ${statusColor}
          ${statusBorder}
        `}>

          {statusIcon}

          {statusText}

        </div>

      </div>

      {/* ================================================= */}
      {/* METRICS */}
      {/* ================================================= */}

      <div className="
        shrink-0
        grid
        grid-cols-4
        gap-1
        px-1.5
        py-1
        border-b
        border-slate-800/40
        bg-black/5
      ">

        {/* EVENTS */}

        <div className={statCard}>

          <div className="
            text-[6px]
            uppercase
            text-slate-500
            flex
            items-center
            gap-1
            leading-none
          ">

            <Activity
              size={6}
            />

            Events

          </div>

          <div className="
            text-cyan-300
            text-xs
            font-bold
            leading-none
            mt-1
          ">

            {totalEvents.toLocaleString()}

          </div>

        </div>

        {/* COUNTRIES */}

        <div className={statCard}>

          <div className="
            text-[6px]
            uppercase
            text-slate-500
            leading-none
          ">

            Countries

          </div>

          <div className="
            text-cyan-300
            text-xs
            font-bold
            leading-none
            mt-1
          ">

            {countries}

          </div>

        </div>

        {/* LATENCY */}

        <div className={statCard}>

          <div className="
            text-[6px]
            uppercase
            text-slate-500
            leading-none
          ">

            Latency

          </div>

          <div className="
            text-cyan-300
            text-xs
            font-bold
            leading-none
            mt-1
          ">

            {latency}ms

          </div>

        </div>

        {/* ORIGIN */}

        <div className={statCard}>

          <div className="
            text-[6px]
            uppercase
            text-slate-500
            flex
            items-center
            gap-1
            leading-none
          ">

            <Shield
              size={6}
            />

            Origin

          </div>

          <div className="
            text-cyan-300
            text-xs
            font-bold
            leading-none
            mt-1
            truncate
          ">

            {topCountry}

          </div>

        </div>

      </div>

      {/* ================================================= */}
      {/* VISUALIZATION */}
      {/* ================================================= */}

      <div className="
        relative
        flex-1
        min-h-0
        overflow-hidden
      ">

        {/* LOADING */}

        {loading && (

          <div className="
            absolute
            inset-0
            z-30
            flex
            items-center
            justify-center
            bg-black/15
            backdrop-blur-sm
            pointer-events-none
          ">

            <div className="
              flex
              flex-col
              items-center
              gap-2
            ">

              <div className="
                w-7
                h-7
                rounded-full
                border-2
                border-cyan-400/20
                border-t-cyan-400
                animate-spin
              " />

              <div className="
                text-cyan-300
                text-[9px]
                font-semibold
                tracking-widest
              ">

                INITIALIZING

              </div>

            </div>

          </div>
        )}

        {/* GLOBE */}

        <div className={`
          absolute
          inset-0
          transition-opacity
          duration-300
          ${
            view ===
            "globe"
              ? "opacity-100 z-10"
              : "opacity-0 pointer-events-none"
          }
        `}>

          <ThreeJSGlobe />

        </div>

        {/* MAP */}

        <div className={`
          absolute
          inset-0
          transition-opacity
          duration-300
          ${
            view ===
            "map"
              ? "opacity-100 z-10"
              : "opacity-0 pointer-events-none"
          }
        `}>

          <RealTimeThreatMap />

        </div>

      </div>

      {/* ================================================= */}
      {/* FOOTER */}
      {/* ================================================= */}

      <div className="
        shrink-0
        flex
        items-center
        justify-between
        px-1.5
        py-[3px]
        border-t
        border-slate-800/40
        bg-black/15
        text-[7px]
        font-mono
      ">

        <div className="
          text-slate-500
          truncate
        ">

          CHIRON GLOBAL THREAT INTELLIGENCE

        </div>

        <div className="
          text-slate-400
          ml-2
          shrink-0
        ">

          {stale
            ? "STALE"
            : "LIVE"}

        </div>

      </div>

    </div>
  );
};

export default ThreatVisualization;