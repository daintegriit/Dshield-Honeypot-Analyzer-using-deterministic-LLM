// src/components/riskFabric/MasterRiskFabric.js

import React, {
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import * as echarts from "echarts";

import {
  Shield,
  Activity,
  TrendingUp,
  Brain,
  Radar,
} from "lucide-react";

import {
  useTelemetry,
} from "../../context/TelemetryContext";


const CHART_HEIGHT = 520;

const MAX_POINTS = 120;

// =========================================================
// HELPERS
// =========================================================

const getRiskState = (risk) => {

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

const getRiskColor = (risk) => {

  if (risk >= 85) {
    return "#ef4444";
  }

  if (risk >= 60) {
    return "#f97316";
  }

  if (risk >= 45) {
    return "#eab308";
  }

  return "#22c55e";
};

// =========================================================
// COMPONENT
// =========================================================

export default function MasterRiskFabric() {

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  const [data, setData] =
    useState([]);

  // =====================================================
  // CENTRALIZED TELEMETRY
  // =====================================================

  const {

    threatSummary,
    loading,
    stale,
    latency,
    backendHealthy,
    lastUpdated,
    refreshCount,

  } = useTelemetry();

  // =====================================================
  // CORE
  // =====================================================

  const core =
    threatSummary?.coreSummary ||
    threatSummary ||
    {};

  const reasoning =
    core?.reasoning || {};

  // =====================================================
  // LIVE RISK
  // =====================================================

  const liveRisk =
    Number(
      core?.riskScore0to100 ||
      core?.riskScore ||
      0
    );

  // =====================================================
  // SYNCHRONIZED DATA PIPELINE
  // =====================================================

  useEffect(() => {

    if (!threatSummary) {
      return;
    }

    const risk =
      Number(
        core?.riskScore0to100 ||
        core?.riskScore ||
        0
      );

    const V =
      Number(
        core?.riskComponents
          ?.volumeComponent || 0
      );

    const E =
      Number(
        core?.riskComponents
          ?.severityComponent || 0
      );

    const B =
      Number(
        core?.riskComponents
          ?.behaviorComponent || 0
      );

    const A =
      Number(
        core?.riskComponents
          ?.signalAmplifier || 0
      );

    const C =
      Number(
        core?.riskComponents
          ?.c2Bonus || 0
      );

    const I =
      Number(
        core?.riskComponents
          ?.impactBonus || 0
      );

    const K =
      Number(
        core?.riskComponents
          ?.couplingBonus || 0
      );

    const nextPoint = {

      minute:
        Date.now(),

      label:
        new Date()
          .toLocaleTimeString(),

      risk:
        Number(
          risk.toFixed(2)
        ),

      V:
        Number(V.toFixed(2)),

      E:
        Number(E.toFixed(2)),

      B:
        Number(B.toFixed(2)),

      A:
        Number(A.toFixed(2)),

      C:
        Number(C.toFixed(2)),

      I:
        Number(I.toFixed(2)),

      K:
        Number(K.toFixed(2)),

      attackDetected:
        reasoning?.attackDetected === true,

      attackType:
        reasoning?.dominantAttackType ||
        "unknown",
    };

    setData((prev) => {

      const updated = [
        ...prev,
        nextPoint,
      ];

      if (
        updated.length >
        MAX_POINTS
      ) {
        updated.shift();
      }

      return updated;

    });

  }, [
    threatSummary,
  ]);

  // =====================================================
  // STATUS
  // =====================================================

  const currentState =
    useMemo(() => {

      return getRiskState(
        liveRisk
      );

    }, [liveRisk]);

  const currentColor =
    useMemo(() => {

      return getRiskColor(
        liveRisk
      );

    }, [liveRisk]);

  // =====================================================
  // ATTACK WINDOWS
  // =====================================================

  const attackWindows =
    useMemo(() => {

      const windows = [];

      let start = null;

      data.forEach(
        (point, idx) => {

          if (
            point.attackDetected &&
            start === null
          ) {
            start = idx;
          }

          if (
            !point.attackDetected &&
            start !== null
          ) {

            windows.push([
              {
                xAxis: start,
              },
              {
                xAxis: idx,
              },
            ]);

            start = null;
          }
        }
      );

      if (start !== null) {

        windows.push([
          {
            xAxis: start,
          },
          {
            xAxis:
              data.length - 1,
          },
        ]);
      }

      return windows;

    }, [data]);

  // =====================================================
  // ECHARTS
  // =====================================================

  useEffect(() => {

    if (
      !chartRef.current ||
      !data.length
    ) {
      return;
    }

    if (
      !chartInstanceRef.current
    ) {

      chartInstanceRef.current =
        echarts.init(
          chartRef.current,
          null,
          {
            renderer: "canvas",
          }
        );
    }

    const chart =
      chartInstanceRef.current;

    const option = {

      backgroundColor:
        "transparent",

      animation: false,

      tooltip: {

        trigger: "axis",

        backgroundColor:
          "#071028",

        borderColor:
          "rgba(0,229,255,0.25)",

        borderWidth: 1,

        textStyle: {
          color: "#fff",
        },

        formatter: (params) => {

          const p = params?.[0];

          if (!p) {
            return "";
          }

          const item =
            data[p.dataIndex];

          return `
            <div style="
              min-width:240px;
              padding:12px;
            ">

              <div style="
                color:#67e8f9;
                font-size:12px;
                margin-bottom:8px;
              ">
                ${item.label}
              </div>

              <div style="
                font-size:22px;
                font-weight:800;
                color:${getRiskColor(item.risk)};
                margin-bottom:4px;
              ">
                ${item.risk}
              </div>

              <div style="
                color:${getRiskColor(item.risk)};
                font-size:11px;
                margin-bottom:10px;
                font-weight:700;
              ">
                ${getRiskState(item.risk)}
              </div>

              <div style="
                margin-bottom:10px;
                color:#cbd5e1;
                font-size:11px;
              ">
                Attack Type:
                <b>${item.attackType}</b>
              </div>

            </div>
          `;
        },
      },

      grid: {

        left: 45,
        right: 30,
        top: 40,
        bottom: 45,
      },

      xAxis: {

        type: "category",

        boundaryGap: false,

        data: data.map(
          (d) => d.label
        ),

        axisLine: {

          lineStyle: {
            color: "#334155",
          },
        },

        axisLabel: {

          color: "#94a3b8",

          formatter: (v) =>
            v?.split?.(":")
              ?.slice(0, 2)
              ?.join?.(":"),
        },

        splitLine: {
          show: false,
        },
      },

      yAxis: {

        type: "value",

        min: 0,
        max: 100,

        axisLine: {

          lineStyle: {
            color: "#334155",
          },
        },

        axisLabel: {
          color: "#94a3b8",
        },

        splitLine: {

          lineStyle: {
            color:
              "rgba(255,255,255,0.06)",
          },
        },
      },

      series: [

        {
          type: "line",

          markArea: {

            silent: true,

            itemStyle: {

              color:
                "rgba(239,68,68,0.08)",
            },

            data: attackWindows,
          },

          data: [],
        },

        {
          name: "Risk",

          type: "line",

          smooth: true,

          showSymbol: false,

          sampling: "lttb",

          data: data.map(
            (d) => d.risk
          ),

          lineStyle: {

            width: 4,

            color: "#00e5ff",

            shadowBlur: 18,

            shadowColor:
              "rgba(0,229,255,0.45)",
          },

          areaStyle: {

            color:
              new echarts.graphic.LinearGradient(
                0,
                0,
                0,
                1,
                [
                  {
                    offset: 0,

                    color:
                      "rgba(0,229,255,0.55)",
                  },

                  {
                    offset: 1,

                    color:
                      "rgba(0,229,255,0)",
                  },
                ]
              ),
          },

          markLine: {

            silent: true,

            symbol: "none",

            lineStyle: {
              type: "dashed",
            },

            data: [

              {
                yAxis: 45,

                lineStyle: {
                  color: "#eab308",
                },
              },

              {
                yAxis: 60,

                lineStyle: {
                  color: "#f97316",
                },
              },

              {
                yAxis: 85,

                lineStyle: {
                  color: "#ef4444",
                },
              },
            ],
          },
        },
      ],
    };

    chart.setOption(
      option,
      {
        notMerge: true,
        lazyUpdate: true,
      }
    );

    const resizeHandler =
      () => {

        if (
          chartInstanceRef.current
        ) {

          chartInstanceRef.current.resize({
            animation: false,
          });
        }
      };

    window.addEventListener(
      "resize",
      resizeHandler
    );

    return () => {

      window.removeEventListener(
        "resize",
        resizeHandler
      );
    };

  }, [data, attackWindows]);

  // =====================================================
  // DESTROY
  // =====================================================

  useEffect(() => {

    return () => {

      if (
        chartInstanceRef.current
      ) {

        chartInstanceRef.current.dispose();

        chartInstanceRef.current =
          null;
      }
    };

  }, []);

  // =====================================================
  // UI
  // =====================================================

  return (

    <section className="
      relative
      min-h-screen
      bg-black
      text-white
      overflow-x-hidden
    ">

      <div className="
        relative
        z-10
        px-4
        md:px-8
        py-10
      ">

        {/* HEADER */}

        <div className="mb-10">

          <div className="
            flex
            items-center
            gap-3
            mb-4
          ">

            <Shield
              className="
                text-cyan-400
              "
              size={32}
            />

            <h1 className="
              text-4xl
              md:text-5xl
              font-black
              text-white
            ">
              CHIRON RISK FABRIC
            </h1>

          </div>

          <p className="
            text-slate-400
            max-w-4xl
            leading-relaxed
            text-lg
          ">
            Real-time deterministic
            telemetry fusion powered by
            the centralized telemetry engine.
          </p>

        </div>

        {/* STATUS CARDS */}

        <div className="
          grid
          grid-cols-1
          md:grid-cols-2
          xl:grid-cols-4
          gap-5
          mb-10
        ">

          <StatusCard
            title="Operational State"
            value={currentState}
            color={currentColor}
            icon={
              <Shield
                className="text-cyan-400"
                size={18}
              />
            }
          />

          <StatusCard
            title="Risk Score"
            value={liveRisk.toFixed(2)}
            color={currentColor}
            icon={
              <Activity
                className="text-cyan-400"
                size={18}
              />
            }
          />

          <StatusCard
            title="Attack Type"
            value={
              (
                reasoning?.dominantAttackType ||
                "unknown"
              ).toUpperCase()
            }
            color="#67e8f9"
            icon={
              <Radar
                className="text-cyan-400"
                size={18}
              />
            }
          />

          <StatusCard
            title="Telemetry"
            value={
              loading
                ? "SYNCING"
                : stale
                ? "STALE"
                : backendHealthy
                ? "LIVE"
                : "OFFLINE"
            }
            color={
              backendHealthy
                ? "#22c55e"
                : "#ef4444"
            }
            icon={
              <Brain
                className="text-cyan-400"
                size={18}
              />
            }
          />

        </div>

        {/* GRAPH */}

        <div className="
          bg-[#071028]/90
          border
          border-cyan-500/20
          rounded-3xl
          p-6
          md:p-8
          shadow-[0_0_60px_rgba(0,255,255,0.08)]
        ">

          <div className="
            flex
            items-center
            justify-between
            gap-4
            mb-8
            flex-wrap
          ">

            <div className="
              flex
              items-center
              gap-3
            ">

              <TrendingUp
                className="
                  text-cyan-400
                "
                size={24}
              />

              <div>

                <h2 className="
                  text-2xl
                  font-black
                  text-white
                ">
                  LIVE MASTER RISK GRAPH
                </h2>

                <p className="
                  text-slate-400
                ">
                  Centralized synchronized telemetry
                </p>

              </div>

            </div>

            <div className="
              flex
              items-center
              gap-4
              text-xs
              text-slate-400
            ">

              <div>
                Refresh:
                <span className="
                  ml-2
                  text-cyan-300
                  font-bold
                ">
                  {refreshCount}
                </span>
              </div>

              <div>
                Latency:
                <span className="
                  ml-2
                  text-cyan-300
                  font-bold
                ">
                  {latency}ms
                </span>
              </div>

              <div>
                Updated:
                <span className="
                  ml-2
                  text-cyan-300
                  font-bold
                ">
                  {
                    lastUpdated
                      ? new Date(
                          lastUpdated
                        ).toLocaleTimeString()
                      : "--"
                  }
                </span>
              </div>

            </div>

          </div>

          <div
            style={{
              height: CHART_HEIGHT,
            }}
            className="
              relative
              w-full
            "
          >

            <div
              ref={chartRef}
              className="
                absolute
                inset-0
              "
            />

          </div>

        </div>

      </div>

    </section>

  );

}

// =========================================================
// STATUS CARD
// =========================================================

function StatusCard({
  title,
  value,
  color,
  icon,
}) {

  return (

    <div className="
      bg-[#071028]/90
      border
      border-cyan-500/20
      rounded-2xl
      p-5
    ">

      <div className="
        flex
        items-center
        justify-between
        mb-3
      ">

        <div className="
          text-slate-400
          text-sm
        ">
          {title}
        </div>

        {icon}

      </div>

      <div
        className="
          text-3xl
          font-black
          break-words
        "
        style={{
          color,
        }}
      >
        {value}
      </div>

    </div>

  );

}