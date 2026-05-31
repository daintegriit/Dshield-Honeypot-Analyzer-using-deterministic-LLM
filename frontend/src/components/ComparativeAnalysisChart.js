import React, {
  useEffect,
  useRef,
  useMemo,
} from "react";

import * as echarts from "echarts";

import {
  useTelemetry,
} from "../context/TelemetryContext";

const ComparativeAnalysisChart = () => {

  // ====================================================
  // REFS
  // ====================================================

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  const resizeObserverRef =
    useRef(null);

  // ====================================================
  // TELEMETRY
  // ====================================================

  const {
    comparative,
    loading,
    stale,
    endpointHealth,
  } = useTelemetry();

  // ====================================================
  // NORMALIZE
  // ====================================================

  const rows =
    useMemo(
      () =>
        Array.isArray(
          comparative
        )
          ? comparative
          : [],
      [comparative]
    );

  // ====================================================
  // BUILD WINDOWS
  // ====================================================

  const {
    metrics,
    previousWindow,
    currentWindow,
    deltas,
    totalDelta,
    peakDelta,
    averageCurrent,
    averagePrevious,
  } = useMemo(() => {

    if (!rows.length) {

      return {

        metrics: [],

        previousWindow: [],

        currentWindow: [],

        deltas: [],

        totalDelta: 0,

        peakDelta: 0,

        averageCurrent: 0,

        averagePrevious: 0,
      };
    }

    const sorted =
      [...rows]

        .filter(
          (r) =>
            r.timestamp &&
            !Number.isNaN(
              new Date(
                r.timestamp
              ).getTime()
            )
        )

        .sort(
          (a, b) =>
            new Date(
              a.timestamp
            ).getTime() -
            new Date(
              b.timestamp
            ).getTime()
        )

        .slice(-10);

    const metrics =
      sorted.map((r) => {

        const d =
          new Date(
            r.timestamp
          );

        return `${String(
          d.getHours()
        ).padStart(2, "0")}:${String(
          d.getMinutes()
        ).padStart(2, "0")}`;
      });

    const previousWindow =
      sorted.map(
        (r) =>
          Number(
            r.previous || 0
          )
      );

    const currentWindow =
      sorted.map(
        (r) =>
          Number(
            r.current || 0
          )
      );

    const deltas =
      currentWindow.map(
        (v, i) => {

          const prev =
            previousWindow[i];

          if (prev === 0) {

            return v > 0
              ? 100
              : 0;
          }

          return Number(
            (
              (
                (
                  v - prev
                ) / prev
              ) * 100
            ).toFixed(1)
          );
        }
      );

    const totalPrev =
      previousWindow.reduce(
        (a, b) => a + b,
        0
      );

    const totalCurr =
      currentWindow.reduce(
        (a, b) => a + b,
        0
      );

    const totalDelta =
      totalPrev === 0
        ? totalCurr > 0
          ? 100
          : 0
        : Number(
            (
              (
                (
                  totalCurr -
                  totalPrev
                ) / totalPrev
              ) * 100
            ).toFixed(1)
          );

    const normalizedDeltas =
      deltas.map((d) =>
        Math.min(
          Math.abs(d),
          100
        )
      );

    const peakDelta =
      Math.max(
        ...normalizedDeltas,
        0
      );

    const averageCurrent =
      currentWindow.length
        ? Math.round(
            totalCurr /
            currentWindow.length
          )
        : 0;

    const averagePrevious =
      previousWindow.length
        ? Math.round(
            totalPrev /
            previousWindow.length
          )
        : 0;

    return {

      metrics,

      previousWindow,

      currentWindow,

      deltas,

      totalDelta,

      peakDelta,

      averageCurrent,

      averagePrevious,
    };

  }, [rows]);

  // ====================================================
  // INIT CHART
  // ====================================================

  useEffect(() => {

    if (
      !chartRef.current
    ) {
      return;
    }

    if (
      chartInstanceRef.current
    ) {
      return;
    }

    const chart =
      echarts.init(
        chartRef.current,
        null,
        {
          renderer:
            "canvas",

          useDirtyRect:
            true,
        }
      );

    chartInstanceRef.current =
      chart;

    const timeout =
      setTimeout(
        () => {

          chart.resize();

        },
        120
      );

    return () => {

      clearTimeout(
        timeout
      );
    };

  }, []);

  // ====================================================
  // UPDATE CHART
  // ====================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (!chart) {
      return;
    }

    // ==================================================
    // EMPTY
    // ==================================================

    if (!metrics.length) {

      chart.clear();

      chart.setOption(
        {

          backgroundColor:
            "transparent",

          graphic: [

            {
              type: "text",

              left: "center",

              top: "middle",

              silent: true,

              style: {

                text:
                  loading
                    ? "Loading comparative telemetry..."
                    : stale
                    ? "Comparative telemetry stale..."
                    : endpointHealth?.comparative === false
                    ? "Comparative endpoint unavailable"
                    : "Waiting for comparative telemetry...",

                fill:
                  stale
                    ? "#facc15"
                    : "#64748b",

                fontSize: 12,

                fontWeight: 500,
              },
            },
          ],

          xAxis: {
            show: false,
          },

          yAxis: {
            show: false,
          },

          series: [],
        },
        true
      );

      chart.resize();

      return;
    }

    // ==================================================
    // OPTION
    // ==================================================

    const option = {

      backgroundColor:
        "transparent",

      animation: true,

      animationDuration:
        500,

      animationEasing:
        "cubicOut",

      tooltip: {

        trigger: "axis",

        axisPointer: {
          type: "line",
        },

        backgroundColor:
          "#0f172a",

        borderColor:
          "#334155",

        borderWidth: 1,

        textStyle: {
          color: "#fff",
        },

        formatter:
          (params) => {

            const prev =
              params.find(
                (p) =>
                  p.seriesName ===
                  "Previous"
              );

            const curr =
              params.find(
                (p) =>
                  p.seriesName ===
                  "Current"
              );

            if (
              !prev ||
              !curr
            ) {
              return "";
            }

            const delta =
              deltas[
                curr.dataIndex
              ] ?? 0;

            const deltaColor =
              delta > 0
                ? "#ff5252"
                : delta < 0
                ? "#00e676"
                : "#4fc3f7";

            return `
              <div style="
                padding:10px;
                min-width:220px;
              ">

                <div style="
                  font-weight:bold;
                  margin-bottom:8px;
                  color:#ffffff;
                ">
                  ${curr.name}
                </div>

                <div>
                  Previous:
                  <span style="
                    color:#94a3b8;
                    margin-left:6px;
                    font-weight:bold;
                  ">
                    ${Number(
                      prev.value || 0
                    ).toLocaleString()}
                  </span>
                </div>

                <div>
                  Current:
                  <span style="
                    color:#38bdf8;
                    margin-left:6px;
                    font-weight:bold;
                  ">
                    ${Number(
                      curr.value || 0
                    ).toLocaleString()}
                  </span>
                </div>

                <div style="
                  margin-top:8px;
                  color:${deltaColor};
                  font-weight:bold;
                ">
                  Delta:
                  ${delta > 0 ? "+" : ""}
                  ${delta}%
                </div>

              </div>
            `;
          },
      },

      legend: {

        top: 0,

        right: 0,

        itemWidth: 10,

        itemHeight: 10,

        textStyle: {

          color:
            "#cbd5e1",

          fontSize: 10,
        },

        data: [
          "Previous",
          "Current",
        ],
      },

      grid: {

        top: 34,

        left: 42,

        right: 12,

        bottom: 28,
      },

      xAxis: {

        type: "category",

        data: metrics,

        boundaryGap: false,

        axisLine: {

          lineStyle: {
            color:
              "#334155",
          },
        },

        axisLabel: {

          color:
            "#94a3b8",

          fontSize: 9,
        },

        axisTick: {
          show: false,
        },
      },

      yAxis: {

        type: "value",

        axisLabel: {

          color:
            "#64748b",

          fontSize: 9,

          formatter:
            (v) => {

              if (
                v >= 1_000_000
              ) {

                return `${(
                  v / 1_000_000
                ).toFixed(1)}M`;
              }

              if (
                v >= 1_000
              ) {

                return `${(
                  v / 1_000
                ).toFixed(1)}K`;
              }

              return v;
            },
        },

        splitLine: {

          lineStyle: {

            color:
              "rgba(255,255,255,0.04)",
          },
        },

        axisLine: {
          show: false,
        },
      },

      series: [

        // ==========================================
        // PREVIOUS
        // ==========================================

        {
          name: "Previous",

          type: "line",

          smooth: 0.22,

          showSymbol: false,

          data:
            previousWindow,

          lineStyle: {

            width: 2,

            color:
              "rgba(148,163,184,0.7)",
          },

          areaStyle: {

            color:
              "rgba(148,163,184,0.05)",
          },
        },

        // ==========================================
        // CURRENT
        // ==========================================

        {
          name: "Current",

          type: "line",

          smooth: 0.22,

          symbol: "circle",

          symbolSize: 5,

          data:
            currentWindow,

          lineStyle: {

            width: 3,

            color:
              "#38bdf8",
          },

          areaStyle: {

            color:
              "rgba(56,189,248,0.12)",
          },

          itemStyle: {

            color:
              "#38bdf8",

            borderColor:
              "#ffffff",

            borderWidth: 1,
          },

          emphasis: {

            focus:
              "series",
          },

          markPoint: {

            symbol:
              "circle",

            symbolSize: 8,

            data: [

              {
                type: "max",
                name: "Peak",
              },
            ],

            itemStyle: {

              color:
                "#ff5252",

              borderColor:
                "#ffffff",

              borderWidth: 1,
            },

            label: {

              show: true,

              position: [-4, -24],

              color:
                "#ffffff",

              fontSize: 9,

              fontWeight:
                "bold",

              backgroundColor:
                "rgba(15,23,42,0.95)",

              borderRadius: 4,

              padding: [
                3,
                5,
              ],

              formatter:
                (params) => {

                  const val =
                    Number(
                      params.value || 0
                    );

                  return `Peak ${val.toLocaleString()}`;
                },
            },
          },
        },
      ],
    };

    chart.clear();

    chart.setOption(
      option,
      true
    );

    chart.resize();

  }, [
    metrics,
    previousWindow,
    currentWindow,
    deltas,
    loading,
    stale,
    endpointHealth,
  ]);

  // ====================================================
  // RESIZE
  // ====================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (
      !chart ||
      !chartRef.current
    ) {
      return;
    }

    const resize =
      () => {

        chart.resize();
      };

    resizeObserverRef.current?.disconnect();

    resizeObserverRef.current =
      new ResizeObserver(
        resize
      );

    resizeObserverRef.current.observe(
      chartRef.current
    );

    window.addEventListener(
      "resize",
      resize
    );

    const timeout =
      setTimeout(
        resize,
        200
      );

    return () => {

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      window.removeEventListener(
        "resize",
        resize
      );

      clearTimeout(
        timeout
      );
    };

  }, []);

  // ====================================================
  // CLEANUP
  // ====================================================

  useEffect(() => {

    return () => {

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      if (
        chartInstanceRef.current
      ) {

        chartInstanceRef.current.dispose();

        chartInstanceRef.current =
          null;
      }
    };

  }, []);

  // ====================================================
  // HEADER METRICS
  // ====================================================

  const trendColor =
    totalDelta > 40
      ? "text-red-400"
      : totalDelta > 15
      ? "text-orange-300"
      : totalDelta > 0
      ? "text-yellow-300"
      : "text-green-400";

  const trendText =
    totalDelta > 0
      ? `Attack Activity Increased +${totalDelta}%`
      : `Attack Activity Decreased ${Math.abs(
          totalDelta
        )}%`;

  // ====================================================
  // RENDER
  // ====================================================

  return (

    <div className="
      w-full
      h-full
      flex
      flex-col
      overflow-hidden
      min-h-0
    ">

      {/* ============================================== */}
      {/* HEADER */}
      {/* ============================================== */}

      <div className="
        flex
        items-center
        justify-between
        text-[10px]
        mb-2
        shrink-0
        gap-2
      ">

        <div className="
          flex
          flex-col
          min-w-0
        ">

          <div className={`
            font-semibold
            truncate
            ${trendColor}
          `}>
            {trendText}
          </div>

          <div className="
            text-[9px]
            text-gray-500
            truncate
          ">
            Avg Current:
            {" "}
            {averageCurrent.toLocaleString()}
            {"  •  "}
            Avg Previous:
            {" "}
            {averagePrevious.toLocaleString()}
          </div>

        </div>

        <div className="
          text-gray-400
          whitespace-nowrap
          text-right
          shrink-0
        ">

          <div>
            Peak Surge:
            {" "}
            {peakDelta}%
          </div>

          <div className="
            text-[9px]
            text-gray-500
          ">
            Live Delta
          </div>

        </div>

      </div>

      {/* ============================================== */}
      {/* CHART */}
      {/* ============================================== */}

      <div
        ref={chartRef}
        className="
          flex-1
          w-full
          min-h-0
        "
      />

    </div>
  );
};

export default ComparativeAnalysisChart;