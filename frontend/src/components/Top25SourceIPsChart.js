import React, {
  useEffect,
  useMemo,
  useRef,
  useState,
  useCallback,
} from "react";

import * as echarts from "echarts";

import {
  useTelemetry,
} from "../context/TelemetryContext";

import apiService from "../services/apiService";

const MAX_POINTS = 10;

const CHART_HEIGHT = 260;

const Top25SourceIPsChart = () => {

  // ====================================================
  // TELEMETRY
  // ====================================================

  const {
    topIPs,
    lastUpdated,
  } = useTelemetry();

  // ====================================================
  // REFS
  // ====================================================

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  const resizeObserverRef =
    useRef(null);

  const resizeFrameRef =
    useRef(null);

  const prevCountsRef =
    useRef({});

  // ====================================================
  // STATE
  // ====================================================

  const [
    selectedIP,
    setSelectedIP,
  ] = useState(null);

  const [
    drillDownData,
    setDrillDownData,
  ] = useState(null);

  // ====================================================
  // HELPERS
  // ====================================================

  const formatCompactIP =
    useCallback((ip = "") => {

      const parts =
        ip.split(".");

      if (
        parts.length !== 4
      ) {
        return ip;
      }

      if (
        ip.startsWith(
          "192.168."
        )
      ) {

        return `192.168.${parts[2]}.${parts[3]}`;
      }

      return `${parts[0]}.${parts[1]}…${parts[3]}`;

    }, []);

  const getSeverityGradient =
    useCallback(
      (
        value,
        max
      ) => {

        const pct =
          max
            ? value / max
            : 0;

        if (pct >= 0.8) {

          return new echarts.graphic.LinearGradient(
            1,
            0,
            0,
            0,
            [

              {
                offset: 0,
                color:
                  "#ff4d4d",
              },

              {
                offset: 1,
                color:
                  "#ff7b72",
              },
            ]
          );
        }

        if (pct >= 0.55) {

          return new echarts.graphic.LinearGradient(
            1,
            0,
            0,
            0,
            [

              {
                offset: 0,
                color:
                  "#ff8c42",
              },

              {
                offset: 1,
                color:
                  "#ffb86b",
              },
            ]
          );
        }

        if (pct >= 0.25) {

          return new echarts.graphic.LinearGradient(
            1,
            0,
            0,
            0,
            [

              {
                offset: 0,
                color:
                  "#38bdf8",
              },

              {
                offset: 1,
                color:
                  "#7dd3fc",
              },
            ]
          );
        }

        return new echarts.graphic.LinearGradient(
          1,
          0,
          0,
          0,
          [

            {
              offset: 0,
              color:
                "#22c55e",
            },

            {
              offset: 1,
              color:
                "#4ade80",
            },
          ]
        );

      },
      []
    );

  // ====================================================
  // NORMALIZE
  // ====================================================

  const ipData =
    useMemo(() => {

      const raw =
        Array.isArray(
          topIPs
        )
          ? topIPs.slice(
              0,
              MAX_POINTS
            )
          : [];

      const prev =
        prevCountsRef.current;

      const normalized =
        raw

          .map((item) => {

            const sourceIP =
              item.sourceIP ??
              item.source_ip ??
              item.ip ??
              item._id ??
              "Unknown";

            const count =
              Number(
                item.count ??
                item.total ??
                item.value ??
                item.attacks ??
                0
              );

            const previous =
              prev[
                sourceIP
              ] ?? 0;

            return {

              sourceIP,

              count,

              logValue:
                Math.log10(
                  count + 1
                ),

              shortLabel:
                formatCompactIP(
                  sourceIP
                ),

              changePct:
                previous > 0
                  ? Number(
                      (
                        (
                          (
                            count -
                            previous
                          ) /
                          previous
                        ) * 100
                      ).toFixed(1)
                    )
                  : null,
            };

          })

          .filter(
            (r) =>
              r.count > 0
          )

          .sort(
            (a, b) =>
              b.count -
              a.count
          );

      prevCountsRef.current =
        normalized.reduce(
          (acc, row) => {

            acc[
              row.sourceIP
            ] = row.count;

            return acc;

          },
          {}
        );

      return normalized;

    }, [
      topIPs,
      formatCompactIP,
    ]);

  // ====================================================
  // TOTALS
  // ====================================================

  const totalTraffic =
    useMemo(
      () =>
        ipData.reduce(
          (sum, row) =>
            sum +
            row.count,
          0
        ),
      [ipData]
    );

  const maxTraffic =
    useMemo(
      () =>
        Math.max(
          ...ipData.map(
            (r) =>
              r.count
          ),
          0
        ),
      [ipData]
    );

  // ====================================================
  // DRILLDOWN
  // ====================================================

  const fetchDrillDownData =
    useCallback(
      async (ip) => {

        try {

          const data =
            await apiService.getIPDetails(
              ip
            );

          setSelectedIP(
            ip
          );

          setDrillDownData(
            data
          );

        } catch (err) {

          console.error(
            err
          );
        }

      },
      []
    );

  // ====================================================
  // INIT
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
  // UPDATE
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

    if (!ipData.length) {

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

              style: {

                text:
                  "Waiting for source IP telemetry...",

                fill:
                  "#64748b",

                fontSize: 12,
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
        400,

      animationEasing:
        "cubicOut",

      grid: {

        left: 82,

        right: 8,

        top: 8,

        bottom: 6,

        containLabel:
          false,
      },

      tooltip: {

        trigger: "axis",

        axisPointer: {
          type: "shadow",
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

            const row =
              ipData[
                params?.[0]
                  ?.dataIndex
              ];

            if (!row) {
              return "";
            }

            const share =
              totalTraffic
                ? (
                    (
                      row.count /
                      totalTraffic
                    ) * 100
                  ).toFixed(2)
                : "0.00";

            return `
              <div style="
                padding:8px;
                min-width:180px;
              ">

                <div style="
                  font-weight:bold;
                  margin-bottom:8px;
                  color:#ffffff;
                ">
                  ${row.sourceIP}
                </div>

                <div>
                  Traffic:
                  <span style="
                    color:#38bdf8;
                    margin-left:6px;
                    font-weight:bold;
                  ">
                    ${row.count.toLocaleString()}
                  </span>
                </div>

                <div>
                  Share:
                  <span style="
                    color:#cbd5e1;
                    margin-left:6px;
                    font-weight:bold;
                  ">
                    ${share}%
                  </span>
                </div>

              </div>
            `;
          },
      },

      xAxis: {

        type: "value",

        show: false,
      },

      yAxis: {

        type: "category",

        inverse: true,

        data:
          ipData.map(
            (r) =>
              r.shortLabel
          ),

        axisLine: {
          show: false,
        },

        axisTick: {
          show: false,
        },

        axisLabel: {

          color:
            "#d1d5db",

          fontSize: 8,

          width: 74,

          overflow:
            "truncate",

          margin: 6,
        },
      },

      series: [

        // ==========================================
        // BACKGROUND
        // ==========================================

        {
          type: "bar",

          silent: true,

          barWidth: 7,

          barGap: "-100%",

          data:
            ipData.map(
              () =>
                Math.log10(
                  maxTraffic + 1
                )
            ),

          itemStyle: {

            color:
              "rgba(255,255,255,0.04)",

            borderRadius:
              [0, 4, 4, 0],
          },

          z: 1,
        },

        // ==========================================
        // MAIN
        // ==========================================

        {
          type: "bar",

          data:
            ipData.map(
              (row) => ({

                value:
                  row.logValue,

                itemStyle: {

                  color:
                    getSeverityGradient(
                      row.count,
                      maxTraffic
                    ),

                  borderRadius:
                    [0, 4, 4, 0],
                },
              })
            ),

          barWidth: 7,

          barCategoryGap:
            "35%",

          z: 2,

          emphasis: {

            itemStyle: {

              shadowBlur: 10,

              shadowColor:
                "rgba(255,255,255,0.12)",
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

    chart.off(
      "click"
    );

    chart.on(
      "click",
      (params) => {

        const row =
          ipData[
            params.dataIndex
          ];

        if (row) {

          fetchDrillDownData(
            row.sourceIP
          );
        }

      }
    );

    chart.resize();

  }, [
    ipData,
    maxTraffic,
    totalTraffic,
    fetchDrillDownData,
    getSeverityGradient,
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

    const handleResize =
      () => {

        if (
          resizeFrameRef.current
        ) {

          cancelAnimationFrame(
            resizeFrameRef.current
          );
        }

        resizeFrameRef.current =
          requestAnimationFrame(
            () => {

              chart.resize({
                animation: false,
              });

            }
          );
      };

    resizeObserverRef.current?.disconnect();

    resizeObserverRef.current =
      new ResizeObserver(
        handleResize
      );

    resizeObserverRef.current.observe(
      chartRef.current
    );

    window.addEventListener(
      "resize",
      handleResize
    );

    const timeout =
      setTimeout(
        handleResize,
        200
      );

    return () => {

      if (
        resizeFrameRef.current
      ) {

        cancelAnimationFrame(
          resizeFrameRef.current
        );
      }

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      window.removeEventListener(
        "resize",
        handleResize
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

      if (
        resizeFrameRef.current
      ) {

        cancelAnimationFrame(
          resizeFrameRef.current
        );
      }

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
  // RENDER
  // ====================================================

  return (

    <div className="
      w-full
      h-full
      min-h-0
      overflow-hidden
      flex
      flex-col
    ">

      {/* ============================================== */}
      {/* METRICS */}
      {/* ============================================== */}

      <div className="
        text-[10px]
        text-gray-400
        mb-1
        flex
        gap-2
        flex-wrap
        shrink-0
      ">

        <span>
          Total:
          {" "}
          <b>
            {totalTraffic.toLocaleString()}
          </b>
        </span>

        <span>
          Unique:
          {" "}
          <b>
            {ipData.length}
          </b>
        </span>

        {lastUpdated && (

          <span>
            {new Date(
              lastUpdated
            ).toLocaleTimeString()}
          </span>
        )}

      </div>

      {/* ============================================== */}
      {/* CHART */}
      {/* ============================================== */}

      <div
        ref={chartRef}
        className="
          w-full
          flex-1
          min-h-0
          overflow-hidden
        "
        style={{
          height:
            CHART_HEIGHT,

          minHeight:
            CHART_HEIGHT,

          maxHeight:
            CHART_HEIGHT,
        }}
      />

      {/* ============================================== */}
      {/* DRILLDOWN */}
      {/* ============================================== */}

      {selectedIP &&
        drillDownData && (

        <div className="
          mt-2
          p-2
          text-[10px]
          bg-gray-800
          rounded
          border
          border-gray-700
          max-h-32
          overflow-auto
          shrink-0
        ">

          <div className="
            font-bold
            mb-1
            text-white
          ">
            {selectedIP}
          </div>

          <pre className="
            text-gray-400
            whitespace-pre-wrap
            break-words
          ">
            {JSON.stringify(
              drillDownData,
              null,
              2
            )}
          </pre>

        </div>
      )}

    </div>
  );
};

export default Top25SourceIPsChart;