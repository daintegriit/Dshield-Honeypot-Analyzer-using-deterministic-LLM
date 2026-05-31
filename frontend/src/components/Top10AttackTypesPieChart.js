import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
} from "react";

import * as echarts from "echarts";

import {
  useTelemetry
} from "../context/TelemetryContext";

const Top10AttackTypesChart = () => {

  // ====================================================
  // TELEMETRY CONTEXT
  // ====================================================

  const {
    attackTypes,
    loading,
    stale
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

  // ====================================================
  // LOCAL STATE
  // ====================================================

  const [rows, setRows] =
    useState([]);

  // ====================================================
  // SYNC TELEMETRY
  // ====================================================

  useEffect(() => {

    if (
      Array.isArray(
        attackTypes
      )
    ) {

      setRows(
        attackTypes
      );
    }

  }, [attackTypes]);

  // ====================================================
  // COLOR MAPPING
  // ====================================================

  const getColor = (
    name = ""
  ) => {

    const n =
      String(name)
        .toLowerCase();

    if (
      n.includes("brute")
    ) {
      return "#ff4d4d";
    }

    if (
      n.includes("telnet")
    ) {
      return "#ff884d";
    }

    if (
      n.includes("probe")
    ) {
      return "#4da6ff";
    }

    if (
      n.includes("rdp")
    ) {
      return "#ffd24d";
    }

    if (
      n.includes("scan")
    ) {
      return "#66cc66";
    }

    if (
      n.includes("dos")
    ) {
      return "#ff3355";
    }

    return "#4caf50";
  };

  // ====================================================
  // NORMALIZED DATA
  // ====================================================

  const mappedRows =
    useMemo(() => {

      return (
        rows || []
      )
        .map(
          (item) => ({

            name:
              item.attackType ||
              item.name ||
              item._id ||
              "Unknown",

            value: Number(
              item.count ??
              item.value ??
              0
            ),
          })
        )
        .filter(
          (r) =>
            r.value > 0
        )
        .sort(
          (a, b) =>
            b.value - a.value
        );

    }, [rows]);

  const names =
    useMemo(
      () =>
        mappedRows.map(
          (r) => r.name
        ),
      [mappedRows]
    );

  const total =
    useMemo(
      () =>
        mappedRows.reduce(
          (sum, r) =>
            sum + r.value,
          0
        ),
      [mappedRows]
    );

  // ====================================================
  // SAFE RESIZE
  // ====================================================

  const safeResize = () => {

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

          if (
            chartInstanceRef.current
          ) {

            try {

              chartInstanceRef.current.resize();

            } catch (err) {

              console.warn(
                "AttackTypes resize skipped:",
                err
              );
            }
          }
        }
      );
  };

  // ====================================================
  // CHART INIT
  // ====================================================

  useEffect(() => {

    if (
      !chartRef.current
    ) {
      return;
    }

    // ================================================
    // SINGLE INSTANCE ONLY
    // ================================================

    if (
      !chartInstanceRef.current
    ) {

      chartInstanceRef.current =
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
    }

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
  // CHART UPDATE
  // ====================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (!chart) {
      return;
    }

    // ------------------------------------------------
    // EMPTY STATE
    // ------------------------------------------------

    if (
      !mappedRows.length
    ) {

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
                    ? "Loading attack intelligence..."
                    : stale
                    ? "Telemetry stale..."
                    : "Waiting for attack type data...",

                fill:
                  stale
                    ? "#facc15"
                    : "#666",

                fontSize: 14,

                fontWeight: 400,

                textAlign:
                  "center",

                textVerticalAlign:
                  "middle",
              },
            },
          ],

          xAxis: {
            show: false
          },

          yAxis: {
            show: false
          },

          series: [],
        },
        true
      );

      safeResize();

      return;
    }

    // ------------------------------------------------
    // RESPONSIVE WIDTH
    // ------------------------------------------------

    const width =
      chartRef.current
        ?.clientWidth || 0;

    const isTight =
      width > 0 &&
      width < 420;

    // ------------------------------------------------
    // OPTION
    // ------------------------------------------------

    const option = {

      backgroundColor:
        "transparent",

      animation: true,

      animationDuration: 600,

      animationEasing:
        "cubicOut",

      tooltip: {

        trigger: "axis",

        axisPointer: {
          type: "shadow"
        },

        backgroundColor:
          "#111",

        borderColor:
          "#444",

        borderWidth: 1,

        textStyle: {
          color: "#fff"
        },

        formatter: (
          params
        ) => {

          const p =
            params?.[0];

          if (!p)
            return "";

          const percent =
            total
              ? (
                  (
                    p.value /
                    total
                  ) * 100
                ).toFixed(1)
              : "0.0";

          return `
            <b>${p.name}</b><br/>
            Count: ${p.value}<br/>
            Share: ${percent}%
          `;
        },
      },

      grid: {

        left:
          isTight
            ? 110
            : 140,

        right: 35,

        top: 20,

        bottom: 25,

        containLabel: true,
      },

      xAxis: {

        type: "value",

        axisLine: {

          lineStyle: {
            color: "#555"
          },
        },

        splitLine: {

          lineStyle: {
            color: "#253041"
          },
        },

        axisLabel: {

          color: "#cbd5e1",

          formatter: (
            v
          ) => {

            if (
              v >= 1_000_000
            ) {
              return `${Math.round(
                v / 1_000_000
              )}M`;
            }

            if (
              v >= 1_000
            ) {
              return `${Math.round(
                v / 1_000
              )}k`;
            }

            return v;
          },
        },
      },

      yAxis: {

        type: "category",

        data: names,

        axisLine: {

          lineStyle: {
            color: "#555"
          },
        },

        axisTick: {
          show: false
        },

        axisLabel: {

          color: "#e5e7eb",

          fontSize:
            isTight
              ? 10
              : 12,

          interval: 0,

          width:
            isTight
              ? 90
              : 120,

          overflow:
            "truncate",

          formatter: (
            name
          ) => {

            if (!name)
              return "";

            return String(
              name
            );
          },
        },
      },

      series: [

        {

          name:
            "Attack Types",

          type: "bar",

          data:
            mappedRows.map(
              (r) => ({

                value:
                  r.value,

                itemStyle: {

                  color:
                    getColor(
                      r.name
                    ),
                },
              })
            ),

          barWidth:
            isTight
              ? 14
              : 18,

          label: {

            show:
              !isTight,

            position:
              "right",

            color:
              "#e5e7eb",

            fontSize: 11,

            formatter: (
              p
            ) => {

              const percent =
                total
                  ? (
                      (
                        p.value /
                        total
                      ) * 100
                    ).toFixed(1)
                  : "0.0";

              return `${p.value} (${percent}%)`;
            },
          },
        },
      ],
    };

    chart.setOption(
      option,
      true
    );

    safeResize();

  }, [
    mappedRows,
    names,
    total,
    loading,
    stale
  ]);

  // ====================================================
  // SAFE RESIZE HANDLING
  // ====================================================

  useEffect(() => {

    if (
      !chartRef.current
    ) {
      return;
    }

    // ================================================
    // CLEAN PREVIOUS
    // ================================================

    resizeObserverRef.current?.disconnect();

    // ================================================
    // OBSERVER
    // ================================================

    resizeObserverRef.current =
      new ResizeObserver(
        () => {

          safeResize();
        }
      );

    resizeObserverRef.current.observe(
      chartRef.current
    );

    // ================================================
    // WINDOW RESIZE
    // ================================================

    window.addEventListener(
      "resize",
      safeResize
    );

    // ================================================
    // INITIAL RESIZE
    // ================================================

    const timeout =
      setTimeout(
        safeResize,
        120
      );

    return () => {

      clearTimeout(
        timeout
      );

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      window.removeEventListener(
        "resize",
        safeResize
      );

      if (
        resizeFrameRef.current
      ) {

        cancelAnimationFrame(
          resizeFrameRef.current
        );
      }
    };

  }, []);

  // ====================================================
  // RENDER
  // ====================================================

  return (

    <div className="w-full h-full min-h-0 overflow-hidden">

      <div
        ref={chartRef}
        className="w-full h-full min-h-0"
        style={{
          minHeight: "260px",
          height: "100%",
        }}
      />

    </div>
  );
};

export default Top10AttackTypesChart;