import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
} from "react";

import * as echarts from "echarts";

import apiService from "../services/apiService";

// =====================================================
// SOC SEVERITY COLORS
// =====================================================

const severityColors = {
  critical: "#d9534f",
  high: "#f97316",
  medium: "#eab308",
  low: "#06b6d4",
};

// =====================================================
// DETERMINISTIC ORDERING
// =====================================================

const severityOrder = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// =====================================================
// TIME WINDOWS
// =====================================================

const WINDOW_OPTIONS = [
  { label: "All", value: "all" },
  { label: "1m", value: 1 },
  { label: "5m", value: 5 },
  { label: "15m", value: 15 },
  { label: "30m", value: 30 },
  { label: "60m", value: 60 },
  { label: "6h", value: 360 },
  { label: "24h", value: 1440 },
];

// =====================================================
// EMPTY STATE
// =====================================================

const EMPTY_STATE = {
  total: 0,
  dominantSeverity: "none",
  severities: [],
};

// =====================================================
// COMPONENT
// =====================================================

const SeverityDistributionChart = () => {

  // ===================================================
  // REFS
  // ===================================================

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  const resizeObserverRef =
    useRef(null);

  const intervalRef =
    useRef(null);

  const mountedRef =
    useRef(true);

  // ===================================================
  // STATE
  // ===================================================

  const [
    severityData,
    setSeverityData,
  ] = useState(
    EMPTY_STATE
  );

  const [
    selectedWindow,
    setSelectedWindow,
  ] = useState("all");

  const [
    previousTotal,
    setPreviousTotal,
  ] = useState(0);

  const [
    loading,
    setLoading,
  ] = useState(false);

  // ===================================================
  // NORMALIZED DATA
  // ===================================================

  const mappedSeverityData =
    useMemo(() => {

      const severities =
        Array.isArray(
          severityData?.severities
        )
          ? severityData.severities
          : [];

      const totalRaw =
        severities.reduce(
          (sum, s) =>
            sum +
            Number(
              s.count || 0
            ),
          0
        );

      return severities

        .map((item) => {

          const key =
            String(
              item.severity || ""
            ).toLowerCase();

          const raw =
            Number(
              item.count || 0
            );

          const percent =
            totalRaw > 0
              ? (
                  raw /
                  totalRaw
                ) * 100
              : 0;

          const visualValue =
            Math.max(
              Math.sqrt(
                percent
              ) * 12,
              3
            );

          return {

            name: key,

            rawValue:
              raw,

            value:
              visualValue,

            percent,

            itemStyle: {
              color:
                severityColors[
                  key
                ] || "#888",
            },
          };
        })

        .filter(
          (s) =>
            s.rawValue > 0
        )

        .sort(
          (a, b) =>
            severityOrder[
              a.name
            ] -
            severityOrder[
              b.name
            ]
        );

    }, [severityData]);

  // ===================================================
  // TOTAL
  // ===================================================

  const total =
    Number(
      severityData?.total || 0
    );

  // ===================================================
  // DOMINANT
  // ===================================================

  const dominantSeverity =
    severityData?.dominantSeverity ||
    "none";

  const dominantColor =
    severityColors[
      dominantSeverity
    ] || "#94a3b8";

  // ===================================================
  // DELTA %
  // ===================================================

  const deltaPercent =
    useMemo(() => {

      if (
        previousTotal <= 0
      ) {

        return total > 0
          ? 100
          : 0;
      }

      return Number(
        (
          (
            (
              total -
              previousTotal
            ) /
            previousTotal
          ) * 100
        ).toFixed(1)
      );

    }, [
      total,
      previousTotal,
    ]);

  // ===================================================
  // OPERATIONAL STATE
  // ===================================================

  const operationalState =
    useMemo(() => {

      if (
        deltaPercent >= 50
      ) {
        return "SURGING";
      }

      if (
        deltaPercent >= 20
      ) {
        return "ELEVATED";
      }

      if (
        deltaPercent >= 0
      ) {
        return "STABLE";
      }

      return "COOLING";

    }, [deltaPercent]);

  // ===================================================
  // EVENTS/MIN
  // ===================================================

  const eventsPerMinute =
    useMemo(() => {

      if (
        selectedWindow === "all"
      ) {
        return 0;
      }

      if (
        !selectedWindow
      ) {
        return 0;
      }

      return Math.round(
        total /
        Number(selectedWindow)
      );

    }, [
      total,
      selectedWindow,
    ]);

  // ===================================================
  // FETCH DATA
  // ===================================================

  useEffect(() => {

    mountedRef.current =
      true;

    const fetchSeverityData =
      async () => {

        try {

          setLoading(true);

          const current =
            await apiService.getSeverityDistribution(
              selectedWindow
            );

          const previous =
            selectedWindow === "all"
              ? null
              : await apiService.getSeverityDistribution(
                  Number(
                    selectedWindow
                  ) * 2
                );

          if (
            !mountedRef.current
          ) {
            return;
          }

          if (
            current &&
            typeof current === "object" &&
            Array.isArray(
              current.severities
            )
          ) {

            setSeverityData({

              total:
                Number(
                  current.total || 0
                ),

              dominantSeverity:
                current.dominantSeverity ||
                "none",

              severities:
                current.severities || [],

            });

          } else {

            setSeverityData(
              EMPTY_STATE
            );
          }

          if (
            previous &&
            typeof previous.total ===
              "number"
          ) {

            setPreviousTotal(
              Number(
                previous.total || 0
              )
            );

          } else {

            setPreviousTotal(0);
          }

        } catch (err) {

          console.error(
            "❌ Severity fetch error:",
            err
          );

          if (
            mountedRef.current
          ) {

            setSeverityData(
              EMPTY_STATE
            );

            setPreviousTotal(0);
          }

        } finally {

          if (
            mountedRef.current
          ) {

            setLoading(false);
          }
        }
      };

    fetchSeverityData();

    intervalRef.current =
      setInterval(
        fetchSeverityData,
        10000
      );

    return () => {

      mountedRef.current =
        false;

      clearInterval(
        intervalRef.current
      );
    };

  }, [selectedWindow]);

  // ===================================================
  // INIT CHART
  // ===================================================

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

    return () => {

      chart.dispose();

      chartInstanceRef.current =
        null;
    };

  }, []);

  // ===================================================
  // UPDATE CHART
  // ===================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (!chart) {
      return;
    }

    // ===============================================
    // EMPTY STATE
    // ===============================================

    if (
      !mappedSeverityData.length
    ) {

      chart.clear();

      chart.setOption(
        {

          backgroundColor:
            "transparent",

          title: {

            text:
              loading
                ? "Loading severity telemetry..."
                : "No live severity telemetry",

            left: "center",

            top: "center",

            textStyle: {

              color:
                "#64748b",

              fontSize: 10,

              fontWeight:
                500,
            },
          },

          series: [],
        },
        true
      );

      return;
    }

    // ===============================================
    // OPTION
    // ===============================================

    const option = {

      backgroundColor:
        "transparent",

      animation: true,

      animationDuration:
        600,

      animationEasing:
        "cubicOut",

      tooltip: {

        trigger: "item",

        backgroundColor:
          "#111827",

        borderColor:
          "#334155",

        borderWidth: 1,

        textStyle: {
          color: "#fff",
        },

        formatter:
          (params) => {

            const raw =
              Number(
                params.data.rawValue || 0
              );

            const percent =
              total > 0
                ? (
                    (
                      raw /
                      total
                    ) * 100
                  ).toFixed(2)
                : "0.00";

            return `
              <div style="padding:8px;min-width:180px;">

                <div style="
                  font-size:12px;
                  font-weight:bold;
                  margin-bottom:6px;
                  color:${params.color};
                  text-transform:uppercase;
                ">
                  ${params.name}
                </div>

                <div>
                  Events:
                  <span style="
                    color:#ffffff;
                    margin-left:6px;
                    font-weight:bold;
                  ">
                    ${raw.toLocaleString()}
                  </span>
                </div>

                <div>
                  Distribution:
                  <span style="
                    color:#38bdf8;
                    margin-left:6px;
                    font-weight:bold;
                  ">
                    ${percent}%
                  </span>
                </div>

              </div>
            `;
          },
      },

      legend: {

        show: true,

        bottom: 0,

        itemWidth: 10,

        itemHeight: 8,

        textStyle: {

          color:
            "#cbd5e1",

          fontSize: 9,
        },
      },

      graphic: [

        {
          type: "text",

          left: "center",

          top: "34%",

          silent: true,

          style: {

            text:
              total.toLocaleString(),

            fill:
              "#ffffff",

            fontSize: 11,

            fontWeight:
              "bold",

            textAlign:
              "center",
          },
        },

        {
          type: "text",

          left: "center",

          top: "43%",

          silent: true,

          style: {

            text:
              operationalState,

            fill:
              dominantColor,

            fontSize: 9,

            fontWeight:
              "bold",

            textAlign:
              "center",
          },
        },

        {
          type: "text",

          left: "center",

          top: "51%",

          silent: true,

          style: {

            text:
              selectedWindow === "all"
                ? "Lifetime"
                : `${eventsPerMinute}/min`,

            fill:
              "#64748b",

            fontSize: 7,

            textAlign:
              "center",
          },
        },
      ],

      series: [

        {
          name:
            "Severity",

          type: "pie",

          radius: [
            "58%",
            "82%",
          ],

          center: [
            "50%",
            "42%",
          ],

          avoidLabelOverlap:
            true,

          stillShowZeroSum:
            false,

          minAngle: 5,

          clockwise: true,

          label: {
            show: false,
          },

          labelLine: {
            show: false,
          },

          emphasis: {

            scale: true,

            scaleSize: 4,

            itemStyle: {

              shadowBlur: 14,

              shadowColor:
                "rgba(0,0,0,0.35)",
            },
          },

          itemStyle: {

            borderColor:
              "#0f172a",

            borderWidth: 2,
          },

          data:
            mappedSeverityData,
        },
      ],
    };

    chart.setOption(
      option,
      true
    );

  }, [
    mappedSeverityData,
    total,
    dominantColor,
    operationalState,
    eventsPerMinute,
    selectedWindow,
    loading,
  ]);

  // ===================================================
  // SAFE RESIZE
  // ===================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (
      !chart ||
      !chartRef.current
    ) {
      return;
    }

    let frame;

    const resize =
      () => {

        cancelAnimationFrame(
          frame
        );

        frame =
          requestAnimationFrame(
            () => {

              if (
                chart &&
                !chart.isDisposed()
              ) {

                chart.resize({
                  animation:
                    false,
                });
              }
            }
          );
      };

    window.addEventListener(
      "resize",
      resize,
      {
        passive: true,
      }
    );

    resizeObserverRef.current =
      new ResizeObserver(
        () => {

          resize();
        }
      );

    resizeObserverRef.current.observe(
      chartRef.current
    );

    return () => {

      cancelAnimationFrame(
        frame
      );

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      window.removeEventListener(
        "resize",
        resize
      );
    };

  }, []);

  // ===================================================
  // CLEANUP
  // ===================================================

  useEffect(() => {

    return () => {

      clearInterval(
        intervalRef.current
      );

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

  // ===================================================
  // RENDER
  // ===================================================

  return (

    <div className="
      w-full
      h-full
      min-h-0
      max-h-full
      overflow-hidden
      flex
      flex-col
    ">

      {/* =========================================== */}
      {/* HEADER */}
      {/* =========================================== */}

      <div className="
        flex
        items-center
        justify-end
        h-[22px]
        px-1
        shrink-0
      ">

        <div className="
          flex
          items-center
          gap-2
        ">

          <div
            className="
              text-[10px]
              font-semibold
            "
            style={{
              color:
                deltaPercent >= 0
                  ? "#f87171"
                  : "#4ade80",
            }}
          >
            {deltaPercent >= 0
              ? `+${deltaPercent}%`
              : `${deltaPercent}%`}
          </div>

          <select
            value={
              selectedWindow
            }
            onChange={(e) =>
              setSelectedWindow(
                e.target.value === "all"
                  ? "all"
                  : Number(
                      e.target.value
                    )
              )
            }
            className="
              bg-[#0f172a]
              border
              border-[#334155]
              text-gray-200
              text-[10px]
              rounded
              px-2
              py-[2px]
              outline-none
              h-[22px]
            "
          >
            {WINDOW_OPTIONS.map(
              (w) => (
                <option
                  key={w.value}
                  value={w.value}
                >
                  {w.label}
                </option>
              )
            )}
          </select>
        </div>
      </div>

      {/* =========================================== */}
      {/* CHART */}
      {/* =========================================== */}

      <div
        className="
          flex-1
          min-h-0
          overflow-hidden
        "
      >
        <div
          ref={chartRef}
          className="
            w-full
            h-full
          "
        />
      </div>

      {/* =========================================== */}
      {/* FOOTER */}
      {/* =========================================== */}

      <div className="
        grid
        grid-cols-2
        sm:grid-cols-4
        gap-1
        mt-1
        px-1
        pb-1
        shrink-0
      ">

        {mappedSeverityData.map(
          (item) => {

            const percent =
              total > 0
                ? (
                    (
                      item.rawValue /
                      total
                    ) * 100
                  ).toFixed(1)
                : "0.0";

            return (

              <div
                key={item.name}
                className="
                  flex
                  flex-col
                  items-center
                  justify-center
                  rounded
                  bg-[#0f172a]
                  border
                  border-[#1e293b]
                  py-1
                  min-h-[38px]
                "
              >

                <div
                  className="
                    text-[9px]
                    uppercase
                    font-bold
                  "
                  style={{
                    color:
                      severityColors[
                        item.name
                      ],
                  }}
                >
                  {item.name}
                </div>

                <div className="
                  text-[10px]
                  text-white
                  font-semibold
                ">
                  {percent}%
                </div>

              </div>
            );
          }
        )}
      </div>
    </div>
  );
};

export default SeverityDistributionChart;