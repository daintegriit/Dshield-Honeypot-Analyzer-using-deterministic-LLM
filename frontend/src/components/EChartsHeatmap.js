import React, {
  useEffect,
  useRef,
  useState,
  useMemo
} from "react";

import * as echarts from "echarts";
import apiService from "../services/apiService";

const EChartsHeatmap = () => {
  const chartRef = useRef(null);

  const chartInstanceRef =
    useRef(null);

  const resizeObserverRef =
    useRef(null);

  const intervalRef =
    useRef(null);

  const mountedRef =
    useRef(true);

  const [rawData, setRawData] =
    useState([]);

  // =====================================================
  // NORMALIZE + LOG SCALE
  // =====================================================

  const {
    hours,
    days,
    indexedData,
    visualMax,
    realMax,
    totalEvents
  } = useMemo(() => {
    // ----------------------------------------------
    // EMPTY
    // ----------------------------------------------

    if (!rawData.length) {
      return {
        hours: [],
        days: [],
        indexedData: [],
        visualMax: 1,
        realMax: 1,
        totalEvents: 0
      };
    }

    // ----------------------------------------------
    // UNIQUE AXES
    // ----------------------------------------------

    const hoursSet = new Set();
    const daysSet = new Set();

    rawData.forEach(
      ([day, hour]) => {
        daysSet.add(day);
        hoursSet.add(hour);
      }
    );

    const hoursArr =
      [...hoursSet].sort(
        (a, b) => a - b
      );

    const daysArr =
      [...daysSet].sort(
        (a, b) => a - b
      );

    // ----------------------------------------------
    // LABELS
    // ----------------------------------------------

    const hours =
      hoursArr.map((h) =>
        `${String(h).padStart(
          2,
          "0"
        )}:00`
      );

    const days =
      daysArr.map((d) =>
        `Day ${d}`
      );

    // ----------------------------------------------
    // INDEX MAPS
    // ----------------------------------------------

    const hourIndex =
      Object.fromEntries(
        hours.map((h, i) => [
          h,
          i
        ])
      );

    const dayIndex =
      Object.fromEntries(
        days.map((d, i) => [
          d,
          i
        ])
      );

    // ----------------------------------------------
    // REAL MAX
    // ----------------------------------------------

    const realMax =
      Math.max(
        ...rawData.map(
          (d) => d[2] || 0
        ),
        1
      );

    // ----------------------------------------------
    // VISUAL MAX
    // ----------------------------------------------

    const visualMax =
      realMax > 1000
        ? Math.ceil(
            Math.log10(
              realMax + 1
            )
          )
        : Math.max(
            Math.ceil(
              Math.log10(
                realMax + 1
              )
            ),
            1
          );

    // ----------------------------------------------
    // TOTAL EVENTS
    // ----------------------------------------------

    const totalEvents =
      rawData.reduce(
        (sum, item) =>
          sum + (item[2] || 0),
        0
      );

    // ----------------------------------------------
    // INDEXED DATA
    // LOG NORMALIZED
    // ----------------------------------------------

    const indexedData =
      rawData.map(
        ([day, hour, count]) => {
          const normalized =
            count > 0
              ? Number(
                  Math.log10(
                    count + 1
                  ).toFixed(3)
                )
              : 0;

          return [
            dayIndex[
              `Day ${day}`
            ],
            hourIndex[
              `${String(
                hour
              ).padStart(
                2,
                "0"
              )}:00`
            ],
            normalized,
            count
          ];
        }
      );

    return {
      hours,
      days,
      indexedData,
      visualMax,
      realMax,
      totalEvents
    };
  }, [rawData]);

  // =====================================================
  // FETCH LOOP
  // =====================================================

  useEffect(() => {
    mountedRef.current = true;

    const fetchData =
      async () => {
        try {
          console.log(
            "🚀 Fetching heatmap..."
          );

          const data =
            await apiService.getHeatmapData();

          if (
            !mountedRef.current
          )
            return;

          if (
            Array.isArray(data)
          ) {
            console.log(
              "✅ Heatmap rows:",
              data.length
            );

            setRawData(data);
          } else {
            console.warn(
              "⚠️ Invalid heatmap response"
            );

            setRawData([]);
          }
        } catch (err) {
          console.error(
            "❌ Heatmap fetch error:",
            err
          );

          if (
            mountedRef.current
          ) {
            setRawData([]);
          }
        }
      };

    // ----------------------------------------------
    // INITIAL
    // ----------------------------------------------

    fetchData();

    // ----------------------------------------------
    // LIVE LOOP
    // ----------------------------------------------

    intervalRef.current =
      setInterval(
        fetchData,
        10000
      );

    return () => {
      mountedRef.current =
        false;

      clearInterval(
        intervalRef.current
      );
    };
  }, []);

  // =====================================================
  // CHART
  // =====================================================

  useEffect(() => {
    if (!chartRef.current)
      return;

    let chart =
      chartInstanceRef.current;

    // ----------------------------------------------
    // SAFE INIT
    // ----------------------------------------------

    if (!chart) {
      chart = echarts.init(
        chartRef.current
      );

      chartInstanceRef.current =
        chart;

      setTimeout(
        () => chart.resize(),
        100
      );
    }

    // ----------------------------------------------
    // EMPTY STATE
    // ----------------------------------------------

    if (!indexedData.length) {
      chart.clear();

      chart.setOption({
        backgroundColor:
          "transparent",

        title: {
          text:
            "Waiting for heatmap telemetry...",

          left: "center",
          top: "middle",

          textStyle: {
            color: "#64748b",
            fontSize: 14,
            fontWeight:
              "normal"
          }
        }
      });

      return;
    }

    // =====================================================
    // OPTION
    // =====================================================

    const option = {
      backgroundColor:
        "transparent",

      animation: true,

      animationDuration: 800,

      animationEasing:
        "cubicOut",

      tooltip: {
        trigger: "item",

        backgroundColor:
          "#0f172a",

        borderColor:
          "#334155",

        borderWidth: 1,

        textStyle: {
          color: "#fff"
        },

        formatter: (p) => {
          return `
            <div style="padding:6px;min-width:140px;">
              
              <div style="
                font-weight:bold;
                margin-bottom:6px;
                color:#4fc3f7;
              ">
                Threat Density
              </div>

              <div>
                <span style="color:#94a3b8;">
                  Day:
                </span>
                ${days[p.data[0]]}
              </div>

              <div>
                <span style="color:#94a3b8;">
                  Hour:
                </span>
                ${hours[p.data[1]]}
              </div>

              <div>
                <span style="color:#94a3b8;">
                  Attacks:
                </span>

                <span style="
                  color:#f87171;
                  font-weight:bold;
                ">
                  ${p.data[3]}
                </span>
              </div>

            </div>
          `;
        }
      },

      grid: {
        top: "10%",
        left: "7%",
        right: "4%",
        bottom: "24%",
        containLabel: true
      },

      xAxis: {
        type: "category",

        data: hours,

        splitArea: {
          show: true
        },

        axisLabel: {
          color: "#94a3b8",
          rotate: 35,
          fontSize: 10
        },

        axisLine: {
          lineStyle: {
            color: "#334155"
          }
        },

        splitLine: {
          lineStyle: {
            color:
              "rgba(255,255,255,0.03)"
          }
        }
      },

      yAxis: {
        type: "category",

        data: days,

        splitArea: {
          show: true
        },

        axisLabel: {
          color: "#94a3b8",
          fontSize: 11
        },

        axisLine: {
          lineStyle: {
            color: "#334155"
          }
        },

        splitLine: {
          lineStyle: {
            color:
              "rgba(255,255,255,0.03)"
          }
        }
      },

      visualMap: {
        min: 0,

        max: visualMax,

        calculable: true,

        realtime: true,

        orient: "horizontal",

        left: "center",

        bottom: "6%",

        itemWidth: 14,

        itemHeight: 100,

        text: [
          "High",
          "Low"
        ],

        textStyle: {
          color: "#94a3b8"
        },

        inRange: {
          color: [
            "#0f172a",
            "#1e3a8a",
            "#2563eb",
            "#06b6d4",
            "#10b981",
            "#fde047",
            "#fb923c",
            "#ef4444",
            "#7f1d1d"
          ]
        },

        outOfRange: {
          color: [
            "#020617"
          ]
        }
      },

      series: [
        {
          name:
            "Threat Density",

          type: "heatmap",

          data: indexedData,

          progressive: 1000,

          progressiveThreshold:
            3000,

          emphasis: {
            itemStyle: {
              borderColor:
                "#fff",

              borderWidth: 1,

              shadowBlur: 18,

              shadowColor:
                "rgba(0,0,0,0.7)"
            }
          },

          itemStyle: {
            borderColor:
              "rgba(255,255,255,0.04)",

            borderWidth: 0.5
          }
        }
      ]
    };

    chart.setOption(
      option,
      true
    );

    chart.resize();
  }, [
    indexedData,
    hours,
    days,
    visualMax
  ]);

  // =====================================================
  // RESIZE
  // =====================================================

  useEffect(() => {
    const chart =
      chartInstanceRef.current;

    if (
      !chart ||
      !chartRef.current
    )
      return;

    const resize = () =>
      chart.resize();

    if (
      resizeObserverRef.current
    ) {
      resizeObserverRef.current.disconnect();
    }

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

      clearTimeout(timeout);
    };
  }, []);

  // =====================================================
  // CLEANUP
  // =====================================================

  useEffect(() => {
    return () => {
      clearInterval(
        intervalRef.current
      );

      const chart =
        chartInstanceRef.current;

      if (
        chart &&
        !chart.isDisposed()
      ) {
        chart.dispose();
      }

      chartInstanceRef.current =
        null;
    };
  }, []);

  // =====================================================
  // UI
  // =====================================================

  return (
    <div className="w-full h-full min-h-0 overflow-hidden flex flex-col">
      {/* HEADER */}
      <div className="flex items-center justify-between text-xs text-gray-400 mb-1 px-1">
        <div>
          <span className="text-white font-semibold">
            Events:
          </span>{" "}
          {totalEvents.toLocaleString()}
        </div>

        <div>
          <span className="text-white font-semibold">
            Peak:
          </span>{" "}
          {realMax.toLocaleString()}
        </div>
      </div>

      {/* CHART */}
      <div
        ref={chartRef}
        className="flex-1 w-full min-h-0"
        style={{
          width: "100%",
          height: "100%"
        }}
      />
    </div>
  );
};

export default EChartsHeatmap;