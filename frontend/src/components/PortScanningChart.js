import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
} from "react";

import * as echarts from "echarts";
import apiService from "../services/apiService";

const PortScanningChart = () => {

  // ==================================================
  // REFS
  // ==================================================

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  const resizeObserverRef =
    useRef(null);

  const resizeFrameRef =
    useRef(null);

  const intervalRef =
    useRef(null);

  const mountedRef =
    useRef(true);

  const prevCountsRef =
    useRef({});

  // ==================================================
  // STATE
  // ==================================================

  const [portData,
    setPortData] =
      useState([]);

  const [drilldown,
    setDrilldown] =
      useState(null);

  // ==================================================
  // RISK CLASSIFICATION
  // ==================================================

  const getPortCategory =
    (port) => {

      const p =
        Number(port);

      if (
        [
          22,
          80,
          443,
          3389,
          5900,
        ].includes(p)
      ) {

        return "High-Risk Service";
      }

      if (p < 1024) {

        return "Privileged Port";
      }

      return "Ephemeral";
    };

  // ==================================================
  // DRILLDOWN
  // ==================================================

  const fetchPortAttackers =
    async (port) => {

      try {

        const res =
          await fetch(
            `${process.env.REACT_APP_API_BASE_URL}/api/attacks/port-details?port=${port}`
          );

        const data =
          await res.json();

        setDrilldown({

          port,

          attackers:
            data,
        });

      } catch (err) {

        console.error(
          "Drilldown error:",
          err
        );
      }
    };

  // ==================================================
  // FETCH
  // ==================================================

  useEffect(() => {

    mountedRef.current =
      true;

    const fetchData =
      async () => {

        try {

          const data =
            await apiService.getPortScanningData();

          if (
            !mountedRef.current ||
            !Array.isArray(data)
          ) {
            return;
          }

          const prev =
            prevCountsRef.current;

          const enriched =
            data

              .map((row) => ({

                ...row,

                category:
                  getPortCategory(
                    row.port
                  ),

                previous:
                  prev[
                    row.port
                  ],

                rising:
                  prev[
                    row.port
                  ] !==
                    undefined &&
                  row.count >
                    prev[
                      row.port
                    ],
              }))

              .filter(
                (r) =>
                  Number(
                    r.count || 0
                  ) > 0
              )

              .sort(
                (a, b) =>
                  b.count -
                  a.count
              )

              .slice(0, 12);

          setPortData(
            enriched
          );

          prevCountsRef.current =
            enriched.reduce(
              (acc, r) => {

                acc[
                  r.port
                ] = r.count;

                return acc;

              },
              {}
            );

        } catch (err) {

          console.error(
            "Port scan fetch error:",
            err
          );
        }
      };

    fetchData();

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

  // ==================================================
  // TOTAL
  // ==================================================

  const total =
    useMemo(
      () =>
        portData.reduce(
          (s, r) =>
            s +
            Number(
              r.count || 0
            ),
          0
        ),
      [portData]
    );

  // ==================================================
  // CHART INIT
  // ==================================================

  useEffect(() => {

    if (
      !chartRef.current
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
            renderer:
              "canvas",

            useDirtyRect:
              true,
          }
        );
    }

  }, []);

  // ==================================================
  // APPLY OPTION
  // ==================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (!chart) {
      return;
    }

    // ==============================================
    // EMPTY STATE
    // ==============================================

    if (
      !portData.length
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
                  "Waiting for port telemetry...",

                fill:
                  "#64748b",

                fontSize:
                  13,

                textAlign:
                  "center",
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

      return;
    }

    // ==============================================
    // RESPONSIVE
    // ==============================================

    const width =
      chartRef.current
        ?.clientWidth || 0;

    const isTight =
      width < 400;

    // ==============================================
    // OPTION
    // ==============================================

    const option = {

      backgroundColor:
        "transparent",

      animation:
        true,

      animationDuration:
        450,

      animationEasing:
        "cubicOut",

      tooltip: {

        trigger:
          "axis",

        axisPointer: {
          type:
            "shadow",
        },

        backgroundColor:
          "#111827",

        borderColor:
          "#334155",

        borderWidth:
          1,

        textStyle: {
          color:
            "#fff",
        },

        formatter:
          (params) => {

            const p =
              params?.[0];

            if (!p) {
              return "";
            }

            const r =
              portData[
                p.dataIndex
              ];

            const percent =
              total
                ? (
                    (
                      r.count /
                      total
                    ) * 100
                  ).toFixed(1)
                : "0.0";

            return `
              <div style="
                padding:8px;
                min-width:140px;
              ">

                <div style="
                  font-weight:bold;
                  margin-bottom:6px;
                  color:#fff;
                ">
                  Port ${r.port}
                </div>

                <div>
                  Count:
                  <span style="
                    color:#fff;
                    font-weight:bold;
                    margin-left:6px;
                  ">
                    ${r.count.toLocaleString()}
                  </span>
                </div>

                <div>
                  Share:
                  <span style="
                    color:#38bdf8;
                    font-weight:bold;
                    margin-left:6px;
                  ">
                    ${percent}%
                  </span>
                </div>

                <div style="
                  margin-top:6px;
                  color:#94a3b8;
                ">
                  ${r.category}
                </div>

              </div>
            `;
          },
      },

      grid: {

        left:
          isTight
            ? 40
            : 48,

        right:
          isTight
            ? 12
            : 18,

        top: 18,

        bottom:
          isTight
            ? 52
            : 44,

        containLabel:
          false,
      },

      xAxis: {

        type:
          "category",

        data:
          portData.map(
            (r) =>
              `${r.port}${r.rising ? " ↑" : ""}`
          ),

        axisLine: {

          lineStyle: {
            color:
              "#475569",
          },
        },

        axisTick: {
          show: false,
        },

        axisLabel: {

          color:
            "#94a3b8",

          rotate:
            35,

          fontSize:
            isTight
              ? 9
              : 11,
        },
      },

      yAxis: {

        type:
          "value",

        axisLine: {

          lineStyle: {
            color:
              "#475569",
          },
        },

        splitLine: {

          lineStyle: {
            color:
              "rgba(255,255,255,0.05)",
          },
        },

        axisLabel: {

          color:
            "#94a3b8",

          fontSize:
            10,

          formatter:
            (v) => {

              if (
                v >= 1000
              ) {

                return `${(
                  v / 1000
                ).toFixed(1)}k`;
              }

              return v;
            },
        },
      },

      series: [

        {
          type:
            "bar",

          data:
            portData.map(
              (r) => r.count
            ),

          barWidth:
            isTight
              ? 12
              : 18,

          itemStyle: {

            borderRadius:
              [4, 4, 0, 0],

            color:
              (p) => {

                const r =
                  portData[
                    p.dataIndex
                  ];

                if (
                  r.rising
                ) {

                  return "#ff1744";
                }

                if (
                  r.category ===
                  "High-Risk Service"
                ) {

                  return "#ff9100";
                }

                if (
                  r.category ===
                  "Privileged Port"
                ) {

                  return "#ffd600";
                }

                return "#38bdf8";
              },
          },

          emphasis: {

            itemStyle: {

              shadowBlur:
                14,

              shadowColor:
                "rgba(255,255,255,0.18)",
            },
          },

          label: {

            show:
              !isTight,

            position:
              "top",

            color:
              "#d1d5db",

            fontSize:
              10,

            formatter:
              (p) => {

                const r =
                  portData[
                    p.dataIndex
                  ];

                const percent =
                  total
                    ? (
                        (
                          r.count /
                          total
                        ) * 100
                      ).toFixed(1)
                    : "0.0";

                return `${percent}%`;
              },
          },
        },
      ],
    };

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
          portData[
            params.dataIndex
          ];

        if (row) {

          fetchPortAttackers(
            row.port
          );
        }
      }
    );

  }, [
    portData,
    total,
  ]);

  // ==================================================
  // RESIZE
  // ==================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (
      !chart ||
      !chartRef.current
    ) {
      return;
    }

    const safeResize =
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

              chart.resize();
            }
          );
      };

    resizeObserverRef.current =
      new ResizeObserver(
        () => {

          safeResize();
        }
      );

    resizeObserverRef.current.observe(
      chartRef.current
    );

    window.addEventListener(
      "resize",
      safeResize
    );

    const timeout =
      setTimeout(
        safeResize,
        150
      );

    return () => {

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      window.removeEventListener(
        "resize",
        safeResize
      );

      clearTimeout(
        timeout
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

  // ==================================================
  // CLEANUP
  // ==================================================

  useEffect(() => {

    return () => {

      clearInterval(
        intervalRef.current
      );

      resizeObserverRef.current?.disconnect();

      resizeObserverRef.current =
        null;

      if (
        resizeFrameRef.current
      ) {

        cancelAnimationFrame(
          resizeFrameRef.current
        );
      }

      if (
        chartInstanceRef.current
      ) {

        chartInstanceRef.current.dispose();

        chartInstanceRef.current =
          null;
      }
    };

  }, []);

  // ==================================================
  // UI
  // ==================================================

  return (

    <div className="
      w-full
      h-full
      min-h-0
      overflow-hidden
      flex
      flex-col
      text-white
    ">

      {/* CHART */}

      <div className="
        flex-1
        min-h-0
        w-full
      ">

        <div
          ref={chartRef}
          className="
            w-full
            h-full
            min-h-0
          "
        />

      </div>

      {/* DRILLDOWN */}

      {drilldown && (

        <div className="
          mt-2
          p-2
          bg-gray-800
          rounded
          text-xs
          shrink-0
          max-h-32
          overflow-auto
        ">

          <div className="
            flex
            justify-between
            mb-1
          ">

            <span className="
              font-bold
            ">
              Port {drilldown.port}
            </span>

            <button
              onClick={() =>
                setDrilldown(null)
              }
              className="
                text-gray-400
                hover:text-white
              "
            >
              Close
            </button>

          </div>

          {drilldown.attackers?.length ? (

            drilldown.attackers.map(
              (a, i) => (

                <div key={i}>
                  {a.sourceIP}
                  {" — "}
                  {a.count}
                </div>
              )
            )

          ) : (

            <div className="
              text-gray-400
            ">
              No data
            </div>
          )}

        </div>
      )}

    </div>
  );
};

export default PortScanningChart;