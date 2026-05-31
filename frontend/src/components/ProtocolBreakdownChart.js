import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
} from "react";

import * as echarts from "echarts";
import apiService from "../services/apiService";

/* =====================================================
   IANA PROTOCOL MAP
===================================================== */

const IANA_PROTOCOL_MAP = {
  "1": "ICMP",
  "2": "IGMP",
  "4": "IP-in-IP",
  "6": "TCP",
  "17": "UDP",
  "47": "GRE",
  "50": "ESP",
  "51": "AH",
};

/* =====================================================
   COMPONENT
===================================================== */

const ProtocolBreakdownChart = () => {

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

  // ==================================================
  // STATE
  // ==================================================

  const [protocolData,
    setProtocolData] =
      useState([]);

  // ==================================================
  // NORMALIZE
  // ==================================================

  const mappedProtocolData =
    useMemo(() => {

      return (
        protocolData || []
      )

        .map((item) => {

          const raw =
            String(
              item.protocol ||
              item.name ||
              "Unknown"
            );

          const name =
            IANA_PROTOCOL_MAP[
              raw
            ] || raw;

          return {

            name,

            value:
              Number(
                item.count ??
                item.value ??
                0
              ),
          };
        })

        .filter(
          (r) =>
            r.value > 0
        )

        .sort(
          (a, b) =>
            b.value - a.value
        );

    }, [protocolData]);

  // ==================================================
  // FETCH
  // ==================================================

  useEffect(() => {

    mountedRef.current =
      true;

    const fetchProtocolData =
      async () => {

        try {

          const data =
            await apiService.getProtocolBreakdown();

          if (
            !mountedRef.current
          ) {
            return;
          }

          if (
            Array.isArray(data)
          ) {

            setProtocolData(
              data
            );

          } else {

            setProtocolData([]);
          }

        } catch (err) {

          console.error(
            "Protocol fetch error:",
            err
          );

          if (
            mountedRef.current
          ) {

            setProtocolData([]);
          }
        }
      };

    fetchProtocolData();

    intervalRef.current =
      setInterval(
        fetchProtocolData,
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
  // CHART UPDATE
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
      !mappedProtocolData.length
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
                  "Waiting for protocol telemetry...",

                fill:
                  "#64748b",

                fontSize:
                  13,

                textAlign:
                  "center",
              },
            },
          ],

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
      width < 420;

    // ==============================================
    // TOTAL
    // ==============================================

    const total =
      mappedProtocolData.reduce(
        (sum, p) =>
          sum + p.value,
        0
      );

    // ==============================================
    // OPTION
    // ==============================================

    const option = {

      backgroundColor:
        "transparent",

      animation:
        true,

      animationDuration:
        500,

      animationEasing:
        "cubicOut",

      tooltip: {

        trigger:
          "item",

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

            const percent =
              total
                ? (
                    (
                      params.value /
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
                  color:${params.color};
                ">
                  ${params.name}
                </div>

                <div>
                  Count:
                  <span style="
                    color:#fff;
                    font-weight:bold;
                    margin-left:6px;
                  ">
                    ${params.value.toLocaleString()}
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

              </div>
            `;
          },
      },

      legend: {

        show: true,

        bottom: 2,

        left: "center",

        type: "scroll",

        itemWidth:
          isTight
            ? 10
            : 14,

        itemHeight:
          isTight
            ? 8
            : 10,

        textStyle: {

          color:
            "#cbd5e1",

          fontSize:
            isTight
              ? 9
              : 10,
        },
      },

      graphic: [

        {
          type: "text",

          left: "center",

          top: "40%",

          z: 100,

          style: {

            text:
              total.toLocaleString(),

            fill:
              "#ffffff",

            fontSize:
              isTight
                ? 12
                : 14,

            fontWeight:
              "bold",

            textAlign:
              "center",
          },
        },

        {
          type: "text",

          left: "center",

          top: "50%",

          z: 100,

          style: {

            text:
              "Protocols",

            fill:
              "#94a3b8",

            fontSize:
              isTight
                ? 8
                : 9,

            textAlign:
              "center",
          },
        },
      ],

      series: [

        {
          name:
            "Protocols",

          type:
            "pie",

          radius:
            isTight
              ? ["42%", "68%"]
              : ["44%", "72%"],

          center:
            ["50%", "42%"],

          avoidLabelOverlap:
            true,

          stillShowZeroSum:
            false,

          minAngle: 4,

          clockwise: true,

          label: {
            show: false,
          },

          emphasis: {

            scale: true,

            scaleSize: 6,

            itemStyle: {

              shadowBlur:
                18,

              shadowColor:
                "rgba(0,0,0,0.45)",
            },
          },

          itemStyle: {

            borderColor:
              "#0f172a",

            borderWidth: 2,
          },

          data:
            mappedProtocolData,
        },
      ],
    };

    chart.setOption(
      option,
      true
    );

  }, [mappedProtocolData]);

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
  // RENDER
  // ==================================================

  return (

    <div className="
      w-full
      h-full
      min-h-0
      overflow-hidden
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
  );
};

export default ProtocolBreakdownChart;