import React, {
  useEffect,
  useRef,
  useState,
} from "react";

import * as echarts from "echarts";
import apiService from "../services/apiService";

const SourceASNChart = () => {

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

  const [asnData, setAsnData] =
    useState([]);

  // ==================================================
  // FETCH
  // ==================================================

  useEffect(() => {

    mountedRef.current =
      true;

    const fetchASNData =
      async () => {

        try {

          const data =
            await apiService.getTopASNs();

          if (
            !mountedRef.current
          ) {
            return;
          }

          if (
            !Array.isArray(data)
          ) {

            setAsnData([]);

            return;
          }

          const formatted =
            data
              .map((item) => ({

                asn:
                  item.asn,

                org:
                  (item.org || "")
                    .replace(
                      /, Inc\.| LLC| LTD| Co\./gi,
                      ""
                    )
                    .trim(),

                count:
                  Number(
                    item.count || 0
                  ),
              }))

              .filter(
                (r) =>
                  r.count > 0
              )

              .sort(
                (a, b) =>
                  b.count - a.count
              )

              .slice(0, 10);

          setAsnData(
            formatted
          );

        } catch (err) {

          console.error(
            "ASN fetch error:",
            err
          );

          if (
            mountedRef.current
          ) {

            setAsnData([]);
          }
        }
      };

    fetchASNData();

    intervalRef.current =
      setInterval(
        fetchASNData,
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
      !asnData.length
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
                  "Waiting for ASN telemetry...",

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
      width < 420;

    // ==============================================
    // OPTION
    // ==============================================

    const option = {

      backgroundColor:
        "transparent",

      animation:
        true,

      animationDuration:
        400,

      grid: {

        left:
          isTight
            ? 52
            : 60,

        right:
          isTight
            ? 90
            : 120,

        top: 14,

        bottom: 22,

        containLabel:
          false,
      },

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
          (p) => `
            <b>${p.data.asn}</b><br/>
            Org: ${p.data.org}<br/>
            Attacks: ${p.data.count.toLocaleString()}
          `,
      },

      xAxis: {

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
            "#cbd5e1",

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

      yAxis: [

        // ==========================================
        // LEFT ASN
        // ==========================================

        {
          type:
            "category",

          data:
            asnData.map(
              (i) => i.asn
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
              "#e5e7eb",

            fontSize:
              isTight
                ? 9
                : 11,

            margin: 6,
          },
        },

        // ==========================================
        // RIGHT ORG
        // ==========================================

        {
          type:
            "category",

          position:
            "right",

          data:
            asnData.map(
              (i) => i.org
            ),

          axisLine: {
            show: false,
          },

          axisTick: {
            show: false,
          },

          axisLabel: {

            color:
              "#94a3b8",

            fontSize:
              isTight
                ? 8
                : 10,

            width:
              isTight
                ? 90
                : 140,

            overflow:
              "truncate",

            align:
              "left",

            margin: 10,
          },
        },
      ],

      series: [

        {
          name:
            "Attack Count",

          type:
            "bar",

          yAxisIndex:
            0,

          barWidth:
            isTight
              ? 10
              : 12,

          data:
            asnData.map(
              (i) => ({

                value:
                  i.count,

                asn:
                  i.asn,

                org:
                  i.org,

                count:
                  i.count,
              })
            ),

          itemStyle: {

            color:
              "#ef4444",

            borderRadius:
              [2, 2, 2, 2],
          },

          emphasis: {

            itemStyle: {

              shadowBlur:
                10,

              shadowColor:
                "rgba(239,68,68,0.35)",
            },
          },
        },
      ],
    };

    chart.setOption(
      option,
      true
    );

  }, [asnData]);

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

export default SourceASNChart;