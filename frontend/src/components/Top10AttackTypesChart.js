import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
} from "react";

import * as echarts from "echarts";
import apiService from "../services/apiService";

const Top10AttackTypesChart = () => {

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  const intervalRef =
    useRef(null);

  const mountedRef =
    useRef(true);

  const [rows, setRows] =
    useState([]);

  // ----------------------------------------------------
  // COLOR MAPPING
  // ----------------------------------------------------

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

    return "#4caf50";
  };

  // ----------------------------------------------------
  // NORMALIZE DATA
  // ----------------------------------------------------

  const mappedRows =
    useMemo(() => {

      return (
        rows || []
      )
        .map((item) => ({

          name:
            item.attackType ||
            item.name ||
            "Unknown",

          value: Number(
            item.count ??
            item.value ??
            0
          ),

        }))
        .sort(
          (a, b) =>
            b.value - a.value
        );

    }, [rows]);

  const names =
    useMemo(() => {

      return mappedRows.map(
        (r) => r.name
      );

    }, [mappedRows]);

  const total =
    useMemo(() => {

      return mappedRows.reduce(
        (sum, r) =>
          sum + r.value,
        0
      );

    }, [mappedRows]);

  // ----------------------------------------------------
  // FETCH
  // ----------------------------------------------------

  useEffect(() => {

    mountedRef.current =
      true;

    const fetchData =
      async () => {

        try {

          const data =
            await apiService.getTopAttackTypes();

          if (
            !mountedRef.current
          ) {
            return;
          }

          if (
            Array.isArray(data)
          ) {

            setRows(data);

          } else {

            setRows([]);

          }

        } catch (err) {

          console.error(
            "❌ Attack type fetch error:",
            err
          );

          if (
            mountedRef.current
          ) {

            setRows([]);

          }
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

  // ----------------------------------------------------
  // CHART INIT
  // ----------------------------------------------------

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
          }
        );
    }

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

  // ----------------------------------------------------
  // CHART UPDATE
  // ----------------------------------------------------

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (!chart) {
      return;
    }

    // --------------------------------------------
    // EMPTY STATE
    // --------------------------------------------

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

              left:
                "center",

              top:
                "middle",

              silent:
                true,

              style: {

                text:
                  "Waiting for attack type data...",

                fill:
                  "#666",

                fontSize:
                  14,

                fontWeight:
                  400,

                textAlign:
                  "center",

                textVerticalAlign:
                  "middle",
              },
            },
          ],

          xAxis: {
            show:
              false,
            type:
              "value",
          },

          yAxis: {
            show:
              false,
            type:
              "category",
          },

          series: [],
        },
        true
      );

      return;
    }

    // --------------------------------------------
    // RESPONSIVE WIDTH
    // --------------------------------------------

    const width =
      chartRef.current
        ?.clientWidth || 0;

    const isTight =
      width > 0 &&
      width < 420;

    // --------------------------------------------
    // OPTION
    // --------------------------------------------

    const option = {

      backgroundColor:
        "transparent",

      animation:
        true,

      tooltip: {

        trigger:
          "axis",

        axisPointer: {
          type:
            "shadow",
        },

        backgroundColor:
          "#111",

        borderColor:
          "#444",

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

            const percent =
              total
                ? (
                    (p.value /
                      total) *
                    100
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
            ? 100
            : 130,

        right: 35,
        top: 20,
        bottom: 25,

        containLabel:
          false,
      },

      xAxis: {

        type:
          "value",

        axisLine: {

          lineStyle: {
            color:
              "#555",
          },
        },

        splitLine: {

          lineStyle: {
            color:
              "#253041",
          },
        },

        axisLabel: {

          color:
            "#cbd5e1",

          formatter:
            (v) => {

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

        type:
          "category",

        data:
          names,

        axisLine: {

          lineStyle: {
            color:
              "#555",
          },
        },

        axisTick: {
          show:
            false,
        },

        axisLabel: {

          color:
            "#e5e7eb",

          fontSize:
            isTight
              ? 10
              : 12,

          interval:
            0,

          width:
            isTight
              ? 85
              : 120,

          overflow:
            "truncate",

          formatter:
            (name) => {

              if (!name) {
                return "";
              }

              return String(name);
            },
        },
      },

      series: [

        {
          name:
            "Attack Types",

          type:
            "bar",

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

            fontSize:
              11,

            formatter:
              (p) => {

                const percent =
                  total
                    ? (
                        (p.value /
                          total) *
                        100
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

  }, [
    mappedRows,
    names,
    total,
  ]);

  // ----------------------------------------------------
  // SAFE WINDOW RESIZE ONLY
  // ----------------------------------------------------

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (!chart) {
      return;
    }

    let frame =
      null;

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

                chart.resize();
              }
            }
          );
      };

    window.addEventListener(
      "resize",
      resize
    );

    return () => {

      cancelAnimationFrame(
        frame
      );

      window.removeEventListener(
        "resize",
        resize
      );
    };

  }, []);

  // ----------------------------------------------------
  // UI
  // ----------------------------------------------------

  return (

    <div className="
      w-full
      overflow-hidden
    ">

      <div
        ref={chartRef}
        className="
          w-full
        "
        style={{
          height: 260,
        }}
      />

    </div>
  );
}

export default Top10AttackTypesChart;