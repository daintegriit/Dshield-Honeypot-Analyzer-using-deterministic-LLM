import * as echarts from "echarts";
import React, {
  useRef,
  useEffect,
  useMemo,
  useState,
} from "react";

import apiService from "../services/apiService";

const Top10CountriesChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);

  const [rows, setRows] = useState([]);
  const [range] = useState("24h");

  // ----------------------------------------------------
  // FETCH
  // ----------------------------------------------------
  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        console.log(
          "🌍 Fetching top countries..."
        );

        const data =
          await apiService.getTopCountries();

        console.log(
          "✅ top countries response:",
          data
        );

        const transformed = Array.isArray(data)
          ? data.map((item) => ({
              country:
                item.country || "Unknown",

              attacks: Number(
                item.attacks ??
                  item.count ??
                  0
              ),
            }))
          : [];

        if (mounted) {
          setRows(transformed);
        }
      } catch (err) {
        console.error(
          "❌ Top Countries error:",
          err
        );

        if (mounted) {
          setRows([]);
        }
      }
    };

    fetchData();

    return () => {
      mounted = false;
    };
  }, [range]);

  // ----------------------------------------------------
  // DERIVED DATA
  // ----------------------------------------------------
  const countries = useMemo(
    () => rows.map((r) => r.country),
    [rows]
  );

  const attacks = useMemo(
    () => rows.map((r) => r.attacks),
    [rows]
  );

  // ----------------------------------------------------
  // INIT + UPDATE CHART
  // ----------------------------------------------------
  useEffect(() => {
    if (!chartRef.current) return;

    // --------------------------------------------
    // PREVENT DUPLICATE INSTANCES
    // --------------------------------------------
    if (!chartInstanceRef.current) {
      console.log(
        "Initializing Countries chart"
      );

      chartInstanceRef.current =
        echarts.init(chartRef.current);
    }

    const chart =
      chartInstanceRef.current;

    // --------------------------------------------
    // EMPTY STATE
    // --------------------------------------------
    if (!rows.length) {
      chart.clear();

      chart.setOption(
        {
          backgroundColor: "transparent",

          graphic: [
            {
              type: "text",

              left: "center",
              top: "middle",

              silent: true,

              style: {
                text: "Waiting for country data...",

                fill: "#666",

                fontSize: 14,

                fontWeight: 400,

                textAlign: "center",
                textVerticalAlign: "middle",
              },
            },
          ],

          xAxis: {
            show: false,
            type: "category",
            data: [],
          },

          yAxis: {
            show: false,
            type: "value",
          },

          series: [],
        },
        true
      );

      chart.resize();

      return;
    }

    // --------------------------------------------
    // RESPONSIVE
    // --------------------------------------------
    const width =
      chartRef.current?.clientWidth || 0;

    const isTight =
      width > 0 && width < 360;

    // --------------------------------------------
    // REAL CHART
    // --------------------------------------------
    const option = {
      backgroundColor:
        "transparent",

      animation: true,

      tooltip: {
        trigger: "axis",

        axisPointer: {
          type: "shadow",
        },

        backgroundColor: "#111",

        borderColor: "#444",

        textStyle: {
          color: "#fff",
        },

        formatter: (params) => {
          const p = params?.[0];

          if (!p) return "";

          return `
            <b>${p.name}</b><br/>
            Attacks: ${p.value}
          `;
        },
      },

      grid: {
        left: 42,
        right: 12,
        top: 20,
        bottom: isTight
          ? 60
          : 45,
      },

      xAxis: {
        type: "category",

        data: countries,

        axisLabel: {
          color: "#cbd5e1",

          fontSize: isTight
            ? 9
            : 11,

          rotate: isTight
            ? 55
            : 35,

          interval: 0,

          hideOverlap: true,
        },

        axisLine: {
          lineStyle: {
            color: "#444",
          },
        },
      },

      yAxis: {
        type: "value",

        axisLabel: {
          color: "#cbd5e1",
        },

        splitLine: {
          lineStyle: {
            color: "#253041",
          },
        },
      },

      series: [
        {
          name: "Attacks",

          type: "bar",

          data: attacks,

          barMaxWidth: isTight
            ? 18
            : 32,

          itemStyle: {
            color: "#22c55e",

            borderRadius: [
              6,
              6,
              0,
              0,
            ],
          },

          label: {
            show: !isTight,

            position: "top",

            color: "#e5e7eb",
          },
        },
      ],
    };

    chart.setOption(option, true);

    chart.resize();
  }, [rows]);

  // ----------------------------------------------------
  // WINDOW RESIZE
  // ----------------------------------------------------
  useEffect(() => {
    const handleResize = () => {
      if (
        chartInstanceRef.current
      ) {
        chartInstanceRef.current.resize();
      }
    };

    window.addEventListener(
      "resize",
      handleResize
    );

    return () => {
      window.removeEventListener(
        "resize",
        handleResize
      );
    };
  }, []);

  // ----------------------------------------------------
  // CLEANUP
  // ----------------------------------------------------
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

  // ----------------------------------------------------
  // UI
  // ----------------------------------------------------
  return (
    <div className="flex flex-col w-full h-full min-h-0 overflow-hidden">
      <div
        ref={chartRef}
        className="flex-1 w-full"
        style={{
          minHeight: "260px",
          height: "100%",
        }}
      />
    </div>
  );
};

export default Top10CountriesChart;