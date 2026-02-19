import React, { useEffect, useRef, useState, useMemo } from "react";
import * as echarts from "echarts";
import axios from "axios";

const Top10AttackTypesChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const resizeObserverRef = useRef(null);

  const [rows, setRows] = useState([]);

  // ----------------------------------------------------
  // Severity-based color mapping (UNCHANGED)
  // ----------------------------------------------------
  const getColor = (name = "") => {
    if (name.includes("Brute Force")) return "#ff4d4d";
    if (name.includes("Telnet")) return "#ff884d";
    if (name.includes("Probe")) return "#4da6ff";
    if (name.includes("RDP")) return "#ffd24d";
    if (name.includes("Scan")) return "#66cc66";
    return "#4caf50";
  };

  // ----------------------------------------------------
  // Fetch data (auto refresh)
  // ----------------------------------------------------
  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        const res = await axios.get("/api/charts/top-attack-types");
        const transformed = Array.isArray(res.data)
          ? res.data
              .map((item) => ({
                name: item.attackType,
                value: Number(item.count || 0),
              }))
              .sort((a, b) => b.value - a.value)
          : [];

        if (mounted) setRows(transformed);
      } catch (err) {
        console.error("Attack type fetch error:", err);
        if (mounted) setRows([]);
      }
    };

    fetchData();
    const id = setInterval(fetchData, 60000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  const names = useMemo(() => rows.map((r) => r.name), [rows]);
  const total = useMemo(
    () => rows.reduce((sum, r) => sum + r.value, 0),
    [rows]
  );

  // ----------------------------------------------------
  // Init chart ONCE (with guaranteed height)
  // ----------------------------------------------------
  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    const chart = chartInstanceRef.current;

    // ResizeObserver for dashboard / dashboard2
    if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
    resizeObserverRef.current = new ResizeObserver(() => {
      chart.resize();
      if (rows.length > 0) {
        const width = chartRef.current.clientWidth || 0;
        chart.setOption(buildOption(width), { notMerge: true });
      }
    });

    resizeObserverRef.current.observe(chartRef.current);

    return () => {
      resizeObserverRef.current?.disconnect();
      resizeObserverRef.current = null;
      chartInstanceRef.current?.dispose();
      chartInstanceRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ----------------------------------------------------
  // Option builder (responsive)
  // ----------------------------------------------------
  const buildOption = (containerWidth) => {
    const isTight = containerWidth < 360;

    return {
      backgroundColor: "transparent",

      tooltip: {
        trigger: "axis",
        axisPointer: { type: "shadow" },
        backgroundColor: "#111",
        borderColor: "#444",
        borderWidth: 1,
        textStyle: { color: "#fff" },
        formatter: (params) => {
          const p = params?.[0];
          if (!p) return "";
          const percent = total
            ? ((p.value / total) * 100).toFixed(1)
            : "0.0";
          return `<b>${p.name}</b><br/>Count: ${p.value}<br/>Percent: ${percent}%`;
        },
      },

      grid: {
        left: 70,   // 🔥 closer to Top 10 Countries
        right: 74,
        top: 18,
        bottom: 24,
        containLabel: false,
      },

      xAxis: {
        type: "value",
        axisLine: { lineStyle: { color: "#666" } },
        splitLine: { lineStyle: { color: "#253041" } },
        axisLabel: {
          color: "#cbd5e1",
          fontSize: isTight ? 10 : 11,
          formatter: (value) => {
            if (value >= 1_000_000) return `${value / 1_000_000}M`;
            if (value >= 1_000) return `${value / 1_000}k`;
            return value;
          },
        },
      },

      yAxis: {
        type: "category",
        data: names,
        axisLine: { lineStyle: { color: "#666" } },
        axisTick: { show: false },
        axisLabel: {
          color: "#e5e7eb",
          fontSize: isTight ? 11 : 13,
          margin: 14,
          interval: 0,
          formatter: (name) => {
            if (!name) return "";

            const words = name.split(" ");

            // Always stack words vertically for visual consistency
            return words.join("\n");
          },
        },
      },

      series: [
        {
          type: "bar",
          data: rows.map((r) => ({
            value: r.value,
            itemStyle: { color: getColor(r.name) },
          })),
          barWidth: isTight ? 14 : 20,
          label: {
            show: !isTight,
            position: "right",
            color: "#e5e7eb",
            fontSize: 11,
            formatter: (p) => {
              const percent = total
                ? ((p.value / total) * 100).toFixed(1)
                : "0.0";
              return `${p.value} (${percent}%)`;
            },
          },
        },
      ],
    };
  };

  // ----------------------------------------------------
  // Apply option when data arrives (CRITICAL FIX)
  // ----------------------------------------------------
  useEffect(() => {
    const chart = chartInstanceRef.current;
    if (!chart || !chartRef.current) return;
    if (rows.length === 0) return;

    const width = chartRef.current.clientWidth || 0;
    chart.setOption(buildOption(width), { notMerge: true });
  }, [rows]);

  // ----------------------------------------------------
  // Render (FIXED height)
  // ----------------------------------------------------
  return (
    <div
      ref={chartRef}
      style={{
        width: "100%",
        height: 260,          // ✅ REAL HEIGHT — fixes blank render
        minHeight: 260,
      }}
    />
  );
};

export default Top10AttackTypesChart;