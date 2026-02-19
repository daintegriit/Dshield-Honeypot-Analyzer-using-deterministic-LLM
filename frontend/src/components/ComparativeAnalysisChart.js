import React, { useEffect, useRef, useState, useMemo } from "react";
import * as echarts from "echarts";
import axios from "axios";

const ComparativeAnalysisChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const resizeObserverRef = useRef(null);

  const [rows, setRows] = useState([]);

  // ----------------------------------------------------
  // Fetch data (auto refresh)
  // ----------------------------------------------------
  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        const res = await axios.get("/api/attacks/comparative-traffic");
        if (!Array.isArray(res.data)) return;

        if (mounted) setRows(res.data);
      } catch (err) {
        console.error("Comparative fetch error:", err);
        if (mounted) setRows([]);
      }
    };

    fetchData();
    const id = setInterval(fetchData, 15000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  const regions = useMemo(() => rows.map((r) => r.region), [rows]);
  const lastWeek = useMemo(() => rows.map((r) => r.lastWeek), [rows]);
  const thisWeek = useMemo(() => rows.map((r) => r.thisWeek), [rows]);

  // ----------------------------------------------------
  // Init chart ONCE
  // ----------------------------------------------------
  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    const chart = chartInstanceRef.current;

    if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
    resizeObserverRef.current = new ResizeObserver(() => {
      chart.resize();
      if (rows.length > 0) {
        chart.setOption(buildOption(), { notMerge: true });
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
  // Option builder
  // ----------------------------------------------------
  const buildOption = () => ({
    backgroundColor: "transparent",

    tooltip: {
      trigger: "axis",
      axisPointer: { type: "shadow" },
      backgroundColor: "#111",
      borderColor: "#444",
      borderWidth: 1,
      textStyle: { color: "#fff" },
      formatter: (params) => {
        const a = params?.[0];
        const b = params?.[1];
        if (!a || !b) return "";
        return `
          <b>${a.name}</b><br/>
          Last Week: ${a.value}<br/>
          This Week: ${b.value}
        `;
      },
    },

    legend: {
      top: 6,
      textStyle: { color: "#e5e7eb" },
      data: ["Last Week", "This Week"],
    },

    grid: {
      left: 40,
      right: 20,
      top: 36,
      bottom: 28,
      containLabel: false,
    },

    xAxis: {
      type: "category",
      data: regions,
      axisLabel: {
        color: "#cbd5e1",
        fontSize: 11,
      },
      axisLine: { lineStyle: { color: "#666" } },
    },

    yAxis: {
      type: "value",
      axisLabel: {
        color: "#cbd5e1",
        formatter: (v) =>
          v >= 1000 ? `${v / 1000}k` : v,
      },
      splitLine: { lineStyle: { color: "#253041" } },
    },

    series: [
      {
        name: "Last Week",
        type: "bar",
        data: lastWeek,
        barWidth: 14,
        itemStyle: { color: "#4575b4" },
      },
      {
        name: "This Week",
        type: "bar",
        data: thisWeek,
        barWidth: 14,
        itemStyle: { color: "#f46d43" },
      },
    ],
  });

  // ----------------------------------------------------
  // Apply option when data arrives
  // ----------------------------------------------------
  useEffect(() => {
    const chart = chartInstanceRef.current;
    if (!chart || rows.length === 0) return;
    chart.setOption(buildOption(), { notMerge: true });
  }, [rows]);

  // ----------------------------------------------------
  // Render (SAME as other charts)
  // ----------------------------------------------------
  return (
    <div
      ref={chartRef}
      style={{
        width: "100%",
        height: 260,
        minHeight: 260,
      }}
    />
  );
};

export default ComparativeAnalysisChart;