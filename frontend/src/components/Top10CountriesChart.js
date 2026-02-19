import * as echarts from "echarts";
import axios from "axios";
import React, { useRef, useEffect, useMemo, useState } from "react";

const Top10CountriesChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const resizeObserverRef = useRef(null);

  const [rows, setRows] = useState([]);
  const [range, setRange] = useState("24h"); // 24h, 7d, 30d

  // ----------------------------------------------------
  // Fetch Top Countries (auto-refresh)
  // ----------------------------------------------------
  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        const res = await axios.get(`/api/charts/top-countries?range=${range}`);
        const transformed = Array.isArray(res.data)
          ? res.data.map((item) => ({
              country: item.country ?? "Unknown",
              attacks: Number(item.attacks ?? 0),
            }))
          : [];

        if (mounted) setRows(transformed);
      } catch (error) {
        console.error(
          "Error fetching Top 10 Countries:",
          error?.response?.data || error?.message || error
        );
        if (mounted) setRows([]);
      }
    };

    fetchData();
    const id = setInterval(fetchData, 60000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, [range]);

  const countries = useMemo(() => rows.map((r) => r.country), [rows]);
  const attacks = useMemo(() => rows.map((r) => r.attacks), [rows]);

  // ----------------------------------------------------
  // 🔑 Y-Axis formatter (ONLY new logic added)
  // ----------------------------------------------------
  const formatYAxis = (value) => {
    if (value >= 1_000_000) return `${Math.round(value / 1_000_000)}M`;
    if (value >= 1_000) return `${Math.round(value / 1_000)}k`;
    return value;
  };

  // ----------------------------------------------------
  // Build chart instance once + keep it responsive
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
        const width = chartRef.current?.clientWidth || 0;
        chart.setOption(buildOption(width), { notMerge: true });
      }
    });

    resizeObserverRef.current.observe(chartRef.current);

    return () => {
      if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
      resizeObserverRef.current = null;

      if (chartInstanceRef.current) {
        chartInstanceRef.current.dispose();
        chartInstanceRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ----------------------------------------------------
  // Option builder (responsive)
  // ----------------------------------------------------
  const buildOption = (containerWidth) => {
    const isTight = containerWidth > 0 && containerWidth < 360;

    const xFont = isTight ? 9 : 12;
    const rotate = isTight ? 55 : 35;
    const showBarLabels = !isTight;
    const bottomPad = isTight ? 48 : 40;
    const maxVal = attacks.length ? Math.max(...attacks) : 0;

    return {
      backgroundColor: "transparent",
      animationDuration: 600,
      animationEasing: "cubicOut",

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
          return `<b>Country:</b> ${p.name}<br/><b>Attacks:</b> ${p.value}`;
        },
      },

      grid: {
        left: 44,
        right: 18,
        top: 18,
        bottom: bottomPad,
        containLabel: false,
      },

      xAxis: {
        type: "category",
        data: countries,
        axisTick: { alignWithLabel: true },
        axisLine: { lineStyle: { color: "#666" } },
        axisLabel: {
          color: "#cbd5e1",
          fontSize: xFont,
          rotate,
          interval: 0,
          hideOverlap: true,
          formatter: (name) => {
            if (!name) return "";
            const s = String(name);
            return s.length > (isTight ? 6 : 12)
              ? s.substring(0, isTight ? 6 : 12) + "…"
              : s;
          },
        },
      },

      // ✅ ONLY CHANGE IS formatter BELOW
      yAxis: {
        type: "value",
        min: 0,
        max: maxVal ? undefined : 1,
        axisLine: { lineStyle: { color: "#666" } },
        axisLabel: {
          color: "#cbd5e1",
          fontSize: isTight ? 9 : 11,
          formatter: formatYAxis,
        },
        splitLine: { lineStyle: { color: "#253041" } },
      },

      series: [
        {
          name: "Attacks",
          type: "bar",
          data: attacks,
          barMaxWidth: isTight ? 18 : 34,
          itemStyle: {
            color: "#4caf50",
            borderRadius: [6, 6, 0, 0],
          },
          label: {
            show: showBarLabels,
            position: "top",
            color: "#e5e7eb",
            fontSize: 11,
            formatter: (v) => v.value,
          },
        },
      ],
    };
  };

  // ----------------------------------------------------
  // Update option when data changes
  // ----------------------------------------------------
  useEffect(() => {
    const chart = chartInstanceRef.current;
    if (!chart || !chartRef.current) return;

    if (!rows || rows.length === 0) {
      chart.clear();
      return;
    }

    const width = chartRef.current.clientWidth || 0;
    chart.setOption(buildOption(width), { notMerge: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows]);

  // ----------------------------------------------------
  // CSV Download
  // ----------------------------------------------------
  const downloadCSV = () => {
    const csvData = [
      ["Country", "Attacks"],
      ...rows.map((r) => [r.country, r.attacks]),
    ];

    const csvContent =
      "data:text/csv;charset=utf-8," +
      csvData.map((row) => row.join(",")).join("\n");

    const link = document.createElement("a");
    link.href = encodeURI(csvContent);
    link.download = "top_countries.csv";
    link.click();
  };

  return (
    <div style={{ width: "100%" }}>
      <div
        style={{
          display: "flex",
          gap: 10,
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          marginBottom: 8,
          color: "#fff",
        }}
      >
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span style={{ fontSize: 13, opacity: 0.9 }}>Range:</span>
          <select
            value={range}
            onChange={(e) => setRange(e.target.value)}
            style={{
              background: "#111",
              color: "#fff",
              border: "1px solid #444",
              padding: "6px 8px",
              borderRadius: 6,
              fontSize: 13,
            }}
          >
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>

        <button
          onClick={downloadCSV}
          style={{
            background: "#22c55e",
            color: "#0b1220",
            border: "none",
            padding: "6px 10px",
            borderRadius: 6,
            fontWeight: 700,
            fontSize: 13,
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
        >
          Download CSV
        </button>
      </div>

      <div
        ref={chartRef}
        style={{
          width: "100%",
          height: "100%",
          minHeight: 260,
        }}
      />
    </div>
  );
};

export default Top10CountriesChart;