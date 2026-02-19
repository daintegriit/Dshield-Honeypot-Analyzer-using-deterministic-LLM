import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import axios from "axios";

// -----------------------------------------------------
// Severity colors (SOC standard)
// -----------------------------------------------------
const severityColors = {
  critical: "#d9534f",
  high: "#f0ad4e",
  medium: "#f7e463",
  low: "#5bc0de",
};

const SeverityDistributionChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const resizeObserverRef = useRef(null);

  const [severityData, setSeverityData] = useState([]);

  // -----------------------------------------------------
  // Fetch Severity Data (60s refresh)
  // -----------------------------------------------------
  useEffect(() => {
    let mounted = true;

    const fetchSeverityData = async () => {
      try {
        const res = await axios.get("/api/charts/severity-distribution");
        if (!Array.isArray(res.data)) return;

        const order = ["critical", "high", "medium", "low"];
        const sorted = [...res.data].sort(
          (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity)
        );

        if (mounted) setSeverityData(sorted);
      } catch (err) {
        console.error("Severity fetch error:", err);
        if (mounted) setSeverityData([]);
      }
    };

    fetchSeverityData();
    const id = setInterval(fetchSeverityData, 60000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  // -----------------------------------------------------
  // Init chart ONCE (same pattern as other charts)
  // -----------------------------------------------------
  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    const chart = chartInstanceRef.current;

    if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
    resizeObserverRef.current = new ResizeObserver(() => {
      chart.resize();
      if (severityData.length > 0) {
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

  // -----------------------------------------------------
  // Option builder (pure donut, no title)
  // -----------------------------------------------------
  const buildOption = () => {
    const total = severityData.reduce((s, i) => s + i.count, 0);

    return {
      backgroundColor: "transparent",

      tooltip: {
        trigger: "item",
        backgroundColor: "#111",
        borderColor: "#444",
        borderWidth: 1,
        textStyle: { color: "#fff" },
        formatter: (p) => {
          const percent = total
            ? ((p.value / total) * 100).toFixed(1)
            : "0.0";
          return `<b>${p.name.toUpperCase()}</b><br/>Count: ${p.value}<br/>Percent: ${percent}%`;
        },
      },

      series: [
        {
          type: "pie",
          radius: ["40%", "68%"],
          center: ["50%", "50%"],
          avoidLabelOverlap: true,

          data: severityData.map((item) => ({
            name: item.severity,
            value: item.count,
            itemStyle: {
              color: severityColors[item.severity],
              borderColor: "#0f172a",
              borderWidth: 1,
            },
          })),

          label: {
            show: true,
            color: "#e5e7eb",
            fontSize: 12,
            formatter: ({ name, value }) => {
              const percent = total
                ? ((value / total) * 100).toFixed(1)
                : "0.0";
              return `${name}: ${percent}%`;
            },
          },

          labelLine: {
            length: 14,
            length2: 10,
            lineStyle: { color: "#cbd5e1" },
          },

          emphasis: {
            scale: true,
            itemStyle: {
              shadowBlur: 10,
              shadowColor: "rgba(0,0,0,0.6)",
            },
          },
        },
      ],
    };
  };

  // -----------------------------------------------------
  // Apply option when data arrives
  // -----------------------------------------------------
  useEffect(() => {
    const chart = chartInstanceRef.current;
    if (!chart || severityData.length === 0) return;
    chart.setOption(buildOption(), { notMerge: true });
  }, [severityData]);

  // -----------------------------------------------------
  // Render — EXACTLY like other dashboard charts
  // -----------------------------------------------------
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

export default SeverityDistributionChart;