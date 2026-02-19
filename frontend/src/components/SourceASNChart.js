import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import axios from "axios";

const SourceASNChart = () => {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);
  const resizeObserverRef = useRef(null);

  const [asnData, setAsnData] = useState([]);

  // -------------------------------
  // Fetch ASN data
  // -------------------------------
  useEffect(() => {
    const fetchASNData = async () => {
      try {
        const res = await axios.get("/api/charts/top-asns");

        const formatted = res.data
          .map((item) => ({
            asn: item.asn,
            org: (item.org || "")
              .replace(/, Inc\.| LLC| LTD| Co\./gi, "")
              .trim(),
            count: item.count
          }))
          .sort((a, b) => b.count - a.count);

        setAsnData(formatted);
      } catch (err) {
        console.error("ASN fetch error:", err);
      }
    };

    fetchASNData();
  }, []);

  // -------------------------------
  // Chart init + resize handling
  // -------------------------------
  useEffect(() => {
    if (!chartRef.current || asnData.length === 0) return;

    if (!chartInstance.current) {
      chartInstance.current = echarts.init(chartRef.current);
    }

    const chart = chartInstance.current;

    const option = {
      backgroundColor: "transparent",

      tooltip: {
        trigger: "item",
        backgroundColor: "#111",
        borderColor: "#333",
        textStyle: { color: "#fff" },
        formatter: (p) => `
          <b>${p.data.asn}</b><br/>
          Org: ${p.data.org}<br/>
          Attacks: ${p.data.count.toLocaleString()}
        `
      },

      grid: {
        left: 70,   // 🔥 closer to Top 10 Countries
        right: 150,
        top: 18,
        bottom: 24,
        containLabel: false,
      },

      // LEFT → ASN
      yAxis: [
        {
          type: "category",
          data: asnData.map((i) => i.asn),
          axisLine: { lineStyle: { color: "#555" } },
          axisTick: { show: false },
          axisLabel: {
            color: "#e5e7eb",
            fontSize: 11,
            margin: 8
          }
        },

        // RIGHT → ORG
        {
          type: "category",
          data: asnData.map((i) => i.org),
          position: "right",
          axisLine: { show: false },
          axisTick: { show: false },
          axisLabel: {
            color: "#9ca3af",
            fontSize: 11,
            width: 180,
            overflow: "truncate",
            align: "left",
            margin: 12
          }
        }
      ],

      xAxis: {
        type: "value",
        axisLabel: {
          color: "#cbd5e1",
          formatter: (v) => (v >= 1000 ? `${v / 1000}k` : v)
        },
        axisLine: { lineStyle: { color: "#555" } },
        splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } }
      },

      series: [
        {
          name: "Attack Count",
          type: "bar",
          yAxisIndex: 0,
          barWidth: 12,
          data: asnData.map((i) => ({
            value: i.count,
            asn: i.asn,
            org: i.org,
            count: i.count
          })),
          itemStyle: {
            color: "#ef4444",
            borderRadius: [2, 2, 2, 2]
          },
          label: {
            show: false   // 🔥 labels cause overflow — tooltips handle detail
          }
        }
      ]
    };

    chart.setOption(option, true);

    // 🔥 ResizeObserver = container-aware
    if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
    resizeObserverRef.current = new ResizeObserver(() => chart.resize());
    resizeObserverRef.current.observe(chartRef.current);

    return () => {
      if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
      resizeObserverRef.current = null;
    };
  }, [asnData]);

  // -------------------------------
  // Render (container-controlled)
  // -------------------------------
  return (
    <div
      ref={chartRef}
      style={{
        width: "100%",
        height: "100%",     // 🔥 inherits parent
        minHeight: 260      // consistent with other charts
      }}
    />
  );
};

export default SourceASNChart;