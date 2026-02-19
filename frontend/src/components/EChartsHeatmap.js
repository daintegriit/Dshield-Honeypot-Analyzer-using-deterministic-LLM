import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import axios from "axios";

const EChartsHeatmap = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const containerRef = useRef(null);

  const [heatmapData, setHeatmapData] = useState([]);

  // -------------------------------------------------------
  // Fetch heatmap data
  // -------------------------------------------------------
  const fetchHeatmapData = async () => {
    try {
      const { data } = await axios.get("/api/charts/heatmap");
      if (Array.isArray(data)) setHeatmapData(data);
    } catch (err) {
      console.error("❌ Heatmap fetch error:", err);
    }
  };

  useEffect(() => {
    fetchHeatmapData();
  }, []);

  // -------------------------------------------------------
  // Render Heatmap
  // -------------------------------------------------------
  useEffect(() => {
    if (!chartRef.current || heatmapData.length === 0) return;

    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    const chart = chartInstanceRef.current;

    // ---------------------------
    // Axis labels
    // ---------------------------
    const hours = [...new Set(heatmapData.map(d => d[1]))]
      .sort((a, b) => a - b)
      .map(h => `${h}:00`);

    const days = [...new Set(heatmapData.map(d => d[0]))]
      .sort((a, b) => a - b)
      .map(d => `Day ${d}`);

    const hourIndex = Object.fromEntries(hours.map((h, i) => [h, i]));
    const dayIndex = Object.fromEntries(days.map((d, i) => [d, i]));

    const indexedData = heatmapData.map(([day, hour, count]) => [
      dayIndex[`Day ${day}`],
      hourIndex[`${hour}:00`],
      count,
    ]);

    const option = {
      backgroundColor: "transparent",

      title: {
        text: "Honeypot Attack Heatmap",
        left: "center",
        top: 10,
        textStyle: {
          color: "#fff",
          fontSize: 16,
          fontWeight: "normal",
        },
      },

      tooltip: {
        position: "top",
        formatter: p =>
          `Day: ${days[p.data[0]]}<br/>
           Hour: ${hours[p.data[1]]}<br/>
           Attacks: ${p.data[2]}`,
      },

      grid: {
        top: 60,
        left: 50,
        right: 30,
        bottom: 90, // ✅ space for visualMap + labels
        containLabel: true,
      },

      xAxis: {
        type: "category",
        data: hours,
        axisLabel: {
          color: "#ccc",
          rotate: 45,
          interval: "auto",
          hideOverlap: true,
        },
        splitArea: { show: true },
        axisLine: { lineStyle: { color: "#555" } },
      },

      yAxis: {
        type: "category",
        data: days,
        axisLabel: { color: "#ccc" },
        splitArea: { show: true },
        axisLine: { lineStyle: { color: "#555" } },
      },

      visualMap: {
        min: 0,
        max: Math.max(...heatmapData.map(d => d[2])),
        calculable: true,
        orient: "horizontal",
        left: "center",
        bottom: 20, // ✅ never clipped
        textStyle: { color: "#ccc" },
        inRange: {
          color: [
            "#313695",
            "#4575b4",
            "#74add1",
            "#abd9e9",
            "#fee090",
            "#fdae61",
            "#f46d43",
            "#d73027",
          ],
        },
      },

      series: [
        {
          name: "Attacks",
          type: "heatmap",
          data: indexedData,
          emphasis: {
            itemStyle: {
              shadowBlur: 12,
              shadowColor: "rgba(0,0,0,0.6)",
            },
          },
        },
      ],
    };

    chart.setOption(option, true);

    // ---------------------------------------------------
    // ResizeObserver — works in ANY dashboard layout
    // ---------------------------------------------------
    const observer = new ResizeObserver(() => {
      chart.resize();
    });

    if (containerRef.current) observer.observe(containerRef.current);

    return () => observer.disconnect();
  }, [heatmapData]);

  // -------------------------------------------------------
  // Component container (NO hardcoded padding)
  // -------------------------------------------------------
  return (
    <div ref={containerRef} style={{ width: "100%", height: "100%" }}>
      <div
        ref={chartRef}
        style={{
          width: "100%",
          height: "100%",
          minHeight: "320px", // safe floor for small cards
        }}
      />
    </div>
  );
};

export default EChartsHeatmap;