import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import axios from "axios";

const AttackTrendsChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);

  const [attackData, setAttackData] = useState([]);
  const [smaPeriod, setSmaPeriod] = useState(5);

  // ----------------------------------------------------
  // Utility: Simple Moving Average (SMA)
  // ----------------------------------------------------
  const calculateSMA = (data, period) => {
    if (period === 0) return Array(data.length).fill(null);

    const sma = [];
    for (let i = 0; i < data.length; i++) {
      if (i < period) sma.push(null);
      else {
        const slice = data.slice(i - period, i);
        sma.push(slice.reduce((a, b) => a + b, 0) / period);
      }
    }
    return sma;
  };

  // ----------------------------------------------------
  // Fetch trends (polling)
  // ----------------------------------------------------
  useEffect(() => {
    const fetchTrends = async () => {
      try {
        const { data } = await axios.get("/api/charts/attack-trends");
        setAttackData(data);
      } catch (err) {
        console.error("❌ Error fetching attack trends:", err);
      }
    };

    fetchTrends();
    const id = setInterval(fetchTrends, 5000); // keep polling sane
    return () => clearInterval(id);
  }, []);

  // ----------------------------------------------------
  // Derived counters
  // ----------------------------------------------------
  const latestCount =
    attackData.length > 0 ? attackData[attackData.length - 1].count : 0;

  const lastHourTotal = attackData.reduce((sum, p) => sum + p.count, 0);

  // ----------------------------------------------------
  // Render chart
  // ----------------------------------------------------
  useEffect(() => {
    if (!chartRef.current || attackData.length === 0) return;

    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    const chart = chartInstanceRef.current;

    const times = attackData.map((item) => item.time);
    const counts = attackData.map((item) => item.count);
    const movingAvg = calculateSMA(counts, smaPeriod);

    const latestPoint = counts[counts.length - 1];
    const maxPoint = Math.max(...counts);
    const maxIndex = counts.indexOf(maxPoint);

    const option = {
      backgroundColor: "transparent",

      tooltip: {
        trigger: "axis",
        backgroundColor: "#222",
        borderColor: "#555",
        borderWidth: 1,
        textStyle: { color: "#fff" }
      },

      dataZoom: [
        { type: "inside" },
        {
          type: "slider",
          bottom: 12,
          height: 20
        }
      ],

      xAxis: {
        type: "category",
        data: times,
        axisLabel: {
          color: "#ccc",
          rotate: 30,
          interval: "auto",
          hideOverlap: true,
          formatter: (value) => value.substring(11)
        },
        axisLine: { lineStyle: { color: "#666" } }
      },

      yAxis: {
        type: "value",
        axisLabel: { color: "#ccc" },
        axisLine: { lineStyle: { color: "#666" } },
        splitLine: { lineStyle: { color: "#333" } }
      },

      grid: {
        left: "8%",
        right: "5%",
        top: "12%",
        bottom: 60
      },

      series: [
        {
          name: "Attacks",
          type: "line",
          smooth: true,
          data: counts,
          symbolSize: 10,
          label: {
            show: true,
            formatter: (params) =>
              params.dataIndex === counts.length - 1
                ? `${params.value} attacks`
                : "",
            position: "top",
            color: "#ffb74d",
            fontSize: 12,
            fontWeight: "bold"
          },
          itemStyle: {
            color: (params) => {
              const value = params.value;
              if (value > 100) return "#ff1744";
              if (value > 50) return "#ff9100";
              if (value > 20) return "#ffd600";
              return "#4fc3f7";
            }
          },
          lineStyle: {
            width: 3,
            color: "#ff7043",
            shadowColor: "rgba(255, 112, 67, 0.6)",
            shadowBlur: 12
          },
          areaStyle: {
            color: new echarts.graphic.LinearGradient(0, 0, 0, 1, [
              { offset: 0, color: "rgba(255,112,67,0.4)" },
              { offset: 1, color: "rgba(255,112,67,0)" }
            ])
          }
        },
        {
          name: `Trend (SMA-${smaPeriod})`,
          type: "line",
          smooth: true,
          data: movingAvg,
          lineStyle: {
            width: 2,
            color: "#4fc3f7"
          },
          symbol: "none"
        },
        {
          name: "Max Spike",
          type: "effectScatter",
          data: [[times[maxIndex], maxPoint]],
          symbolSize: 22,
          rippleEffect: {
            brushType: "stroke",
            scale: 4,
            period: 3
          },
          itemStyle: {
            color: "#ff1744",
            shadowBlur: 25,
            shadowColor: "rgba(255,0,0,0.9)"
          },
          zlevel: 10
        },
        {
          name: "Latest",
          type: "effectScatter",
          data: [[times[times.length - 1], latestPoint]],
          symbolSize: 15,
          rippleEffect: {
            brushType: "stroke",
            scale: 3,
            period: 4
          },
          itemStyle: { color: "#ff7043" },
          zlevel: 10
        }
      ]
    };

    chart.setOption(option);
  }, [attackData, smaPeriod]);

  // ----------------------------------------------------
  // Container-aware resize (CRITICAL FIX)
  // ----------------------------------------------------
  useEffect(() => {
    if (!chartRef.current || !chartInstanceRef.current) return;

    const observer = new ResizeObserver(() => {
      chartInstanceRef.current.resize();
    });

    observer.observe(chartRef.current);

    return () => observer.disconnect();
  }, []);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        width: "100%",
        height: "100%",
        minHeight: 0
      }}
    >
      <div style={{ color: "#fff", marginBottom: "10px", fontSize: "15px" }}>
        <strong>Current Minute:</strong> {latestCount} attacks&nbsp; |&nbsp;
        <strong>Last Hour Total:</strong> {lastHourTotal}
      </div>

      <div style={{ color: "#fff", marginBottom: "6px", fontSize: "14px" }}>
        Smoothing:
        <select
          value={smaPeriod}
          onChange={(e) => setSmaPeriod(Number(e.target.value))}
          style={{
            marginLeft: "10px",
            background: "#111",
            color: "#fff",
            border: "1px solid #444",
            padding: "4px"
          }}
        >
          <option value={0}>None</option>
          <option value={3}>SMA-3</option>
          <option value={5}>SMA-5</option>
          <option value={10}>SMA-10</option>
        </select>
      </div>

      <div
        ref={chartRef}
        style={{
          flex: 1,
          width: "100%",
          minHeight: "220px"
        }}
      />
    </div>
  );
};

export default AttackTrendsChart;