import React, { useEffect, useRef, useState, useMemo } from "react";
import * as echarts from "echarts";
import axios from "axios";

const PortScanningChart = () => {
  const chartRef = useRef(null);
  const chartInstanceRef = useRef(null);
  const resizeObserverRef = useRef(null);

  const [portData, setPortData] = useState([]);
  const [drilldown, setDrilldown] = useState(null);
  const prevCountsRef = useRef({});

  // -------------------------------
  // Risk Classification
  // -------------------------------
  const getPortCategory = (port) => {
    const p = Number(port);
    if ([22, 80, 443, 3389, 5900].includes(p)) return "High-Risk Service";
    if (p < 1024) return "Privileged Port";
    return "Ephemeral / Normal Port";
  };

  // -------------------------------
  // Drilldown
  // -------------------------------
  const fetchPortAttackers = async (port) => {
    try {
      const res = await axios.get(`/api/attacks/port-details?port=${port}`);
      setDrilldown({ port, attackers: res.data });
    } catch (err) {
      console.error("Error fetching port drilldown:", err);
    }
  };

  // -------------------------------
  // Fetch data
  // -------------------------------
  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      try {
        const res = await axios.get("/api/charts/port-scanning");
        if (!Array.isArray(res.data)) return;

        const prev = prevCountsRef.current;

        const enriched = res.data
          .map((row) => ({
            ...row,
            category: getPortCategory(row.port),
            previous: prev[row.port],
            // 🔴 FIX: only rising if previous EXISTS and count increased
            rising:
              prev[row.port] !== undefined &&
              row.count > prev[row.port],
          }))
          .sort((a, b) => b.count - a.count);

        if (mounted) {
          setPortData(enriched);
          prevCountsRef.current = enriched.reduce((acc, r) => {
            acc[r.port] = r.count;
            return acc;
          }, {});
        }
      } catch (err) {
        console.error("Port scan fetch error:", err);
      }
    };

    fetchData();
    const id = setInterval(fetchData, 60000);
    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  const total = useMemo(
    () => portData.reduce((s, r) => s + r.count, 0),
    [portData]
  );

  // -------------------------------
  // Init chart ONCE
  // -------------------------------
  useEffect(() => {
    if (!chartRef.current) return;

    if (!chartInstanceRef.current) {
      chartInstanceRef.current = echarts.init(chartRef.current);
    }

    const chart = chartInstanceRef.current;

    if (resizeObserverRef.current) resizeObserverRef.current.disconnect();
    resizeObserverRef.current = new ResizeObserver(() => {
      chart.resize();
      if (portData.length > 0) {
        const w = chartRef.current.clientWidth || 0;
        chart.setOption(buildOption(w), { notMerge: true });
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

  // -------------------------------
  // Option builder (UNCHANGED)
  // -------------------------------
  const buildOption = (width) => {
    const isTight = width < 360;

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
          const r = portData[p.dataIndex];
          const percent = total
            ? ((r.count / total) * 100).toFixed(1)
            : "0.0";
          return `<b>Port ${r.port}</b><br/>Count: ${r.count}<br/>Percent: ${percent}%`;
        },
      },

      grid: {
        left: 40,
        right: 10,
        top: 18,
        bottom: 30,
        containLabel: false,
      },

      xAxis: {
        type: "category",
        data: portData.map((r) => `${r.port}${r.rising ? " ↑" : ""}`),
        axisLabel: {
          color: "#cbd5e1",
          rotate: 40,
          fontSize: isTight ? 10 : 11,
          interval: 0, // ✅ FORCE ALL PORT LABELS TO SHOW
        },
        axisLine: { lineStyle: { color: "#666" } },
      },

      yAxis: {
        type: "value",
        interval: 5000,
        axisLabel: {
          color: "#cbd5e1",
          formatter: (v) => (v === 0 ? "0" : `${v / 1000}k`),
        },
        splitLine: { lineStyle: { color: "#253041" } },
      },

      series: [
        {
          type: "bar",
          data: portData.map((r) => r.count),
          barWidth: isTight ? 14 : 20,
          itemStyle: {
            color: (p) => {
              const r = portData[p.dataIndex];
              if (r.rising) return "#ff4d4d";
              if (r.category === "High-Risk Service") return "#ff7f50";
              if (r.category === "Privileged Port") return "#f4b042";
              return "#7fd48b";
            },
          },
          label: {
            show: !isTight,
            position: "top",
            rotate: 30,
            align: "center",
            verticalAlign: "middle",
            offset: [8, 0],   // 🔥 VISUAL CENTERING FIX
            color: "#e5e7eb",
            formatter: (p) => {
              const r = portData[p.dataIndex];
              const percent = total
                ? ((r.count / total) * 100).toFixed(1)
                : "0.0";
              return `(${percent}%)`;
            },
          },
        },
      ],
    };
  };

  // -------------------------------
  // Apply option when data arrives
  // -------------------------------
  useEffect(() => {
    const chart = chartInstanceRef.current;
    if (!chart || portData.length === 0) return;
    const w = chartRef.current.clientWidth || 0;
    chart.setOption(buildOption(w), { notMerge: true });
  }, [portData]);

  // -------------------------------
  // Render — SAME AS OTHER CHARTS
  // -------------------------------
  return (
    <>
      <div
        ref={chartRef}
        style={{
          width: "100%",
          height: 260,
          minHeight: 260,
        }}
      />

      {drilldown && (
        <div className="mt-4 p-4 bg-gray-700 rounded-lg">
          <div className="flex justify-between">
            <h3 className="text-lg font-bold">
              Attackers targeting port {drilldown.port}
            </h3>
            <button
              className="text-gray-300 hover:text-white"
              onClick={() => setDrilldown(null)}
            >
              Close
            </button>
          </div>

          {drilldown.attackers?.length > 0 ? (
            <ul className="mt-2 text-sm">
              {drilldown.attackers.map((a, i) => (
                <li key={i}>
                  <strong>{a.sourceIP}</strong> — {a.count} hits
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-gray-300 text-sm mt-2">
              No attacker data available.
            </p>
          )}
        </div>
      )}
    </>
  );
};

export default PortScanningChart;