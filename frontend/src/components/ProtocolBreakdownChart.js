import React, { useEffect, useRef, useState } from "react";
import * as echarts from "echarts";
import axios from "axios";

/* ✅ ADD: IANA Protocol Number Mapping */
const IANA_PROTOCOL_MAP = {
  "1": "ICMP",
  "2": "IGMP",
  "4": "IP-in-IP",
  "6": "TCP",
  "17": "UDP",
  "47": "GRE",
  "50": "ESP",
  "51": "AH",
};

const ProtocolBreakdownChart = () => {
  const chartRef = useRef(null);
  const [protocolData, setProtocolData] = useState([]);

  // ----------------------------------------
  // Fetch protocol data (inside effect — your structure)
  // ----------------------------------------
  useEffect(() => {
    const fetchProtocolData = async () => {
      try {
        const res = await axios.get("/api/charts/protocol-breakdown");

        const formatted = res.data.map((item) => {
          /* ✅ ADD: translate numeric protocol → IANA name */
          const raw = String(item.protocol || "Unknown");
          const name = IANA_PROTOCOL_MAP[raw] || raw;

          return {
            name,
            value: item.count || 0,
          };
        });

        setProtocolData(formatted);
      } catch (err) {
        console.error("Protocol fetch error:", err);
      }
    };

    fetchProtocolData();

    // Auto-refresh every 60 seconds (same structure as your other charts)
    const interval = setInterval(fetchProtocolData, 60000);
    return () => clearInterval(interval);
  }, []); // <-- No ESLint warning because function is *inside* effect

  // ----------------------------------------
  // Build chart effect
  // ----------------------------------------
  useEffect(() => {
    if (!chartRef.current || protocolData.length === 0) return;

    const chart = echarts.init(chartRef.current);

    const total = protocolData.reduce((sum, p) => sum + p.value, 0);

    const option = {
      backgroundColor: "transparent",

      tooltip: {
        trigger: "item",
        formatter: (params) => {
          const percent = ((params.value / total) * 100).toFixed(1);
          return `${params.name}: ${params.value} (${percent}%)`;
        },
      },

      series: [
        {
          name: "Protocols",
          type: "pie",
          radius: ["40%", "65%"],
          label: {
            show: true,
            color: "#fff",
            formatter: "{b}: {c} ({d}%)",
          },
          itemStyle: {
            borderColor: "#111",
            borderWidth: 2,
          },
          data: protocolData,
        },
      ],
    };

    chart.setOption(option);

    const resize = () => chart.resize();
    window.addEventListener("resize", resize);

    return () => {
      window.removeEventListener("resize", resize);
      chart.dispose();
    };
  }, [protocolData]);

  return (
    <div
      ref={chartRef}
      style={{ width: "100%", height: "400px" }}
    />
  );
};

export default ProtocolBreakdownChart;