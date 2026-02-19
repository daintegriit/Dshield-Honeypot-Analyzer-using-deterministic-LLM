import React, { useState, useEffect, useRef } from "react";
import { Bar } from "react-chartjs-2";
import axios from "axios";
import {
  Chart,
  LinearScale,
  CategoryScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";
import zoomPlugin from "chartjs-plugin-zoom";

Chart.register(
  LinearScale,
  CategoryScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  zoomPlugin
);

const Top25SourceIPsChart = () => {
  const [ipData, setIpData] = useState([]); // enriched IP rows
  const [interval, setIntervalRange] = useState("24h"); // 24h, 7d, 30d
  const [limit, setLimit] = useState(25); // 25, 50, 100
  const [selectedIP, setSelectedIP] = useState(null);
  const [drillDownData, setDrillDownData] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [showTable, setShowTable] = useState(false);

  // store previous counts for trend / "new" flag
  const prevCountsRef = useRef({});

  // -------------------------------
  // Helpers
  // -------------------------------

  const getFlagEmoji = (countryCode = "") => {
    if (!countryCode || countryCode.length !== 2) return "";
    const codePoints = countryCode
      .toUpperCase()
      .split("")
      .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  };

  const getSeverityColor = (value, max) => {
    if (!max) return "rgba(75,192,192,0.7)";
    const pct = value / max;
    if (pct > 0.7) return "#ff4d4d"; // high
    if (pct > 0.4) return "#ffa64d"; // medium
    return "#4caf50"; // low
  };

  const formatLabel = (row) => {
    const flag = getFlagEmoji(row.countryCode);
    return flag ? `${flag} ${row.sourceIP}` : row.sourceIP;
  };

  // -------------------------------
  // Fetch IP data (with 60s auto-refresh)
  // -------------------------------
  useEffect(() => {
    let timerId;

    const fetchData = async () => {
      try {
        console.log(
          `Fetching Top ${limit} Source IPs for interval: ${interval}...`
        );

        const res = await axios.get(
          `/api/charts/top-ips?limit=${limit}&interval=${interval}`
        );

        // Generic mapping to be robust to backend fields
        const raw = res.data || [];
        const prevCounts = prevCountsRef.current || {};

        const enriched = raw.map((item) => {
          const sourceIP = item.sourceIP || item._id || "Unknown";
          const count = item.count || 0;
          const country =
            item.country ||
            item.geo?.country ||
            item.country_name ||
            "Unknown";
          const countryCode =
            item.countryCode ||
            item.geo?.countryCode ||
            item.country_code ||
            "";

          const prev = prevCounts[sourceIP] || 0;
          const isNew = prev === 0 && count > 0;
          const changePct =
            prev > 0 ? (((count - prev) / prev) * 100).toFixed(1) : null;

          return {
            sourceIP,
            count,
            country,
            countryCode,
            prevCount: prev,
            isNew,
            changePct,
          };
        });

        // sort by count desc
        enriched.sort((a, b) => b.count - a.count);

        // update state
        setIpData(enriched);
        setLastUpdated(new Date());

        // update prevCounts for next refresh
        prevCountsRef.current = enriched.reduce((acc, row) => {
          acc[row.sourceIP] = row.count;
          return acc;
        }, {});
      } catch (err) {
        console.error("Error fetching Top Source IPs:", err);
      }
    };

    fetchData();
    timerId = setInterval(fetchData, 60000); // 60 sec

    return () => clearInterval(timerId);
  }, [interval, limit]);

  // -------------------------------
  // Drilldown fetch for a clicked IP
  // -------------------------------
  const fetchDrillDownData = async (ip) => {
    try {
      const res = await axios.get(`/api/attacks/ip-details?sourceIP=${ip}`);
      setSelectedIP(ip);
      setDrillDownData(res.data);
    } catch (err) {
      console.error(`Error fetching details for IP ${ip}:`, err);
    }
  };

  // -------------------------------
  // Derived chart data & stats
  // -------------------------------
  const totalAttacks = ipData.reduce((sum, row) => sum + row.count, 0);
  const uniqueIPs = ipData.length;

  const maxCount = ipData.reduce(
    (max, row) => (row.count > max ? row.count : max),
    0
  );

  const labels = ipData.map(formatLabel);
  const counts = ipData.map((row) => row.count);
  const backgroundColors = ipData.map((row) =>
    getSeverityColor(row.count, maxCount)
  );

  const chartData = {
    labels,
    datasets: [
      {
        label: "Traffic Count",
        data: counts,
        backgroundColor: backgroundColors,
        borderColor: backgroundColors.map((c) => c),
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,

    // ✅ KEY: prevents Chart.js from “forcing” extra layout that overflows tiles
    layout: {
      padding: { top: 4, right: 4, bottom: 6, left: 4 },
    },

    plugins: {
      tooltip: {
        callbacks: {
          title: (context) => {
            const idx = context[0].dataIndex;
            const row = ipData[idx];
            return `${row.sourceIP} (${row.country})`;
          },
          label: (context) => {
            const idx = context.dataIndex;
            const row = ipData[idx];
            const value = context.raw;
            const percent =
              totalAttacks > 0
                ? ((value / totalAttacks) * 100).toFixed(2)
                : "0.00";

            let base = `Count: ${value} (${percent}%)`;
            if (row.isNew) {
              base += " • NEW";
            } else if (row.changePct !== null) {
              const arrow = row.changePct >= 0 ? "↑" : "↓";
              base += ` • ${arrow} ${Math.abs(row.changePct)}% vs last`;
            }
            return base;
          },
        },
      },
      legend: {
        display: true,
        labels: { color: "white" },
      },
      zoom: {
        pan: {
          enabled: true,
          mode: "x",
        },
        zoom: {
          wheel: { enabled: true },
          pinch: { enabled: true },
          mode: "x",
        },
      },
    },
    scales: {
      x: {
        ticks: {
          autoSkip: true,
          maxTicksLimit: 6,     // prevents clutter
          color: "white",
          font: { size: 10 },
        },
        grid: { display: false },
      },
      y: {
        ticks: {
          color: "white",
          callback: (value) => {
            if (value >= 1000) return `${value / 1000}k`;
            return value;
          },
        },
        grid: { color: "rgba(255,255,255,0.1)" },
        title: {
          display: true,
          text: "Traffic Count",
          color: "white",
        },
      },
    },
    onClick: (event, elements) => {
      if (!elements.length) return;
      const index = elements[0].index;
      const row = ipData[index];
      if (row && row.sourceIP) {
        fetchDrillDownData(row.sourceIP);
      }
    },
  };

  // -------------------------------
  // CSV Download
  // -------------------------------
  const downloadCSV = () => {
    if (!ipData.length) return;

    const header = ["Source IP", "Country", "Count", "PercentOfTotal"];
    const rows = ipData.map((row) => {
      const percent =
        totalAttacks > 0
          ? ((row.count / totalAttacks) * 100).toFixed(2)
          : "0.00";
      return [row.sourceIP, row.country, row.count, `${percent}%`];
    });

    const csv =
      "data:text/csv;charset=utf-8," +
      [header, ...rows].map((r) => r.join(",")).join("\n");

    const link = document.createElement("a");
    link.href = encodeURI(csv);
    link.download = `top_ips_${interval}_top${limit}.csv`;
    link.click();
  };

  return (
    // ✅ KEY: make the whole component obey parent container size
    <div className="bg-gray-800 text-white p-4 rounded-lg shadow-md w-full h-full min-h-0 flex flex-col overflow-hidden">
      {/* Header stats */}
      <div className="flex flex-wrap justify-between items-center mb-1 flex-none">
        <div>
          <div className="text-sm text-gray-300 mt-1">
            <span className="mr-4">
              <strong>Total Events:</strong> {totalAttacks.toLocaleString()}
            </span>
            <span>
              <strong>Unique IPs:</strong> {uniqueIPs}
            </span>
          </div>
          {lastUpdated && (
            <div className="text-xs text-gray-400 mt-1">
              Last updated: {lastUpdated.toLocaleTimeString()}
            </div>
          )}
        </div>

        <div className="flex items-center space-x-2 mt-2 md:mt-0">
          {/* Interval selector */}
          <div>
            <label className="mr-1 text-sm">Interval:</label>
            <select
              className="p-1 rounded bg-gray-700 text-white text-sm"
              value={interval}
              onChange={(e) => setIntervalRange(e.target.value)}
            >
              <option value="24h">Last 24 Hours</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
          </div>

          {/* Limit selector */}
          <div>
            <label className="mr-1 text-sm">Top:</label>
            <select
              className="p-1 rounded bg-gray-700 text-white text-sm"
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
            >
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>
          </div>

          {/* View as table */}
          <button
            onClick={() => setShowTable((v) => !v)}
            className="bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium py-1 px-2 rounded"
          >
            {showTable ? "Hide Table" : "View Table"}
          </button>

          <button
            onClick={downloadCSV}
            className="bg-green-600 hover:bg-green-700 text-white text-xs font-medium py-1 px-2 rounded"
          >
            Download CSV
          </button>
        </div>
      </div>

      {/* Main chart */}
      {/* ✅ KEY FIX: chart now fills remaining space instead of forcing 400px */}
      <div className="flex-1 min-h-0 w-full">
        {ipData.length > 0 && <Bar data={chartData} options={options} />}
      </div>

      {/* Optional table view */}
      {showTable && (
        <div className="mt-4 max-h-64 overflow-y-auto border-t border-gray-700 pt-3 text-sm flex-none">
          <table className="w-full text-left">
            <thead className="border-b border-gray-600">
              <tr>
                <th className="py-1 pr-2">Source IP</th>
                <th className="py-1 pr-2">Country</th>
                <th className="py-1 pr-2 text-right">Count</th>
                <th className="py-1 pr-2 text-right">% of Total</th>
                <th className="py-1 pr-2 text-right">Trend</th>
              </tr>
            </thead>
            <tbody>
              {ipData.map((row) => {
                const percent =
                  totalAttacks > 0
                    ? ((row.count / totalAttacks) * 100).toFixed(2)
                    : "0.00";
                const trend =
                  row.isNew && row.count > 0
                    ? "NEW"
                    : row.changePct !== null
                    ? `${row.changePct >= 0 ? "↑" : "↓"} ${Math.abs(
                        row.changePct
                      )}%`
                    : "-";

                return (
                  <tr key={row.sourceIP} className="border-b border-gray-700">
                    <td className="py-1 pr-2">{row.sourceIP}</td>
                    <td className="py-1 pr-2">{row.country}</td>
                    <td className="py-1 pr-2 text-right">
                      {row.count.toLocaleString()}
                    </td>
                    <td className="py-1 pr-2 text-right">{percent}%</td>
                    <td className="py-1 pr-2 text-right">{trend}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Drilldown card */}
      {selectedIP && drillDownData && (
        <div className="mt-4 p-4 bg-gray-700 rounded-lg flex-none">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-bold">Details for {selectedIP}</h3>
            <button
              onClick={() => {
                setSelectedIP(null);
                setDrillDownData(null);
              }}
              className="text-xs text-gray-300 hover:text-white"
            >
              Close
            </button>
          </div>
          <ul className="mt-2 text-sm">
            {Object.entries(drillDownData).map(([key, value]) => (
              <li key={key}>
                <strong>{key}:</strong> {String(value)}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default Top25SourceIPsChart;