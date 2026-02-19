import React, { useEffect, useState, useRef } from "react";
import axios from "axios";

const MAX_LINES = 200; // hard cap to prevent memory blowup

const protocolBadgeClasses = {
  TCP: "bg-blue-700 text-blue-100",
  UDP: "bg-purple-700 text-purple-100",
  ICMP: "bg-yellow-600 text-yellow-900",
  HTTP: "bg-cyan-700 text-cyan-100",
  UNKNOWN: "bg-gray-700 text-gray-200",
};

const getProtocol = (log = {}) => {
  if (log.protocol) return String(log.protocol).toUpperCase();

  const raw = (log.raw || "").toUpperCase();
  if (raw.includes("TCP")) return "TCP";
  if (raw.includes("UDP")) return "UDP";
  if (raw.includes("ICMP")) return "ICMP";
  if (raw.includes("HTTP")) return "HTTP";
  return "UNKNOWN";
};

const RecentLogsTerminal = () => {
  const [logs, setLogs] = useState([]);
  const [animatedLogs, setAnimatedLogs] = useState([]);
  const terminalRef = useRef(null);

  // --------------------------------------------------
  // Fetch logs every 1 second
  // --------------------------------------------------
  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const res = await axios.get("/api/charts/recent-logs");
        const safe = Array.isArray(res.data) ? res.data : [];
        setLogs(safe);
      } catch (err) {
        console.error("Recent log fetch error:", err);
      }
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 1000);
    return () => clearInterval(interval);
  }, []);

  // --------------------------------------------------
  // Append ONLY new logs (no reset, no flicker)
  // --------------------------------------------------
  useEffect(() => {
    if (!logs.length) return;

    setAnimatedLogs((prev) => {
      const seen = new Set(
        prev.map((l) => l.id || l.timestamp)
      );

      const incoming = logs.filter(
        (l) => l && !seen.has(l.id || l.timestamp)
      );

      const merged = [...prev, ...incoming];

      // keep only last N lines
      return merged.slice(-MAX_LINES);
    });
  }, [logs]);

  // --------------------------------------------------
  // Auto-scroll to bottom
  // --------------------------------------------------
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [animatedLogs]);

  // --------------------------------------------------
  // Suspicious detection
  // --------------------------------------------------
  const isSuspicious = (log = {}) => {
    const dp = Number(log.target_port);
    const raw = (log.raw || "").toUpperCase();
    const criticalPorts = [22, 23, 445, 3389];

    return (
      criticalPorts.includes(dp) ||
      raw.includes("SYN") ||
      raw.includes("SCAN") ||
      raw.includes("BRUTE") ||
      raw.includes("EXPLOIT") ||
      raw.includes("MALWARE")
    );
  };

  // --------------------------------------------------
  // Render
  // --------------------------------------------------
  return (
    <div
      ref={terminalRef}
      className="
        w-full h-full
        bg-black text-green-400
        p-4 rounded-lg
        overflow-y-auto
        font-mono text-sm
        shadow-lg
      "
      style={{ border: "1px solid #0f0" }}
    >
      {animatedLogs.map((log, i) => {
        if (!log) return null;

        const timestamp = log.timestamp
          ? new Date(log.timestamp).toLocaleTimeString()
          : "N/A";

        const key =
          log.id ||
          log.timestamp ||
          `${log.source_ip}-${log.target_port}-${i}`;

        return (
          <div
            key={key}
            className={`mb-2 ${
              isSuspicious(log)
                ? "bg-red-800/30 p-1 rounded"
                : ""
            }`}
          >
            <span className="text-green-500">
              [{timestamp}]
            </span>{" "}

            <span
              className={`ml-2 px-2 py-[1px] rounded text-[10px] font-bold ${
                protocolBadgeClasses[getProtocol(log)]
              }`}
            >
              {getProtocol(log)}
            </span>{" "}
            <span className="text-green-300">
              SRC={log.source_ip || "N/A"}
            </span>{" "}
            <span className="text-green-300">
              DST={log.target_ip || "N/A"}
            </span>{" "}
            <span className="text-green-300">
              SP={log.source_port || "N/A"}
            </span>{" "}
            <span className="text-green-300">
              DP={log.target_port || "N/A"}
            </span>

            <br />

            <span className="text-green-600">
              {log.raw || "No raw data"}
            </span>
            <span className="text-green-500 animate-pulse">
              {" "}
              █
            </span>

            {isSuspicious(log) && (
              <div className="text-red-400 text-xs font-bold animate-pulse mt-1">
                🚨 Suspicious packet detected!
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default RecentLogsTerminal;