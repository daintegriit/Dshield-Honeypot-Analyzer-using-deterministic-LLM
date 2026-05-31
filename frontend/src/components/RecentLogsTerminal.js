import React, { useEffect, useState, useRef, useMemo } from "react";
import apiService from "../services/apiService";

import {
  FaSkullCrossbones,
  FaShieldAlt,
  FaNetworkWired,
  FaBug,
  FaGlobe,
  FaExclamationTriangle,
  FaServer,
  FaTerminal,
  FaLock,
} from "react-icons/fa";

const MAX_LINES = 200;

// =====================================================
// PROTOCOL BADGES
// =====================================================

const protocolBadgeClasses = {
  TCP: "bg-blue-700 text-blue-100",
  UDP: "bg-purple-700 text-purple-100",
  ICMP: "bg-yellow-600 text-yellow-900",
  HTTP: "bg-cyan-700 text-cyan-100",
  SSL: "bg-indigo-700 text-indigo-100",
  DNS: "bg-pink-700 text-pink-100",
  UNKNOWN: "bg-gray-700 text-gray-200",
};

// =====================================================
// PROTOCOL DETECTION
// =====================================================

const getProtocol = (log = {}) => {
  if (log.protocol) {
    return String(log.protocol).toUpperCase();
  }

  const raw = (log.raw || "").toUpperCase();

  if (raw.includes("PROTO=TCP")) return "TCP";
  if (raw.includes("PROTO=UDP")) return "UDP";
  if (raw.includes("PROTO=ICMP")) return "ICMP";
  if (raw.includes("PROTO=HTTP")) return "HTTP";
  if (raw.includes("PROTO=SSL")) return "SSL";
  if (raw.includes("PROTO=DNS")) return "DNS";

  return "UNKNOWN";
};

// =====================================================
// SEVERITY ENGINE
// =====================================================

const getSeverity = (log = {}) => {
  const raw = (log.raw || "").toUpperCase();
  const dp = Number(log.target_port);

  if (
    raw.includes("EXPLOIT") ||
    raw.includes("MALWARE") ||
    raw.includes("C2")
  ) {
    return "CRITICAL";
  }

  if ([22, 23, 445, 3389].includes(dp)) {
    return "HIGH";
  }

  if (
    raw.includes("SCAN") ||
    raw.includes("SYN") ||
    raw.includes("BRUTE")
  ) {
    return "MEDIUM";
  }

  return "LOW";
};

// =====================================================
// BEHAVIOR CLASSIFIER
// =====================================================

const classifyBehavior = (log = {}) => {
  const raw = (log.raw || "").toUpperCase();

  const dp = Number(log.target_port);

  if (dp === 445) {
    return {
      label: "SMB Probe",
      icon: <FaServer />,
      description: "SMB enumeration or lateral movement behavior detected.",
    };
  }

  if (dp === 3389) {
    return {
      label: "RDP Recon",
      icon: <FaTerminal />,
      description: "Remote Desktop scanning activity observed.",
    };
  }

  if (dp === 22) {
    return {
      label: "SSH Access Attempt",
      icon: <FaLock />,
      description: "Potential SSH brute-force or reconnaissance behavior.",
    };
  }

  if (
    raw.includes("HTTP") &&
    (dp === 80 || dp === 8080 || dp === 443)
  ) {
    return {
      label: "Web Enumeration",
      icon: <FaGlobe />,
      description: "HTTP probing or web surface enumeration detected.",
    };
  }

  if (raw.includes("DNS")) {
    return {
      label: "DNS Activity",
      icon: <FaNetworkWired />,
      description: "DNS query behavior observed.",
    };
  }

  if (
    raw.includes("SCAN") ||
    raw.includes("SYN")
  ) {
    return {
      label: "Port Scan",
      icon: <FaExclamationTriangle />,
      description: "Scanning behavior targeting exposed services.",
    };
  }

  return {
    label: "General Traffic",
    icon: <FaShieldAlt />,
    description: "Observed network communication.",
  };
};

// =====================================================
// SEVERITY STYLING
// =====================================================

const severityClasses = {
  LOW: "border-green-500 bg-green-900/10",
  MEDIUM: "border-yellow-500 bg-yellow-900/10",
  HIGH: "border-orange-500 bg-orange-900/10",
  CRITICAL: "border-red-600 bg-red-900/20",
};

const severityText = {
  LOW: "text-green-400",
  MEDIUM: "text-yellow-400",
  HIGH: "text-orange-400",
  CRITICAL: "text-red-500",
};

// =====================================================
// MAIN COMPONENT
// =====================================================

const RecentLogsTerminal = () => {
  const [logs, setLogs] = useState([]);
  const [animatedLogs, setAnimatedLogs] = useState([]);

  const terminalRef = useRef(null);
  const intervalRef = useRef(null);
  const mountedRef = useRef(true);

  // =====================================================
  // FETCH LOGS
  // =====================================================

  useEffect(() => {
    mountedRef.current = true;

    const fetchLogs = async () => {
      try {
        const data = await apiService.getRecentLogs();

        if (!mountedRef.current) return;

        if (Array.isArray(data)) {
          setLogs(data);
        }
      } catch (err) {
        console.error("Recent log fetch error:", err);
      }
    };

    fetchLogs();

    // ----------------------------------------
    // Near real-time polling
    // ----------------------------------------

    intervalRef.current = setInterval(fetchLogs, 1000);

    return () => {
      mountedRef.current = false;

      clearInterval(intervalRef.current);
    };
  }, []);

  // =====================================================
  // MERGE NEW LOGS ONLY
  // =====================================================

  useEffect(() => {
    if (!logs.length) return;

    setAnimatedLogs((prev) => {
      const seen = new Set(
        prev.map(
          (l) =>
            `${l.source_ip}-${l.timestamp}-${l.target_port}`
        )
      );

      const incoming = logs.filter(
        (l) =>
          l &&
          !seen.has(
            `${l.source_ip}-${l.timestamp}-${l.target_port}`
          )
      );

      const merged = [...prev, ...incoming];

      return merged.slice(-MAX_LINES);
    });
  }, [logs]);

  // =====================================================
  // AUTO SCROLL
  // =====================================================

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop =
        terminalRef.current.scrollHeight;
    }
  }, [animatedLogs]);

  // =====================================================
  // ANALYTICS
  // =====================================================

  const analytics = useMemo(() => {
    const suspicious = animatedLogs.filter(
      (l) => getSeverity(l) !== "LOW"
    ).length;

    const uniqueIPs = new Set(
      animatedLogs.map((l) => l.source_ip)
    ).size;

    return {
      suspicious,
      uniqueIPs,
      total: animatedLogs.length,
    };
  }, [animatedLogs]);

  // =====================================================
  // RENDER
  // =====================================================

  return (
    <div className="flex flex-col h-full w-full bg-black rounded-lg border border-green-500 overflow-hidden">

      {/* HEADER */}

      <div className="flex items-center justify-between px-3 py-2 border-b border-green-700 bg-black/90">
        <div className="flex items-center gap-2 text-green-400 font-bold">
          <FaTerminal />
          Live Threat Terminal
        </div>

        <div className="flex gap-3 text-[10px] text-green-500">
          <span>Total: {analytics.total}</span>
          <span>IPs: {analytics.uniqueIPs}</span>
          <span>Threats: {analytics.suspicious}</span>
        </div>
      </div>

      {/* TERMINAL */}

      <div
        ref={terminalRef}
        className="
          flex-1
          overflow-y-auto
          p-3
          font-mono
          text-xs
          bg-black
        "
      >
        {animatedLogs.length === 0 && (
          <div className="text-green-700 animate-pulse">
            Waiting for incoming honeypot telemetry...
          </div>
        )}

        {animatedLogs.map((log, i) => {
          if (!log) return null;

          const timestamp = log.timestamp
            ? new Date(log.timestamp).toLocaleTimeString()
            : "N/A";

          const protocol = getProtocol(log);

          const severity = getSeverity(log);

          const behavior = classifyBehavior(log);

          const key = `${log.source_ip}-${log.timestamp}-${i}`;

          return (
            <div
              key={key}
              className={`
                mb-3
                border-l-4
                rounded
                px-2
                py-2
                ${severityClasses[severity]}
              `}
            >
              {/* TOP ROW */}

              <div className="flex flex-wrap items-center gap-2 mb-1">

                <span className="text-green-500">
                  [{timestamp}]
                </span>

                <span
                  className={`
                    px-1 rounded text-[9px] font-bold
                    ${protocolBadgeClasses[protocol]}
                  `}
                >
                  {protocol}
                </span>

                <span
                  className={`text-[10px] font-bold ${severityText[severity]}`}
                >
                  {severity}
                </span>

                <span className="flex items-center gap-1 text-cyan-400 text-[10px]">
                  {behavior.icon}
                  {behavior.label}
                </span>
              </div>

              {/* CONNECTION */}

              <div className="text-green-300 mb-1">
                SRC={log.source_ip || "N/A"} → DST=
                {log.target_ip || "N/A"}
              </div>

              <div className="text-green-500 text-[11px] mb-1">
                SP={log.source_port || "N/A"} | DP=
                {log.target_port || "N/A"}
              </div>

              {/* DESCRIPTION */}

              <div className="text-gray-300 text-[11px] mb-1">
                {behavior.description}
              </div>

              {/* RAW */}

              <div className="text-green-700 break-all">
                {log.raw || "No raw telemetry"}
                <span className="animate-pulse"> █</span>
              </div>

              {/* ALERT */}

              {severity !== "LOW" && (
                <div
                  className={`
                    mt-2
                    flex items-center gap-1
                    text-[10px]
                    font-bold
                    ${severityText[severity]}
                  `}
                >
                  <FaSkullCrossbones />
                  Suspicious behavior detected
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default RecentLogsTerminal;