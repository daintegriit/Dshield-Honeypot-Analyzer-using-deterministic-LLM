import axios from "axios";

// ---------------------------------------------
// BASE URL RESOLUTION
// ---------------------------------------------
const resolvedBaseURL =
  process.env.REACT_APP_API_BASE_URL ||
  "http://localhost:5002";

// ---------------------------------------------
// AXIOS INSTANCE
// ---------------------------------------------
const API = axios.create({
  baseURL: resolvedBaseURL,
  timeout: 180000,
});

// ---------------------------------------------
// DEBUG BASE URL
// ---------------------------------------------
console.log("🌐 API BASE URL:", resolvedBaseURL);

// ---------------------------------------------
// REQUEST LOGGER
// ---------------------------------------------
API.interceptors.request.use(
  (config) => {
    console.log(
      `🚀 API Request → ${config.method?.toUpperCase()} ${config.baseURL}${config.url}`
    );
    return config;
  },
  (error) => {
    console.error("❌ Request Interceptor Error:", error);
    return Promise.reject(error);
  }
);

// ---------------------------------------------
// RESPONSE LOGGER
// ---------------------------------------------
API.interceptors.response.use(
  (response) => {
    console.log(
      `✅ API Response ← ${response.config.url}`,
      response.data
    );
    return response;
  },
  (error) => {
    console.error(
      "❌ API Response Error:",
      error?.response?.status,
      error?.message
    );

    return Promise.reject(error);
  }
);

// ======================================================
// SAFE REQUEST HANDLER
// ======================================================
const safeRequest = async (
  fn,
  fallback,
  endpointName = "UnknownEndpoint"
) => {
  try {
    const res = await fn();

    // ---------------------------------------------
    // 🔥 NULL / UNDEFINED GUARD
    // ---------------------------------------------
    if (res?.data === undefined || res?.data === null) {
      console.warn(`⚠️ ${endpointName} returned empty response`);
      return fallback;
    }

    return res.data;
  } catch (err) {
    console.error(
      `❌ ${endpointName} Failed:`,
      err?.response?.status,
      err?.message
    );

    return fallback;
  }
};


const apiService = {
  // ==================================================
  // TOP COUNTRIES
  // ==================================================
  getTopCountries: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/top-countries`),
      [],
      "TopCountries"
    );

    console.log("🌍 Top Countries:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // TOP SOURCE IPS
  // ==================================================
  getTopSourceIPs: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/top-ips`),
      [],
      "TopSourceIPs"
    );

    console.log("🛰️ Top Source IPs:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // ATTACK TYPES
  // ==================================================
  getTopAttackTypes: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/top-attack-types`),
      [],
      "TopAttackTypes"
    );

    console.log("⚔️ Attack Types:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // ATTACK TRENDS
  // ==================================================
  getAttackTrends: async (minutes = 60) => {
    const data = await safeRequest(
      () =>
        API.get(`/api/charts/attack-trends?minutes=${minutes}`),
      [],
      "AttackTrends"
    );

    console.log("📈 Raw Attack Trends:", data);

    // ---------------------------------------------
    // SHAPE NORMALIZATION
    // ---------------------------------------------
    if (!Array.isArray(data)) {
      console.warn("⚠️ Attack trends not array");
      return [];
    }

    const normalized = data.map((item, index) => ({
      time:
        item.time ||
        item.timestamp ||
        item.minute ||
        `T${index}`,

      count:
        Number(
          item.count ??
          item.total ??
          item.value ??
          0
        ) || 0,
    }));

    console.log("📊 Normalized Attack Trends:", normalized);

    return normalized;
  },

  // ==================================================
  // PORT SCANNING
  // ==================================================
  getPortScanningData: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/port-scanning`),
      [],
      "PortScanning"
    );

    console.log("🚪 Port Scanning:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // PROTOCOL BREAKDOWN
  // ==================================================
  getProtocolBreakdown: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/protocol-breakdown`),
      [],
      "ProtocolBreakdown"
    );

    console.log("📡 Protocol Breakdown:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // SEVERITY DISTRIBUTION
  // ==================================================
  getSeverityDistribution: async (
    minutes = 60
  ) => {

    const data =
      await safeRequest(

        () =>
          API.get(

            `/api/charts/severity-distribution`,

            {
              params: {
                minutes,
              },
            }
          ),

        {

          total: 0,

          dominantSeverity:
            "none",

          severities: [],

        },

        "SeverityDistribution"
      );

    console.log(
      "🚨 Severity Distribution:",
      data
    );

    // ==========================================
    // RETURN FULL OBJECT
    // ==========================================

    if (
      !data ||
      typeof data !== "object"
    ) {

      return {

        total: 0,

        dominantSeverity:
          "none",

        severities: [],

      };
    }

    return {

      total:
        Number(
          data.total || 0
        ),

      dominantSeverity:
        data.dominantSeverity ||
        "none",

      severities:
        Array.isArray(
          data.severities
        )
          ? data.severities
          : [],
    };
  },

  // ==================================================
  // ASN ANALYSIS
  // ==================================================
  getTopASNs: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/top-asns`),
      [],
      "TopASNs"
    );

    console.log("🌐 ASN Analysis:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // GEOLOCATION
  // ==================================================
  getGeolocation: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/geolocation`),
      { results: [] },
      "Geolocation"
    );

    console.log("🗺️ Geolocation:", data);

    return data;
  },

  // ==================================================
  // HEATMAP
  // ==================================================
  getHeatmapData: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/heatmap`),
      [],
      "Heatmap"
    );

    console.log("🔥 Heatmap:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // THREAT SUMMARY
  // ==================================================
  getThreatSummary: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/threat-summary`),
      {},
      "ThreatSummary"
    );

    console.log("🧠 Threat Summary:", data);

    return data || {};
  },

  // ==================================================
  // RECENT LOGS
  // ==================================================
  getRecentLogs: async () => {
    const data = await safeRequest(
      () => API.get(`/api/charts/recent-logs`),
      [],
      "RecentLogs"
    );

    console.log("📜 Recent Logs:", data);

    return Array.isArray(data) ? data : [];
  },

  // ==================================================
  // COMPARATIVE ANALYSIS
  // ==================================================
  getComparativeTraffic: async () => {

    const data =
      await safeRequest(

        () =>
          API.get(
            `/api/charts/comparative-analysis`
          ),

        [],

        "ComparativeAnalysis"
      );

    console.log(
      "⚖️ Comparative Analysis:",
      data
    );

    return Array.isArray(data)
      ? data
      : [];
  },
};

export default apiService;