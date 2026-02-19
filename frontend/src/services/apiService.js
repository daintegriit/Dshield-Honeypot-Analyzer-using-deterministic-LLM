import axios from 'axios';

const BASE_URL = `${process.env.REACT_APP_API_BASE_URL}/api`;

const apiService = {
    // Fetch Top 10 Countries
    getTopCountries: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/top-countries`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Top 10 Countries:", error);
            return [];
        }
    },

    // Fetch Top 25 Source IPs
    getTopSourceIPs: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/top-ips`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Top Source IPs:", error);
            return [];
        }
    },

    // Fetch Top Attack Types
    getTopAttackTypes: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/top-attack-types`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Top Attack Types:", error);
            return [];
        }
    },

    // Fetch Attack Trends Over Time
    getAttackTrends: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/attack-trends`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Attack Trends:", error);
            return [];
        }
    },

    // Fetch Port Scanning Analysis
    getPortScanningData: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/port-scanning`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Port Scanning Data:", error);
            return [];
        }
    },

    // Fetch Protocol Breakdown
    getProtocolBreakdown: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/protocol-breakdown`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Protocol Breakdown:", error);
            return [];
        }
    },

    // Fetch Severity Distribution of Attacks
    getSeverityDistribution: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/severity-distribution`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Severity Distribution:", error);
            return [];
        }
    },

    // Fetch Source ASN Analysis
    getSourceASNAnalysis: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/source-asn`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Source ASN Analysis:", error);
            return [];
        }
    },

    // Fetch Comparative Traffic Analysis
    getComparativeTraffic: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/comparative-traffic`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Comparative Traffic Analysis:", error);
            return [];
        }
    },

    // Fetch Global Threat Intelligence Data
    getGlobalThreats: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/global-threats`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Global Threat Intelligence Data:", error);
            return [];
        }
    },

    // Fetch Heatmap Data
    getHeatmapData: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/heatmap-data`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Heatmap Data:", error);
            return [];
        }
    },

    // Fetch Threat Map Data (if needed)
    getThreatMapData: async () => {
        try {
            const response = await axios.get(`${BASE_URL}/attacks/threat-map`);
            return response.data;
        } catch (error) {
            console.error("Error fetching Threat Map Data:", error);
            return [];
        }
    },
};

// Export the API service
export default apiService;
