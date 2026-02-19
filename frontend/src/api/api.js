// src/api/api.js
const API_BASE_URL = "http://localhost:5002/api/attacks"; // Adjust this to your backend URL

export const fetchTopCountries = async () => {
    const response = await fetch(`${API_BASE_URL}/top-countries`);
    if (!response.ok) throw new Error('Failed to fetch top countries');
    return response.json();
};

export const fetchTopAttackTypes = async () => {
    const response = await fetch(`${API_BASE_URL}/top-attack-types`);
    if (!response.ok) throw new Error('Failed to fetch attack types');
    return response.json();
};

export const fetchGlobalThreats = async () => {
    const response = await fetch(`${API_BASE_URL}/global-threats`);
    return response.json();
};

export const fetchTopSourceIPs = async () => {
    const response = await fetch(`${API_BASE_URL}/top-ips`);
    return response.json();
};

export const fetchAttackTrends = async () => {
    const response = await fetch(`${API_BASE_URL}/attack-trends`);
    return response.json();
};

export const fetchProtocolBreakdown = async () => {
    const response = await fetch(`${API_BASE_URL}/protocol-breakdown`);
    return response.json();
};

export const fetchSeverityDistribution = async () => {
    const response = await fetch(`${API_BASE_URL}/severity-distribution`);
    return response.json();
};

export const fetchPortScanning = async () => {
    const response = await fetch(`${API_BASE_URL}/port-scanning`);
    return response.json();
};

export const fetchASNAnalysis = async () => {
    const response = await fetch(`${API_BASE_URL}/source-asn`);
    return response.json();
};

export const fetchComparativeTraffic = async () => {
    const response = await fetch(`${API_BASE_URL}/comparative-traffic`);
    return response.json();
};

export const fetchHeatmapData = async () => {
    const response = await fetch(`${API_BASE_URL}/heatmap-data`);
    return response.json();
};



