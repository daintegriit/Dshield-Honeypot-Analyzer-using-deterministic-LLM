import React, { useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext } from "../context/AuthContext";

import ThreatVisualization from "../components/ThreatVisualization";
import AttackTrendsChart from "../components/AttackTrendsChart";
import RecentLogsTerminal from "../components/RecentLogsTerminal";
import CopilotPanel from "../components/CopilotPanel";

import Top10CountriesChart from "../components/Top10CountriesChart";
import Top10AttacksPiechart from "../components/Top10AttackTypesPieChart";
import Top25SourceIPsChart from "../components/Top25SourceIPsChart";
import EChartsHeatmap from "../components/EChartsHeatmap";

import ProtocolBreakdownChart from "../components/ProtocolBreakdownChart";
import PortScanningChart from "../components/PortScanningChart";
import SeverityDistributionChart from "../components/SeverityDistributionChart";
import SourceASNChart from "../components/SourceASNChart";
import ComparativeAnalysisChart from "../components/ComparativeAnalysisChart";

import apiService from "../services/apiService";

const DashboardPage2 = () => {
  // ✅ AUTH (FROM OLD DASHBOARD)
  const { isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();

  // ✅ REAL DATA STATE (FROM OLD DASHBOARD)
  const [honeypotData, setHoneypotData] = useState([]);
  const [honeypotError, setHoneypotError] = useState(false);
  const [attackTypesData] = useState([]);
  const [ipData] = useState([]);

  // ✅ DATA FETCH (MINIMUM REQUIRED)
  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await apiService.getTopCountries();

        if (!Array.isArray(response)) {
          console.error("Unexpected API response:", response);
          setHoneypotError(true);
          return;
        }

        setHoneypotData(response);
        setHoneypotError(false);
      } catch (err) {
        console.error("Honeypot fetch error:", err);
        setHoneypotError(true);
      }
    };

    fetchData();
  }, []);

  // ✅ REPORT DOWNLOAD HANDLER (RESTORED)
  const handleDownloadClick = () => {
    if (!isAuthenticated) {
      navigate("/login");
    } else {
      console.log("Downloading report...");
      // future: generate PDF / CSV
    }
  };

  return (
    <div className="bg-gradient-to-b from-gray-900 to-black min-h-screen p-4 text-white">

      <h1 className="text-3xl font-extrabold text-center text-green-400 mb-2">
        Cyber Threat Dashboard
      </h1>

      <div className="flex gap-6 items-start">

        {/* LEFT COLUMN */}
        <div className="flex flex-col gap-6 w-2/3">

          {/* Row 1 */}
          <div className="flex gap-6 items-start">

            <div className="bg-gray-800 rounded-lg p-4 shrink-0">
              <h2 className="text-sm font-bold mb-2">Global Threat Visualization</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                <ThreatVisualization />
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4 w-[806px]">
              <h2 className="text-sm font-bold mb-2">Attack Trends Over Time</h2>
              <div className="h-[300px] bg-gray-900 rounded-lg overflow-hidden">
                <AttackTrendsChart />
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Geo Heatmap</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <EChartsHeatmap />}
              </div>
            </div>

          </div>

          {/* Row 2 */}
          <div className="flex gap-6">

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Top 10 Countries by Attacks</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <Top10CountriesChart data={honeypotData} />}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Top 10 Attack Types</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError
                  ? "Error"
                  : <Top10AttacksPiechart data={attackTypesData} />}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Top 25 Source IPs</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <Top25SourceIPsChart />}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Source ASN Analysis</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <SourceASNChart />}
              </div>
            </div>

          </div>

          {/* Row 3 */}
          <div className="flex gap-6">

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Protocol Breakdown</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <ProtocolBreakdownChart />}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Port Scanning Analysis</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <PortScanningChart />}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Severity Distribution</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <SeverityDistributionChart />}
              </div>
            </div>

            <div className="bg-gray-800 rounded-lg p-4">
              <h2 className="text-sm font-bold mb-2">Comparative Traffic Analysis</h2>
              <div className="w-[360px] h-[300px] bg-gray-900 rounded-lg flex items-center justify-center">
                {honeypotError ? "Error" : <ComparativeAnalysisChart />}
              </div>
            </div>

          </div>
        </div>

        {/* RIGHT COLUMN */}
        <div className="flex flex-col gap-6 w-1/3">

          <div className="bg-gray-800 rounded-lg p-4">
            <h2 className="text-sm font-bold mb-1">Live Attack Log Feed (Terminal View)</h2>
            <p className="text-gray-400 text-xs mb-2">
              Real-time events from honeypot → ingestion engine → dashboard.
            </p>
            <div className="h-[360px] bg-black rounded-lg border border-gray-700 overflow-hidden">
              <RecentLogsTerminal />
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h2 className="text-sm font-bold mb-2">AI Threat Copilot</h2>
            <div className="h-[680px] bg-gray-900 rounded-lg overflow-hidden">
              <CopilotPanel />
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-4 text-center">
            <h2 className="text-sm font-bold mb-3">Reports</h2>
            <button
              onClick={handleDownloadClick}
              className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600 transition"
            >
              Download Report
            </button>
          </div>

        </div>

      </div>
    </div>
  );
};

export default DashboardPage2;
