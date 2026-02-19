import React, { useContext, useEffect, useState } from 'react';
import { AuthContext } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import D3BarChart from '../components/D3BarChart';
import Top10CountriesChart from '../components/Top10CountriesChart';
import Top25SourceIPsChart from '../components/Top25SourceIPsChart';
import Top10AttacksPiechart from '../components/Top10AttackTypesPieChart';
import EChartsHeatmap from '../components/EChartsHeatmap';
import AttackTrendsChart from '../components/AttackTrendsChart';
import ProtocolBreakdownChart from '../components/ProtocolBreakdownChart';
import PortScanningChart from '../components/PortScanningChart';
import SeverityDistributionChart from '../components/SeverityDistributionChart';
import SourceASNChart from '../components/SourceASNChart';
import ComparativeAnalysisChart from '../components/ComparativeAnalysisChart';
import ThreatVisualization from '../components/ThreatVisualization';
import apiService from "../services/apiService";
import RecentLogsTerminal from '../components/RecentLogsTerminal';
import CopilotPanel from '../components/CopilotPanel';

const DashboardPage = () => {
  const { isAuthenticated } = useContext(AuthContext);
  const navigate = useNavigate();
  const [honeypotData, setHoneypotData] = useState([]);
  const [honeypotError, setHoneypotError] = useState(false);
  const [ipData, setIpData] = useState([]);
  const [attackTypesData] = useState([
    { attackType: 'SQL Injection', count: 90 },
    { attackType: 'XSS', count: 80 },
    { attackType: 'DDoS', count: 70 },
    { attackType: 'Phishing', count: 60 },
    { attackType: 'Malware', count: 50 },
    { attackType: 'Brute Force', count: 40 },
    { attackType: 'Ransomware', count: 35 },
    { attackType: 'Man-in-the-middle', count: 30 },
    { attackType: 'Trojan', count: 25 },
    { attackType: 'Worm', count: 20 },
  ]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await apiService.getTopCountries();
        
        if (!Array.isArray(response)) {
          console.error("Unexpected response format:", response);
          setHoneypotError(true);
          return;
        }

        const formattedData = response.map((item) => ({
          country: item._id || "Unknown",
          attacks: item.count || 0,
        }));

        setHoneypotData(formattedData);
        setHoneypotError(false);
      } catch (error) {
        console.error("Error fetching data:", error);
        setHoneypotError(true);
      }
    };

    fetchData();
  }, []);

  const handleDownloadClick = () => {
    if (!isAuthenticated) {
      navigate('/login');
    } else {
      console.log('Downloading report...');
    }
  };

  return (
    <div className="bg-gradient-to-b from-gray-900 to-black min-h-screen p-6 text-white">
      {/* Header */}
      <h1 className="text-5xl font-extrabold text-center text-green-400 drop-shadow-lg animate-pulse">
         Cyber Threat Dashboard
      </h1>
      <p className="text-center text-gray-300 mt-2">
        Live threat intelligence from honeypot data. Monitor attack trends, track malicious activity, and analyze security insights.
      </p>
      <p className="text-center text-gray-400 text-sm mt-2">
        Last Updated: {new Date().toLocaleString()}
      </p>
      
      {/* Refresh Button */}
      <div className="text-center mt-4">
        <button
          onClick={() => window.location.reload()}
          className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 flex items-center mx-auto"
        >
          🔄 Refresh Data
        </button>
      </div>

      {/* Row 1: Threat Visualization */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4">
      <h2 className="text-xl font-bold mb-2 flex items-center"> Global Threat Visualization</h2>
        <ThreatVisualization />
      </div>

      {/* Row 2: Live Terminal Feed */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4">
        <h2 className="text-xl font-bold mb-3 flex items-center"> Live Attack Log Feed (Terminal View)</h2>
        <p className="text-gray-400 text-sm mb-3">Real-time events from honeypot → ingestion engine → dashboard.</p>

        <RecentLogsTerminal />
      </div>

      {/* Row 3: Copilot Panel */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4">
        <h2 className="text-xl font-bold mb-3 flex items-center"> Threat Copilot</h2>
        <CopilotPanel />
      </div>

      {/* Row 4: Top Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-6 mb-8">
      <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Top 10 Countries by Attacks</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <Top10CountriesChart data={honeypotData} />
        )}
      </div>
        <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Top 10 Attack Types</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <Top10AttacksPiechart data={attackTypesData} />
        )}
        </div>
        <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Top 25 Source IPs</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <Top25SourceIPsChart data={ipData} />
        )}
        </div>
      </div>

      {/* Row 5: Attack Trends */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4">
      <h2 className="text-xl font-bold mb-2 flex items-center"> Attack Trends Over Time</h2>

      {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
        <AttackTrendsChart />
        )}
      </div>

      {/* Row 6: Geo Heatmap */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4">
      <h2 className="text-xl font-bold mb-2 flex items-center"> Geo Heatmap</h2>

      {honeypotError ? (
       <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
        <EChartsHeatmap />
        )}
      </div>
      
      {/* Row 7: Protocol and Port Analysis */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Protocol Breakdown</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <ProtocolBreakdownChart />
          )}
        </div>
        <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Port Scanning Analysis</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <PortScanningChart />
          )}
        </div>
      </div>

      {/* Row 8: Severity and ASN Analysis */}
      <div className="grid md:grid-cols-2 gap-6 mb-8">
        <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Severity Distribution</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <SeverityDistributionChart />
          )}
        </div>
        <div className="p-4 bg-gray-800 rounded-lg">
        <h2 className="text-xl font-bold mb-2 flex items-center"> Source ASN Analysis</h2>

        {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
          <SourceASNChart />
          )}
        </div>
      </div>

      {/* Row 9: Comparative Traffic Analysis */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4">
      <h2 className="text-xl font-bold mb-2 flex items-center"> Comparative Traffic Analysis</h2>

      {honeypotError ? (
          <div className="flex items-center justify-center h-40 bg-gray-700 border border-red-500 rounded-md animate-pulse">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : honeypotData.length === 0 ? (
          <div className="animate-pulse bg-gray-700 w-full h-40 rounded-md">
            <p className="text-red-400 text-center animate-pulse">⚠️ Failed to load data. Please try again later.</p>
          </div>
        ) : (
        <ComparativeAnalysisChart />
        )}
      </div>

      

      {/* Row 10: Reports */}
      <div className="mb-8 bg-gray-800 rounded-lg p-4 text-center">
      <h2 className="text-xl font-bold mb-2 flex items-center"> Reports</h2>
        <button
          onClick={handleDownloadClick}
          className="bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600"
        >
          Download Report
        </button>
      </div>
    </div>
  );
};

export default DashboardPage;
