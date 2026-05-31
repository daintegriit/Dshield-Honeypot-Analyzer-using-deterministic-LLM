import React, { useContext, useEffect, useMemo, useState } from "react";
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

const REFRESH_INTERVAL_MS = 10000;
const STALE_AFTER_MS = 30000;

const CARD =
  "bg-gray-800 rounded-xl p-3 border border-gray-700 flex flex-col min-h-0 overflow-hidden shadow-lg shadow-black/20";

const CARD_BODY =
  "flex-1 bg-gray-900 rounded-lg min-h-0 overflow-hidden";

const CARD_BODY_CENTER =
  "flex-1 bg-gray-900 rounded-lg min-h-0 overflow-hidden flex items-center justify-center";

const CARD_TITLE =
  "text-sm font-bold text-gray-100 leading-none";

const CONTROL =
  "bg-gray-900 border border-gray-600 text-xs px-2 py-1 rounded text-gray-100 outline-none focus:border-blue-400";

const SMALL_BUTTON =
  "text-black text-xs px-2 py-1 rounded font-semibold transition";

const DashboardPage2 = () => {
  const { isAuthenticated } = useContext(AuthContext);

  const navigate = useNavigate();

  const [lastRefreshAt, setLastRefreshAt] =
    useState(null);

  const [dashboardError, setDashboardError] =
    useState(false);

  const [isRefreshing, setIsRefreshing] =
    useState(false);

  const [summary, setSummary] =
    useState({
      topCountries: [],
      attackTrends: [],
      heatmap: [],
      threatSummary: null,
    });

  // ====================================================
  // DASHBOARD FETCH ENGINE
  // ====================================================

  useEffect(() => {
    let mounted = true;

    let intervalId = null;

    const fetchDashboardPulse = async () => {
      try {
        setIsRefreshing(true);

        const [
          topCountries,
          attackTrends,
          heatmap,
          threatSummary,
        ] = await Promise.allSettled([
          apiService.getTopCountries(),
          apiService.getAttackTrends(60),
          apiService.getHeatmapData(),
          apiService.getThreatSummary(),
        ]);

        if (!mounted) return;

        setSummary({
          topCountries:
            topCountries.status === "fulfilled" &&
            Array.isArray(topCountries.value)
              ? topCountries.value
              : [],

          attackTrends:
            attackTrends.status === "fulfilled" &&
            Array.isArray(attackTrends.value)
              ? attackTrends.value
              : [],

          heatmap:
            heatmap.status === "fulfilled" &&
            Array.isArray(heatmap.value)
              ? heatmap.value
              : [],

          threatSummary:
            threatSummary.status === "fulfilled"
              ? threatSummary.value
              : null,
        });

        setLastRefreshAt(Date.now());

        setDashboardError(false);
      } catch (err) {
        console.error(
          "Dashboard pulse fetch error:",
          err
        );

        if (mounted) {
          setDashboardError(true);
        }
      } finally {
        if (mounted) {
          setIsRefreshing(false);
        }
      }
    };

    fetchDashboardPulse();

    intervalId = setInterval(
      fetchDashboardPulse,
      REFRESH_INTERVAL_MS
    );

    return () => {
      mounted = false;

      clearInterval(intervalId);
    };
  }, []);

  // ====================================================
  // TELEMETRY STATE
  // ====================================================

  const telemetryState = useMemo(() => {
    if (dashboardError) return "offline";

    if (!lastRefreshAt) return "loading";

    const age =
      Date.now() - lastRefreshAt;

    if (age > STALE_AFTER_MS) {
      return "stale";
    }

    if (isRefreshing) {
      return "refreshing";
    }

    return "online";
  }, [
    dashboardError,
    lastRefreshAt,
    isRefreshing,
  ]);

  // ====================================================
  // TELEMETRY BADGE
  // ====================================================

  const telemetryBadge = useMemo(() => {
    switch (telemetryState) {
      case "online":
        return {
          label: "ONLINE",
          className:
            "border-green-500/40 bg-green-500/10 text-green-400",
        };

      case "refreshing":
        return {
          label: "SYNC",
          className:
            "border-cyan-500/40 bg-cyan-500/10 text-cyan-300",
        };

      case "stale":
        return {
          label: "STALE",
          className:
            "border-yellow-500/40 bg-yellow-500/10 text-yellow-300",
        };

      case "offline":
        return {
          label: "OFFLINE",
          className:
            "border-red-500/40 bg-red-500/10 text-red-400",
        };

      default:
        return {
          label: "LOADING",
          className:
            "border-gray-500/40 bg-gray-500/10 text-gray-300",
        };
    }
  }, [telemetryState]);

  // ====================================================
  // DOWNLOAD
  // ====================================================

  const handleDownloadClick = () => {
    if (!isAuthenticated) {
      navigate("/login");
      return;
    }

    console.log("Downloading report...");
  };

  // ====================================================
  // HEADER
  // ====================================================

  const Header = ({
    title,
    children,
  }) => (
    <div className="flex items-center justify-between gap-2 mb-2 shrink-0">
      <h2 className={CARD_TITLE}>
        {title}
      </h2>

      {children ? (
        <div className="flex items-center gap-2 shrink-0">
          {children}
        </div>
      ) : null}
    </div>
  );

  // ====================================================
  // STATUS BADGE
  // ====================================================

  const StatusBadge = () => (
    <span
      className={`text-[10px] px-2 py-1 rounded-md border font-semibold tracking-wide ${telemetryBadge.className}`}
      title={
        lastRefreshAt
          ? `Last refresh: ${new Date(
              lastRefreshAt
            ).toLocaleTimeString()}`
          : "Waiting for first telemetry refresh"
      }
    >
      {telemetryBadge.label}
    </span>
  );

  // ====================================================
  // UI
  // ====================================================

  return (
    <div className="bg-gradient-to-b from-gray-900 to-black h-[calc(100vh-64px)] overflow-hidden p-3 text-white flex flex-col">
      <div className="grid grid-cols-12 gap-3 flex-1 min-h-0">

        {/* ========================================= */}
        {/* LEFT SIDE */}
        {/* ========================================= */}

        <div className="col-span-9 grid grid-rows-[1fr_1fr_1fr] gap-3 min-h-0">

          {/* ===================================== */}
          {/* ROW 1 */}
          {/* ===================================== */}

          <div className="grid grid-cols-12 gap-3 min-h-0">

            {/* GLOBAL VISUALIZATION */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Global Threat Visualization">
                <StatusBadge />
              </Header>

              <div className={CARD_BODY_CENTER}>
                <ThreatVisualization />
              </div>
            </div>

            {/* ATTACK TRENDS */}

            <div className={`col-span-6 ${CARD}`}>
              <Header title="Attack Trends Over Time" />

              <div className={CARD_BODY}>
                <AttackTrendsChart />
              </div>
            </div>

            {/* HEATMAP */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Geo Heatmap" />

              <div className={CARD_BODY_CENTER}>
                {dashboardError ? (
                  <span className="text-xs text-red-400">
                    Heatmap telemetry unavailable
                  </span>
                ) : (
                  <EChartsHeatmap
                    data={summary.heatmap}
                  />
                )}
              </div>
            </div>
          </div>

          {/* ===================================== */}
          {/* ROW 2 */}
          {/* ===================================== */}

          <div className="grid grid-cols-12 gap-3 min-h-0">

            {/* TOP COUNTRIES */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Top Countries">
                <select
                  className={CONTROL}
                  defaultValue="24h"
                >
                  <option>24h</option>
                  <option>7d</option>
                  <option>30d</option>
                </select>

                <button
                  className={`${SMALL_BUTTON} bg-green-500 hover:bg-green-400`}
                  type="button"
                >
                  CSV
                </button>
              </Header>

              <div className={CARD_BODY}>
                <Top10CountriesChart
                  data={summary.topCountries}
                />
              </div>
            </div>

            {/* ATTACK TYPES */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Attack Types" />

              <div className={CARD_BODY}>
                <Top10AttacksPiechart />
              </div>
            </div>

            {/* TOP SOURCE IPS */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Top Source IPs">

                <select
                  className={CONTROL}
                  defaultValue="24h"
                >
                  <option>24h</option>
                  <option>7d</option>
                  <option>30d</option>
                </select>

                <select
                  className={CONTROL}
                  defaultValue="25"
                >
                  <option>25</option>
                  <option>50</option>
                  <option>100</option>
                </select>

                <button
                  type="button"
                  className={`${SMALL_BUTTON} bg-blue-500 hover:bg-blue-400`}
                >
                  Table
                </button>

                <button
                  type="button"
                  className={`${SMALL_BUTTON} bg-green-500 hover:bg-green-400`}
                >
                  CSV
                </button>
              </Header>

              <div className={`${CARD_BODY} p-2`}>
                <Top25SourceIPsChart />
              </div>
            </div>

            {/* ASN */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="ASN Analysis" />

              <div className={CARD_BODY}>
                <SourceASNChart />
              </div>
            </div>
          </div>

          {/* ===================================== */}
          {/* ROW 3 */}
          {/* ===================================== */}

          <div className="grid grid-cols-12 gap-3 min-h-0">

            {/* PROTOCOLS */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Protocol Breakdown" />

              <div className={CARD_BODY}>
                <ProtocolBreakdownChart />
              </div>
            </div>

            {/* PORTS */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Port Scanning" />

              <div className={CARD_BODY}>
                <PortScanningChart />
              </div>
            </div>

            {/* SEVERITY */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Severity Distribution" />

              <div className={CARD_BODY}>
                <SeverityDistributionChart />
              </div>
            </div>

            {/* COMPARATIVE */}

            <div className={`col-span-3 ${CARD}`}>
              <Header title="Comparative Analysis" />

              <div className={CARD_BODY}>
                <ComparativeAnalysisChart />
              </div>
            </div>
          </div>
        </div>

        {/* ========================================= */}
        {/* RIGHT SIDE */}
        {/* ========================================= */}

        <div className="col-span-3 flex flex-col gap-3 min-h-0">

          {/* LIVE FEED */}

          <div className={`${CARD} shrink-0`}>
            <div className="h-[290px] bg-black rounded-lg border border-gray-700 overflow-hidden">
              <RecentLogsTerminal />
            </div>
          </div>

          {/* COPILOT */}

          <div className={`${CARD} flex-1`}>
            <Header title="AI Threat Copilot" />

            <div className="flex-1 bg-gray-900 rounded-lg overflow-hidden min-h-0">
              <CopilotPanel />
            </div>
          </div>

          {/* DOWNLOAD */}

          <div className="bg-gray-800 rounded-xl p-3 text-center border border-gray-700 shrink-0 shadow-lg shadow-black/20">
            <button
              onClick={handleDownloadClick}
              className="bg-green-500 text-white px-4 py-2 rounded-lg hover:bg-green-600 transition w-full"
              type="button"
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