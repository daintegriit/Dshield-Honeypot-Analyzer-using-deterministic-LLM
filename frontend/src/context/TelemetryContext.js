// src/context/TelemetryContext.js

import React, {
  createContext,
  useContext,
  useEffect,
  useRef,
  useState,
  useCallback,
} from "react";

import { io } from "socket.io-client";

import apiService
from "../services/apiService";

// ======================================================
// CONTEXT
// ======================================================

const TelemetryContext =
  createContext(null);

// ======================================================
// CONFIG
// ======================================================

const STALE_THRESHOLD =
  30000;

const SOCKET_URL =
  process.env.REACT_APP_API_BASE_URL ||
  "http://localhost:5002";

// ======================================================
// HELPERS
// ======================================================

const safeResult = (
  results,
  index,
  fallback
) => {

  const result =
    results[index];

  if (
    result?.status ===
    "fulfilled"
  ) {

    return result.value;
  }

  return fallback;
};

const safeNumber = (
  value,
  fallback = 0
) => {

  const parsed =
    Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;

};

// ======================================================
// PHASE ENGINE
// ======================================================

const determinePhase =
  (
    risk,
    attackRate,
    dominantAttack
  ) => {

    if (
      risk >= 85 ||
      attackRate >= 100
    ) {
      return "attack";
    }

    if (
      risk >= 60 ||
      attackRate >= 40
    ) {
      return "escalation";
    }

    if (

      dominantAttack ===
        "scan" ||

      dominantAttack ===
        "recon" ||

      dominantAttack ===
        "web_probe" ||

      attackRate >= 10

    ) {
      return "recon";
    }

    if (
      risk <= 25 &&
      attackRate <= 5
    ) {
      return "baseline";
    }

    return "cooldown";

  };

// ======================================================
// PROVIDER
// ======================================================

export const TelemetryProvider = ({
  children
}) => {

  // ====================================================
  // STATE
  // ====================================================

  const [telemetry,
    setTelemetry] =
      useState({

        // ================================================
        // CORE DATA
        // ================================================

        topCountries: [],
        topIPs: [],
        attackTypes: [],
        attackTrends: [],
        heatmap: [],
        protocols: [],
        ports: [],
        severity: [],
        asns: [],
        geo: [],
        comparative: [],
        recentLogs: [],
        threatSummary: {},

        // ================================================
        // REPLAY FABRIC
        // ================================================

        replay: {

          phase:
            "unknown",

          replayMode:
            "scaled_ts",

          risk: 0,

          eps: 0,

          attacksLast5Min: 0,
          attacksLast15Min: 0,
          attacksLastHour: 0,

          attackVolume1m: 0,
          attackVolume5m: 0,
          attackVolume1h: 0,

          burstRatio5mOverHour: 0,

          dominantAttack:
            "unknown",

          dominantAttackScore: 0,

          dosScore: 0,
          scanScore: 0,
          bruteForceScore: 0,
          webProbeScore: 0,
          c2Score: 0,
          impactScore: 0,

          authPressure: 0,
          webPressure: 0,

          sourceEntropy: 0,
          portEntropy: 0,

          volumeComponent: 0,
          severityComponent: 0,
          behaviorComponent: 0,
          signalAmplifier: 0,
          c2Bonus: 0,
          impactBonus: 0,
          couplingBonus: 0,
        },

        // ================================================
        // HEALTH
        // ================================================

        endpointHealth: {

          topCountries: true,
          topIPs: true,
          attackTypes: true,
          attackTrends: true,
          heatmap: true,
          protocols: true,
          ports: true,
          severity: true,
          asns: true,
          geo: true,
          comparative: true,
          recentLogs: true,
          threatSummary: true,
        },

        loading: true,

        error: null,

        backendHealthy: true,

        lastUpdated: null,

        stale: false,

        refreshCount: 0,

        latency: 0,
      });

  // ====================================================
  // REFS
  // ====================================================

  const mountedRef =
    useRef(true);

  const fetchingRef =
    useRef(false);

  const socketRef =
    useRef(null);

  // ====================================================
  // FETCH ENGINE
  // ====================================================

  const fetchTelemetry =
    useCallback(async () => {

      if (fetchingRef.current) {

        console.warn(
          "⚠️ telemetry fetch already running"
        );

        return;
      }

      fetchingRef.current =
        true;

      const start =
        performance.now();

      try {

        console.log(
          "🚀 TELEMETRY ENGINE FETCH"
        );

        const results =
          await Promise.allSettled([

            apiService.getTopCountries(),

            apiService.getTopSourceIPs(),

            apiService.getTopAttackTypes(),

            apiService.getAttackTrends(),

            apiService.getHeatmapData(),

            apiService.getProtocolBreakdown(),

            apiService.getPortScanningData(),

            apiService.getSeverityDistribution(),

            apiService.getTopASNs(),

            apiService.getGeolocation(),

            apiService.getComparativeTraffic(),

            apiService.getRecentLogs(),

            apiService.getThreatSummary(),
          ]);

        // ================================================
        // NORMALIZATION
        // ================================================

        const topCountries =
          safeResult(results, 0, []);

        const topIPs =
          safeResult(results, 1, []);

        const attackTypes =
          safeResult(results, 2, []);

        const attackTrends =
          safeResult(results, 3, []);

        const heatmap =
          safeResult(results, 4, []);

        const protocols =
          safeResult(results, 5, []);

        const ports =
          safeResult(results, 6, []);

        const severity =
          safeResult(results, 7, []);

        const asns =
          safeResult(results, 8, []);

        const geo =
          safeResult(
            results,
            9,
            { results: [] }
          );

        const comparative =
          safeResult(results, 10, []);

        const recentLogs =
          safeResult(results, 11, []);

        const threatSummary =
          safeResult(results, 12, {});

        // ================================================
        // CORE
        // ================================================

        const core =
          threatSummary?.coreSummary ||
          threatSummary ||
          {};

        const attackMetrics =
          core?.attackMetrics || {};

        const attackClassification =
          core?.attackClassification || {};

        const riskComponents =
          core?.riskComponents || {};

        // ================================================
        // REPLAY FABRIC
        // ================================================

        const risk =
          safeNumber(
            core?.riskScore0to100 ??
            core?.riskScore
          );

        const attackRate =
          safeNumber(

            attackMetrics
              ?.eventsPerSecond ??

            attackMetrics
              ?.eps ??

            attackMetrics
              ?.attacksLast5Min ??

            core?.attacksLast5Min

          );

        const dominantAttack =
          String(

            attackClassification
              ?.dominantAttack
              ?.type ||

            attackClassification
              ?.topAttackType ||

            core?.dominantAttack ||

            "unknown"

          ).toLowerCase();

        const replay = {

          // ============================================
          // CORE
          // ============================================

          phase:
            determinePhase(
              risk,
              attackRate,
              dominantAttack
            ),

          replayMode:
            core?.replayMode ||
            "scaled_ts",

          pcapName:
            core?.pcapName ||
            core?.activePcap ||
            core?.replay?.pcapName ||
            "unknown",

          timeline:
            core?.replayTimeline ||
            core?.timeline ||
            core?.replay?.timeline ||
            [],

          risk,

          eps:
            attackRate,

          // ============================================
          // ATTACK WINDOWS
          // ============================================

          attacksLast5Min:
            safeNumber(
              attackMetrics
                ?.attacksLast5Min ??
              core?.attacksLast5Min
            ),

          attacksLast15Min:
            safeNumber(
              attackMetrics
                ?.attacksLast15Min ??
              core?.attacksLast15Min
            ),

          attacksLastHour:
            safeNumber(
              attackMetrics
                ?.attacksLastHour ??
              core?.attacksLastHour
            ),

          // ============================================
          // VOLUME
          // ============================================

          attackVolume1m:
            safeNumber(
              attackMetrics
                ?.attackVolume1m
            ),

          attackVolume5m:
            safeNumber(
              attackMetrics
                ?.attackVolume5m
            ),

          attackVolume1h:
            safeNumber(
              attackMetrics
                ?.attackVolume1h
            ),

          // ============================================
          // BURSTING
          // ============================================

          burstRatio5mOverHour:
            safeNumber(
              attackMetrics
                ?.burstRatio5mOverHour
            ),

          // ============================================
          // DOMINANT ATTACK
          // ============================================

          dominantAttack,

          dominantAttackScore:
            safeNumber(
              attackClassification
                ?.dominantAttack
                ?.score
            ),

          // ============================================
          // ATTACK TYPE SCORES
          // ============================================

          dosScore:
            safeNumber(
              attackClassification
                ?.attackTypeScores
                ?.dos
            ),

          scanScore:
            safeNumber(
              attackClassification
                ?.attackTypeScores
                ?.scan
            ),

          bruteForceScore:
            safeNumber(
              attackClassification
                ?.attackTypeScores
                ?.brute_force
            ),

          webProbeScore:
            safeNumber(
              attackClassification
                ?.attackTypeScores
                ?.web_probe
            ),

          c2Score:
            safeNumber(
              attackClassification
                ?.attackTypeScores
                ?.c2
            ),

          impactScore:
            safeNumber(
              attackClassification
                ?.attackTypeScores
                ?.impact
            ),

          // ============================================
          // PRESSURE
          // ============================================

          authPressure:
            safeNumber(
              attackMetrics
                ?.authPressure
            ),

          webPressure:
            safeNumber(
              attackMetrics
                ?.webPressure
            ),

          // ============================================
          // ENTROPY
          // ============================================

          sourceEntropy:
            safeNumber(
              attackMetrics
                ?.sourceEntropy
            ),

          portEntropy:
            safeNumber(
              attackMetrics
                ?.portEntropy
            ),

          // ============================================
          // RISK FABRIC
          // ============================================

          volumeComponent:
            safeNumber(
              riskComponents
                ?.volumeComponent
            ),

          severityComponent:
            safeNumber(
              riskComponents
                ?.severityComponent
            ),

          behaviorComponent:
            safeNumber(
              riskComponents
                ?.behaviorComponent
            ),

          signalAmplifier:
            safeNumber(
              riskComponents
                ?.signalAmplifier
            ),

          c2Bonus:
            safeNumber(
              riskComponents
                ?.c2Bonus
            ),

          impactBonus:
            safeNumber(
              riskComponents
                ?.impactBonus
            ),

          couplingBonus:
            safeNumber(
              riskComponents
                ?.couplingBonus
            ),
        };

        // ================================================
        // HEALTH
        // ================================================

        const endpointHealth = {

          topCountries:
            results[0]?.status === "fulfilled",

          topIPs:
            results[1]?.status === "fulfilled",

          attackTypes:
            results[2]?.status === "fulfilled",

          attackTrends:
            results[3]?.status === "fulfilled",

          heatmap:
            results[4]?.status === "fulfilled",

          protocols:
            results[5]?.status === "fulfilled",

          ports:
            results[6]?.status === "fulfilled",

          severity:
            results[7]?.status === "fulfilled",

          asns:
            results[8]?.status === "fulfilled",

          geo:
            results[9]?.status === "fulfilled",

          comparative:
            results[10]?.status === "fulfilled",

          recentLogs:
            results[11]?.status === "fulfilled",

          threatSummary:
            results[12]?.status === "fulfilled",
        };

        // ================================================
        // LATENCY
        // ================================================

        const latency =
          Math.round(
            performance.now() - start
          );

        console.log(
          `⚡ telemetry latency: ${latency}ms`
        );

        const normalizedGeo =
          geo?.results || [];

        const healthyEndpoints =
          Object.values(
            endpointHealth
          ).filter(Boolean).length;

        const backendHealthy =
          healthyEndpoints > 0;

        // ================================================
        // UPDATE
        // ================================================

        if (mountedRef.current) {

          setTelemetry(
            (prev) => ({

              ...prev,

              topCountries:
                Array.isArray(topCountries)
                  ? topCountries
                  : [],

              topIPs:
                Array.isArray(topIPs)
                  ? topIPs
                  : [],

              attackTypes:
                Array.isArray(attackTypes)
                  ? attackTypes
                  : [],

              attackTrends:
                Array.isArray(attackTrends)
                  ? attackTrends
                  : [],

              heatmap:
                Array.isArray(heatmap)
                  ? heatmap
                  : [],

              protocols:
                Array.isArray(protocols)
                  ? protocols
                  : [],

              ports:
                Array.isArray(ports)
                  ? ports
                  : [],

              severity:
                Array.isArray(severity)
                  ? severity
                  : [],

              asns:
                Array.isArray(asns)
                  ? asns
                  : [],

              geo:
                Array.isArray(normalizedGeo)
                  ? normalizedGeo
                  : [],

              comparative:
                Array.isArray(comparative)
                  ? comparative
                  : [],

              recentLogs:
                Array.isArray(recentLogs)
                  ? recentLogs
                  : [],

              threatSummary:
                threatSummary || {},

              replay,

              endpointHealth,

              loading: false,

              backendHealthy,

              stale: false,

              error: null,

              latency,

              lastUpdated:
                Date.now(),

              refreshCount:
                prev.refreshCount + 1,
            })
          );
        }

      } catch (err) {

        console.error(
          "❌ TELEMETRY ENGINE FAILURE:",
          err
        );

        if (mountedRef.current) {

          setTelemetry(
            (prev) => ({

              ...prev,

              loading: false,

              backendHealthy:
                false,

              stale: true,

              error:
                err?.message ||
                "Telemetry failure",
            })
          );
        }

      } finally {

        fetchingRef.current =
          false;
      }

    }, []);

  // ====================================================
  // INITIAL FETCH + SOCKETS
  // ====================================================

  useEffect(() => {

    mountedRef.current =
      true;

    fetchTelemetry();

    socketRef.current = io(

      SOCKET_URL,

      {
        transports: ["websocket"],
      }
    );

    // ================================================
    // CONNECT
    // ================================================

    socketRef.current.on(
      "connect",
      () => {

        console.log(
          "✅ Chiron telemetry socket connected"
        );

      }
    );

    // ================================================
    // LIVE TELEMETRY
    // ================================================

    socketRef.current.on(
      "telemetry:update",
      (payload) => {

        console.log(
          "📡 LIVE telemetry received",
          payload
        );

        if (!mountedRef.current) {
          return;
        }

        const core =
          payload?.coreSummary ||
          payload ||
          {};

        const attackMetrics =
          core?.attackMetrics || {};

        const attackClassification =
          core?.attackClassification || {};

        const riskComponents =
          core?.riskComponents || {};

        const risk =
          safeNumber(
            core?.riskScore0to100 ??
            core?.riskScore
          );

        const attackRate =
          safeNumber(

            attackMetrics
              ?.eventsPerSecond ??

            attackMetrics
              ?.eps ??

            attackMetrics
              ?.attacksLast5Min ??

            core?.attacksLast5Min

          );

        const dominantAttack =
          String(

            attackClassification
              ?.dominantAttack
              ?.type ||

            attackClassification
              ?.topAttackType ||

            core?.dominantAttack ||

            "unknown"

          ).toLowerCase();

        const replay = {

          phase:
            determinePhase(
              risk,
              attackRate,
              dominantAttack
            ),

          replayMode:
            core?.replayMode ||
            "scaled_ts",

          pcapName:
            core?.pcapName ||
            core?.activePcap ||
            core?.replay?.pcapName ||
            "unknown",

          timeline:
            core?.replayTimeline ||
            core?.timeline ||
            core?.replay?.timeline ||
            [],

          risk,

          eps:
            attackRate,

          dominantAttack,

          volumeComponent:
            safeNumber(
              riskComponents
                ?.volumeComponent
            ),

          severityComponent:
            safeNumber(
              riskComponents
                ?.severityComponent
            ),

          behaviorComponent:
            safeNumber(
              riskComponents
                ?.behaviorComponent
            ),

          signalAmplifier:
            safeNumber(
              riskComponents
                ?.signalAmplifier
            ),

          c2Bonus:
            safeNumber(
              riskComponents
                ?.c2Bonus
            ),

          impactBonus:
            safeNumber(
              riskComponents
                ?.impactBonus
            ),

          couplingBonus:
            safeNumber(
              riskComponents
                ?.couplingBonus
            ),
        };

        setTelemetry((prev) => ({

          ...prev,

          threatSummary:
            payload || {},

          replay,

          loading: false,

          backendHealthy: true,

          stale: false,

          error: null,

          lastUpdated:
            Date.now(),

          refreshCount:
            prev.refreshCount + 1,

        }));

      }
    );

    // ================================================
    // DISCONNECT
    // ================================================

    socketRef.current.on(
      "disconnect",
      () => {

        console.warn(
          "⚠️ Chiron telemetry socket disconnected"
        );

      }
    );

    // ================================================
    // CLEANUP
    // ================================================

    return () => {

      mountedRef.current =
        false;

      if (socketRef.current) {

        socketRef.current.disconnect();

      }

    };

  }, [fetchTelemetry]);

  // ====================================================
  // STALE DETECTION
  // ====================================================

  useEffect(() => {

    const staleCheck =
      setInterval(() => {

        setTelemetry(
          (prev) => {

            if (
              !prev.lastUpdated
            ) {
              return prev;
            }

            const stale =
              Date.now() -
                prev.lastUpdated >
              STALE_THRESHOLD;

            if (
              stale !== prev.stale
            ) {

              console.warn(
                stale
                  ? "⚠️ telemetry stale"
                  : "✅ telemetry fresh"
              );

              return {
                ...prev,
                stale,
              };
            }

            return prev;
          }
        );

      }, 5000);

    return () => {

      clearInterval(
        staleCheck
      );
    };

  }, []);

  // ====================================================
  // MANUAL REFRESH
  // ====================================================

  const refreshTelemetry =
    async () => {

      console.log(
        "🔄 manual telemetry refresh"
      );

      await fetchTelemetry();
    };

  // ====================================================
  // CONTEXT VALUE
  // ====================================================

  const value = {

    ...telemetry,

    refreshTelemetry,
  };

  // ====================================================
  // PROVIDER
  // ====================================================

  return (

    <TelemetryContext.Provider
      value={value}
    >

      {children}

    </TelemetryContext.Provider>
  );
};

// ======================================================
// HOOK
// ======================================================

export const useTelemetry =
  () => {

    const context =
      useContext(
        TelemetryContext
      );

    if (!context) {

      throw new Error(
        "useTelemetry must be used inside TelemetryProvider"
      );
    }

    return context;
  };

// ======================================================
// EXPORT
// ======================================================

export default TelemetryContext;