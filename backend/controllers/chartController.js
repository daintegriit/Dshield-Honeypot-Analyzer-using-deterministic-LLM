const mongoose = require("mongoose");
const { Parser } = require("json2csv");

const parseLogs = require("../utils/parseLogs");

const DShieldLog = require("../models/DShieldLogModel");
const ASN = require("../models/ASNModel");
const GeolocationCache = require("../models/GeolocationCacheModel");
const { buildCopilotCore } = require("../services/copilotCore");
const { buildBehaviorSummary } = require("../services/behaviorSummary");

// =========================================================
// CONFIG
// =========================================================

const USE_MONGO =
  process.env.USE_MONGO === "true";

const MAX_ATTACK_TREND_MINUTES = 60;
const MAX_HEATMAP_DOCS = 50000;
const MAX_RECENT_LOGS = 50;
const MAX_GEO_IPS = 50;

// =========================================================
// TEMP ATTACK CLASSIFIER
// =========================================================

function determineAttackType(port) {
  if ([22].includes(port))
    return "SSH Scan";

  if ([23].includes(port))
    return "Telnet Scan";

  if (port >= 0 && port <= 1024)
    return "Low Port Scan";

  return "General Scan";
}

// =========================================================
// TOP COUNTRIES
// =========================================================

exports.getTopCountries = async (
  req,
  res
) => {
  try {
    console.log(
      "🚀 /api/charts/top-countries HIT"
    );

    // =====================================================
    // MONGO MODE
    // =====================================================

    if (USE_MONGO) {
      const results =
        await mongoose.connection
          .collection("countries")
          .find({})
          .sort({
            attackCount: -1,
          })
          .limit(10)
          .toArray();

      console.log(
        `✅ countries returned: ${results.length}`
      );

      return res.json(
        results.map((item) => ({
          country:
            item.country ||
            "Unknown",

          attacks:
            item.attackCount || 0,
        }))
      );
    }

    // =====================================================
    // LOG MODE
    // =====================================================

    const entries = parseLogs();

    const countryCount = {};

    for (const entry of entries) {
      const country =
        entry.country || "Unknown";

      countryCount[country] =
        (countryCount[country] ||
          0) + 1;
    }

    const formatted = Object.entries(
      countryCount
    )
      .map(
        ([country, attacks]) => ({
          country,
          attacks,
        })
      )
      .sort(
        (a, b) =>
          b.attacks - a.attacks
      )
      .slice(0, 10);

    return res.json(formatted);
  } catch (err) {
    console.error(
      "❌ Error Top Countries:",
      err
    );

    return res
      .status(500)
      .json([]);
  }
};

// =========================================================
// COUNTRIES CSV DOWNLOAD
// =========================================================

exports.downloadTopCountries =
  async (req, res) => {
    try {
      const response =
        await exports.getTopCountries(
          req,
          {
            json: (data) => data,
          }
        );

      const csv =
        new Parser().parse(
          response
        );

      res.header(
        "Content-Type",
        "text/csv"
      );

      res.attachment(
        "top_countries.csv"
      );

      res.send(csv);
    } catch (err) {
      console.error(
        "❌ CSV Download Error:",
        err
      );

      return res
        .status(500)
        .json({
          error:
            "Internal Server Error",
        });
    }
  };

// =========================================================
// TOP SOURCE IPS
// =========================================================

exports.getTopIPs = async (
  req,
  res
) => {
  try {
    console.log(
      "🚀 /api/charts/top-ips HIT"
    );

    const limit =
      parseInt(req.query.limit) ||
      25;

    // =====================================================
    // MONGO MODE
    // =====================================================

    if (USE_MONGO) {
      const results =
        await mongoose.connection
          .collection("topIPs")
          .find({})
          .sort({ count: -1 })
          .limit(limit)
          .toArray();

      console.log(
        `✅ topIPs returned: ${results.length}`
      );

      return res.json(
        results.map((ip) => ({
          sourceIP:
            ip.source_ip,
          count: ip.count,

          country:
            ip.country ||
            "Unknown",

          asn:
            ip.asn || "N/A",

          threatScore:
            ip.threat_score ??
            0,
        }))
      );
    }

    // =====================================================
    // LOG MODE
    // =====================================================

    const entries = parseLogs();

    const ipCount = {};

    for (const e of entries) {
      ipCount[e.src] =
        (ipCount[e.src] || 0) +
        1;
    }

    const formatted = Object.entries(
      ipCount
    )
      .map(
        ([sourceIP, count]) => ({
          sourceIP,
          count,
        })
      )
      .sort(
        (a, b) =>
          b.count - a.count
      )
      .slice(0, limit);

    return res.json(formatted);
  } catch (err) {
    console.error(
      "❌ Error Top IPs:",
      err
    );

    return res
      .status(500)
      .json([]);
  }
};

// =========================================================
// TOP ATTACK TYPES
// =========================================================

exports.getTopAttackTypes =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/top-attack-types HIT"
      );

      // ===================================================
      // MONGO MODE
      // ===================================================

      if (USE_MONGO) {
        const results =
          await mongoose.connection
            .collection(
              "attackTypes"
            )
            .find({})
            .sort({
              count: -1,
            })
            .limit(10)
            .toArray();

        console.log(
          `✅ attackTypes returned: ${results.length}`
        );

        return res.json(
          results.map(
            (entry) => ({
              attackType:
                entry.attackType ||
                "Unknown",

              count:
                entry.count ||
                0,
            })
          )
        );
      }

      // ===================================================
      // LOG MODE
      // ===================================================

      const entries =
        parseLogs();

      const typeCount = {};

      for (const e of entries) {
        const type =
          determineAttackType(
            e.dpt
          );

        typeCount[type] =
          (typeCount[type] || 0) +
          1;
      }

      const formatted =
        Object.entries(
          typeCount
        )
          .map(
            ([
              attackType,
              count,
            ]) => ({
              attackType,
              count,
            })
          )
          .sort(
            (a, b) =>
              b.count - a.count
          )
          .slice(0, 10);

      return res.json(
        formatted
      );
    } catch (err) {
      console.error(
        "❌ Error Attack Types:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// PORT SCANNING
// =========================================================

exports.getPortScanning =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/port-scanning HIT"
      );

      if (USE_MONGO) {
        const results =
          await mongoose.connection
            .collection("ports")
            .find({})
            .sort({
              count: -1,
            })
            .limit(15)
            .toArray();

        return res.json(
          results.map((r) => ({
            port: r.port,
            count: r.count,
          }))
        );
      }

      const entries =
        parseLogs();

      const portCount = {};

      for (const e of entries) {
        const p =
          e.dpt ||
          e.port ||
          e.target_port;

        if (!p) continue;

        portCount[p] =
          (portCount[p] || 0) +
          1;
      }

      const formatted =
        Object.entries(
          portCount
        )
          .map(
            ([port, count]) => ({
              port:
                parseInt(
                  port,
                  10
                ),
              count,
            })
          )
          .sort(
            (a, b) =>
              b.count - a.count
          )
          .slice(0, 15);

      return res.json(
        formatted
      );
    } catch (err) {
      console.error(
        "❌ Error Port Scan:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// 🔥 PROTOCOL BREAKDOWN
// =========================================================

exports.getProtocolBreakdown =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/protocol-breakdown HIT"
      );

      if (USE_MONGO) {
        const results =
          await mongoose.connection
            .collection(
              "protocols"
            )
            .find({})
            .sort({
              count: -1,
            })
            .toArray();

        return res.json(
          results.map((r) => ({
            protocol:
              r.protocol,
            count: r.count,
          }))
        );
      }

      const entries =
        parseLogs();

      const protoCount = {};

      for (const e of entries) {
        protoCount[e.proto] =
          (protoCount[
            e.proto
          ] || 0) + 1;
      }

      const formatted =
        Object.entries(
          protoCount
        )
          .map(
            ([
              protocol,
              count,
            ]) => ({
              protocol,
              count,
            })
          )
          .sort(
            (a, b) =>
              b.count - a.count
          );

      return res.json(
        formatted
      );
    } catch (err) {
      console.error(
        "❌ Error Protocol Breakdown:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// SEVERITY DISTRIBUTION
// =========================================================

exports.getSeverityDistribution =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/severity-distribution HIT"
      );

      if (USE_MONGO) {
        const results =
          await mongoose.connection
            .collection(
              "severity"
            )
            .find({})
            .sort({
              count: -1,
            })
            .toArray();

        return res.json(
          results.map((r) => ({
            severity:
              r.level,
            count: r.count,
          }))
        );
      }

      const entries =
        parseLogs();

      const sevCount = {
        Low: 0,
        Medium: 0,
        High: 0,
      };

      for (const e of entries) {
        if (e.dpt <= 1024)
          sevCount.High++;
        else if (
          e.dpt <= 5000
        )
          sevCount.Medium++;
        else sevCount.Low++;
      }

      return res.json([
        {
          severity: "High",
          count:
            sevCount.High,
        },

        {
          severity: "Medium",
          count:
            sevCount.Medium,
        },

        {
          severity: "Low",
          count:
            sevCount.Low,
        },
      ]);
    } catch (err) {
      console.error(
        "❌ Error Severity:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// ATTACK TRENDS
// =========================================================

exports.getAttackTrends =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/attack-trends HIT"
      );

      const since = new Date(
        Date.now() -
          MAX_ATTACK_TREND_MINUTES *
            60 *
            1000
      );

      const results =
        await DShieldLog.aggregate(
          [
            {
              $match: {
                timestamp: {
                  $gte: since,
                },
              },
            },

            {
              $group: {
                _id: {
                  $dateToString:
                    {
                      format:
                        "%Y-%m-%d %H:%M",

                      date:
                        "$timestamp",
                    },
                },

                count: {
                  $sum: 1,
                },
              },
            },

            {
              $sort: {
                _id: 1,
              },
            },
          ],
          {
            allowDiskUse:
              false,

            maxTimeMS: 5000,
          }
        );

      return res.json(
        results.map((r) => ({
          time: r._id,
          count: r.count,
        }))
      );
    } catch (err) {
      console.error(
        "❌ Attack Trends Error:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// HEATMAP
// =========================================================

exports.getHeatmapData =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/heatmap HIT"
      );

      const results =
        await DShieldLog.aggregate(
          [
            {
              $match: {
                timestamp: {
                  $exists: true,
                  $ne: null,
                },
              },
            },

            {
              $sort: {
                timestamp: -1,
              },
            },

            {
              $limit:
                MAX_HEATMAP_DOCS,
            },

            {
              $group: {
                _id: {
                  hour: {
                    $hour: "$timestamp",
                  },

                  day: {
                    $dayOfMonth: "$timestamp",
                  },
                },

                count: {
                  $sum: 1,
                },
              },
            },

            {
              $sort: {
                "_id.day": 1,
                "_id.hour": 1,
              },
            },
          ],
          {
            allowDiskUse: false,
            maxTimeMS: 5000,
          }
        );

      console.log(
        `✅ heatmap buckets returned: ${results.length}`
      );

      const data =
        results.map((r) => [
          r._id.day,
          r._id.hour,
          r.count,
        ]);

      return res.json(data);
    } catch (err) {
      console.error(
        "❌ Heatmap Error:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// COMPARATIVE ANALYSIS
// =========================================================

exports.getComparativeAnalysis =
  async (req, res) => {
    try {
      console.log(
        "🚀 /api/charts/comparative-analysis HIT"
      );

      // ===================================================
      // LOAD COMPARISON DATA
      // ===================================================

      const results =
        await mongoose.connection
          .collection("comparisons")
          .find({})
          .sort({
            day: 1
          })
          .limit(30)
          .toArray();

      console.log(
        `✅ comparisons returned: ${results.length}`
      );

      // ===================================================
      // 🔥 EMPTY SAFETY
      // ===================================================

      if (!results.length) {
        return res.json([]);
      }

      // ===================================================
      // BUILD REAL TEMPORAL COMPARISON
      // ===================================================

      const formatted =
        results.map(
          (r, i, arr) => {

            // ---------------------------------------------
            // PREVIOUS PERIOD
            // ---------------------------------------------

            const previous =
              i > 0
                ? Number(
                    arr[i - 1]
                      ?.total_attacks || 0
                  )
                : Number(
                    r.total_attacks || 0
                  );

            // ---------------------------------------------
            // CURRENT PERIOD
            // ---------------------------------------------

            const current =
              Number(
                r.total_attacks || 0
              );

            // ---------------------------------------------
            // DELTA %
            // ---------------------------------------------

            let delta = 0;

            if (previous > 0) {
              delta = Number(
                (
                  ((current - previous) /
                    previous) *
                  100
                ).toFixed(2)
              );
            }

            // ---------------------------------------------
            // TREND LABEL
            // ---------------------------------------------

            let trend =
              "stable";

            if (delta >= 25) {
              trend =
                "surging";
            } else if (
              delta >= 10
            ) {
              trend =
                "rising";
            } else if (
              delta <= -25
            ) {
              trend =
                "collapsing";
            } else if (
              delta <= -10
            ) {
              trend =
                "cooling";
            }

            // ---------------------------------------------
            // SEVERITY INDEX
            // ---------------------------------------------

            const critical =
              Number(
                r.critical_count || 0
              );

            const high =
              Number(
                r.high_count || 0
              );

            const medium =
              Number(
                r.medium_count || 0
              );

            const low =
              Number(
                r.low_count || 0
              );

            const severityIndex =
              (
                critical * 1.0 +
                high * 0.75 +
                medium * 0.4 +
                low * 0.15
              ).toFixed(2);

            // ---------------------------------------------
            // RETURN
            // ---------------------------------------------

            return {
              // -----------------------------
              // LABEL
              // -----------------------------

              region:
                r.day ||
                "Unknown",

              metric:
                r.day ||
                "Unknown",

              // -----------------------------
              // TEMPORAL WINDOWS
              // -----------------------------

              previous,
              current,
              delta,

              // backwards compatibility
              lastWeek:
                previous,
              thisWeek:
                current,

              // -----------------------------
              // TOTALS
              // -----------------------------

              total:
                current,

              // -----------------------------
              // SEVERITY
              // -----------------------------

              critical,
              high,
              medium,
              low,

              severityIndex:
                Number(
                  severityIndex
                ),

              // -----------------------------
              // INFRASTRUCTURE
              // -----------------------------

              uniqueIPs:
                Number(
                  r.unique_ips || 0
                ),

              uniquePorts:
                Number(
                  r.unique_ports || 0
                ),

              uniqueCountries:
                Number(
                  r.unique_countries || 0
                ),

              // -----------------------------
              // METADATA
              // -----------------------------

              trend,

              timestamp:
                r.last_updated ||
                null,
            };
          }
        );

      // ===================================================
      // RESPONSE
      // ===================================================

      return res.json(
        formatted
      );

    } catch (err) {

      console.error(
        "❌ Comparative Analysis Error:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// TOP ASNS
// =========================================================

exports.getTopASNs = async (
  req,
  res
) => {
  try {
    console.log(
      "🚀 /api/charts/top-asns HIT"
    );

    const results =
      await mongoose.connection
        .collection("asns")
        .find({})
        .sort({ count: -1 })
        .limit(20)
        .toArray();

    return res.json(
      results.map((item) => ({
        asn: item.asn,

        org:
          item.asn_org,

        provider:
          item.provider,

        count: item.count,
      }))
    );
  } catch (err) {
    console.error(
      "❌ ASN Error:",
      err
    );

    return res
      .status(500)
      .json([]);
  }
};

// =========================================================
// RECENT LOGS
// =========================================================

exports.getRecentLogs =
  async (req, res) => {
    try {
      const logs =
        await DShieldLog.find(
          {},
          {
            raw: 1,
            timestamp: 1,
            source_ip: 1,
            target_ip: 1,
            source_port: 1,
            target_port: 1,
          }
        )
          .sort({
            timestamp: -1,
          })
          .limit(
            MAX_RECENT_LOGS
          )
          .lean()
          .maxTimeMS(3000);

      return res.json(logs);
    } catch (err) {
      console.error(
        "❌ Recent Logs Error:",
        err
      );

      return res
        .status(500)
        .json([]);
    }
  };

// =========================================================
// THREAT SUMMARY
// =========================================================

exports.getThreatSummary =
  async (req, res) => {

    try {

      console.log(
        "🚀 /api/charts/threat-summary HIT"
      );

      // =====================================================
      // BUILD DETERMINISTIC CORE
      // =====================================================

      const coreSummary =
        await buildCopilotCore();

      // =====================================================
      // OPTIONAL BEHAVIOR SUMMARY
      // =====================================================

      const behaviorSummary =
        await buildBehaviorSummary({
          minutes: 60,
          limit: 5000,
        });

      // =====================================================
      // SUPPORTING DASHBOARD DATA
      // =====================================================

      const since = new Date(
        Date.now() -
        60 * 60 * 1000
      );

      const topIP =
        await DShieldLog.aggregate([
          {
            $match: {
              timestamp: {
                $gte: since,
              },
            },
          },

          {
            $group: {
              _id: "$source_ip",

              count: {
                $sum: 1,
              },
            },
          },

          {
            $sort: {
              count: -1,
            },
          },

          {
            $limit: 1,
          },
        ]);

      const topPort =
        await DShieldLog.aggregate([
          {
            $match: {
              timestamp: {
                $gte: since,
              },
            },
          },

          {
            $group: {
              _id: "$target_port",

              count: {
                $sum: 1,
              },
            },
          },

          {
            $sort: {
              count: -1,
            },
          },

          {
            $limit: 1,
          },
        ]);

      const topASN =
        await ASN.aggregate([
          {
            $sort: {
              count: -1,
            },
          },

          {
            $limit: 1,
          },

          {
            $project: {
              _id: 0,

              asn: "$asn",

              org: "$asn_org",

              provider: "$provider",

              count: 1,
            },
          },
        ]);

      const recentAttackRate =
        await DShieldLog.countDocuments({
          timestamp: {
            $gte: new Date(
              Date.now() -
              5 * 60 * 1000
            ),
          },
        });

      // =====================================================
      // FINAL RESPONSE
      // =====================================================

      const payload = {

        ok: true,

        generatedAt:
          new Date().toISOString(),

        // ============================================
        // CORE
        // ============================================

        coreSummary,

        // ============================================
        // BEHAVIOR
        // ============================================

        behaviorSummary,

        // ============================================
        // SUPPORTING METRICS
        // ============================================

        topIP:
          topIP[0] || null,

        topPort:
          topPort[0] || null,

        topASN:
          topASN[0] || null,

        recentAttackRate,
      };

      // ==============================================
      // REAL-TIME BROADCAST
      // ==============================================

      if (req.app.locals.io) {

        req.app.locals.io.emit(
          "telemetry:update",
          payload
        );

        console.log(
          "📡 telemetry:update broadcasted"
        );
      }

      // ==============================================
      // RESPONSE
      // ==============================================

      return res.json(payload);

    } catch (err) {

      console.error(
        "❌ Threat Summary Error:",
        err
      );

      return res.status(500).json({
        ok: false,
        error:
          err.message ||
          "Threat summary failed",
      });
    }
  };

// =========================================================
// GEOLOCATION
// =========================================================

exports.getGeolocation = async (req, res) => {
  try {
    console.log("🚀 /api/charts/geolocation HIT");

    const geoDocs = await GeolocationCache.find({
      latitude: { $ne: null },
      longitude: { $ne: null },
    })
      .sort({ createdAt: -1 })
      .limit(MAX_GEO_IPS)
      .lean();

    console.log(`✅ geo cache docs found: ${geoDocs.length}`);

    const results = geoDocs.map((geo) => ({
      ip: geo.ip,

      count: geo.count || 1,

      country: geo.country || "Unknown",
      region: geo.region || "Unknown",
      city: geo.city || "Unknown",

      latitude: Number(geo.latitude),
      longitude: Number(geo.longitude),

      asn: geo.asn || "N/A",

      org:
        geo.asn_org ||
        geo.org ||
        "Unknown Org",

      provider:
        geo.provider ||
        "Unknown Provider",
    }));

    console.log(`✅ geolocation results returned: ${results.length}`);

    return res.json({
      results,
    });

  } catch (err) {
    console.error("❌ Geolocation Error:", err);

    return res.status(500).json({
      error: "Geolocation route failed",
      details: err.message,
    });
  }
};