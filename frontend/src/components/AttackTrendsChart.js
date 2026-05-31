import React, {
  useEffect,
  useRef,
  useState,
  useMemo,
  useCallback,
} from "react";

import * as echarts from "echarts";

import apiService
  from "../services/apiService";

const REFRESH_INTERVAL =
  15000;

const TOTAL_MINUTES = 60;

// ======================================================
// VISUAL FLOOR
// ======================================================

const VISUAL_FLOOR =
  0.35;

const AttackTrendsChart = () => {

  // ====================================================
  // REFS
  // ====================================================

  const chartRef =
    useRef(null);

  const chartInstanceRef =
    useRef(null);

  // ====================================================
  // STATE
  // ====================================================

  const [attackData,
    setAttackData] =
      useState([]);

  const [smaPeriod,
    setSmaPeriod] =
      useState(5);

  const [loading,
    setLoading] =
      useState(true);

  const [stale,
    setStale] =
      useState(false);

  // ====================================================
  // BUILD CONTINUOUS TIMELINE
  // ====================================================

  const buildContinuousTimeline =
    useCallback(
      (
        rawData,
        totalMinutes
      ) => {

        const now =
          new Date();

        const timeline =
          [];

        for (
          let i =
            totalMinutes - 1;
          i >= 0;
          i--
        ) {

          const ts =
            new Date(
              now.getTime() -
              i * 60000
            );

          const key =
            ts
              .toISOString()
              .slice(0, 16)
              .replace(
                "T",
                " "
              );

          timeline.push({

            time: key,

            count: 0,

            inactive: true,
          });
        }

        const lookup =
          {};

        for (const item of rawData) {

          if (!item?.time)
            continue;

          lookup[item.time] =
            Number(
              item.count || 0
            );
        }

        for (const point of timeline) {

          if (
            Object.prototype.hasOwnProperty.call(
              lookup,
              point.time
            )
          ) {

            point.count =
              lookup[
                point.time
              ];

            point.inactive =
              lookup[
                point.time
              ] === 0;
          }
        }

        return timeline;

      },
      []
    );

  // ====================================================
  // SMA
  // ====================================================

  const calculateSMA =
    useCallback(
      (
        data,
        period
      ) => {

        if (
          period === 0
        ) {

          return Array(
            data.length
          ).fill(null);
        }

        const sma =
          [];

        for (
          let i = 0;
          i < data.length;
          i++
        ) {

          if (
            i <
            period - 1
          ) {

            sma.push(null);

            continue;
          }

          const slice =
            data.slice(
              i - period + 1,
              i + 1
            );

          const avg =
            slice.reduce(
              (a, b) =>
                a + b,
              0
            ) / period;

          sma.push(
            Number(
              avg.toFixed(2)
            )
          );
        }

        return sma;

      },
      []
    );

  // ====================================================
  // FETCH
  // ====================================================

  useEffect(() => {

    let mounted =
      true;

    const fetchTrends =
      async () => {

        try {

          setLoading(
            true
          );

          const data =
            await apiService.getAttackTrends(
              TOTAL_MINUTES
            );

          if (
            !mounted
          ) {
            return;
          }

          if (
            Array.isArray(
              data
            )
          ) {

            const continuous =
              buildContinuousTimeline(
                data,
                TOTAL_MINUTES
              );

            setAttackData(
              continuous
            );

            setStale(
              false
            );
          }

        } catch (err) {

          console.error(
            "❌ Attack trend failure:",
            err
          );

          if (
            mounted
          ) {

            setStale(
              true
            );
          }

        } finally {

          if (
            mounted
          ) {

            setLoading(
              false
            );
          }
        }
      };

    fetchTrends();

    const interval =
      setInterval(
        fetchTrends,
        REFRESH_INTERVAL
      );

    return () => {

      mounted =
        false;

      clearInterval(
        interval
      );
    };

  }, [
    buildContinuousTimeline
  ]);

  // ====================================================
  // CLEAN DATA
  // ====================================================

  const cleaned =
    useMemo(() => {

      return attackData.filter(
        (item) =>
          item &&
          typeof item.count ===
            "number" &&
          item.time
      );

    }, [attackData]);

  // ====================================================
  // METRICS
  // ====================================================

  const latestCount =
    cleaned.length
      ? cleaned[
          cleaned.length - 1
        ]?.count || 0
      : 0;

  const lastHourTotal =
    cleaned.reduce(
      (sum, row) =>
        sum +
        Number(
          row.count || 0
        ),
      0
    );

  const activeMinutes =
    cleaned.filter(
      (r) =>
        r.count > 0
    ).length;

  const peakTraffic =
    Math.max(
      ...cleaned.map(
        (r) =>
          r.count || 0
      ),
      0
    );

  // ====================================================
  // CHART
  // ====================================================

  useEffect(() => {

    if (
      !chartRef.current
    ) {
      return;
    }

    if (
      !chartInstanceRef.current
    ) {

      chartInstanceRef.current =
        echarts.init(
          chartRef.current,
          null,
          {
            renderer:
              "canvas",
            useDirtyRect:
              true,
          }
        );
    }

    const chart =
      chartInstanceRef.current;

    if (
      !cleaned.length
    ) {

      chart.clear();

      chart.setOption({

        backgroundColor:
          "transparent",

        graphic: [

          {
            type: "text",

            left:
              "center",

            top:
              "middle",

            style: {

              text:
                loading
                  ? "Loading attack telemetry..."
                  : stale
                  ? "Attack telemetry stale..."
                  : "No attack telemetry",

              fill:
                stale
                  ? "#facc15"
                  : "#64748b",

              fontSize:
                14,
            },
          },
        ],
      });

      return;
    }

    const times =
      cleaned.map(
        (r) =>
          r.time
      );

    const counts =
      cleaned.map(
        (r) =>
          r.count > 0
            ? r.count
            : VISUAL_FLOOR
      );

    const movingAvg =
      calculateSMA(
        counts,
        smaPeriod
      );

    const maxPoint =
      Math.max(
        ...counts
      );

    const maxIndex =
      counts.findIndex(
        (v) =>
          v === maxPoint
      );

    const latestPoint =
      counts[
        counts.length - 1
      ];

    const realMax =
      Math.max(
        ...cleaned.map(
          (r) =>
            r.count || 0
        ),
        1
      );

    const yAxisMax =
      realMax <= 1
        ? 6
        : realMax <= 5
        ? 8
        : realMax <= 20
        ? 25
        : Math.ceil(
            realMax *
            1.15
          );

    chart.setOption({

      backgroundColor:
        "transparent",

      animation:
        true,

      animationDuration:
        300,

      animationEasing:
        "linear",

      grid: {

        left: 42,

        right: 18,

        top: 18,

        bottom: 42,
      },

      tooltip: {

        trigger:
          "axis",

        backgroundColor:
          "#0b1220",

        borderColor:
          "#334155",

        borderWidth:
          1,

        textStyle: {
          color:
            "#fff",
        },

        formatter:
          (
            params
          ) => {

            const point =
              params?.[0];

            if (
              !point
            ) {
              return "";
            }

            return `
              <div style="
                padding:8px;
                min-width:160px;
              ">

                <div style="
                  font-weight:bold;
                  margin-bottom:8px;
                  color:#fff;
                  font-size:13px;
                ">
                  ${point.axisValue}
                </div>

                <div style="
                  color:#4fc3f7;
                ">
                  Attack Volume:
                  <strong>
                    ${Number(
                      point.value
                    ).toFixed(2)}
                  </strong>
                </div>

              </div>
            `;
          },
      },

      dataZoom: [

        {
          type:
            "inside",
        },

        {
          type:
            "slider",

          height:
            14,

          bottom:
            8,

          borderColor:
            "#1e293b",

          backgroundColor:
            "#0f172a",

          fillerColor:
            "rgba(79,195,247,0.15)",

          textStyle: {
            color:
              "#64748b",
          },
        },
      ],

      xAxis: {

        type:
          "category",

        boundaryGap:
          false,

        data:
          times,

        axisLine: {

          lineStyle: {
            color:
              "#334155",
          },
        },

        axisTick: {
          show:
            false,
        },

        axisLabel: {

          color:
            "#94a3b8",

          fontSize:
            9,

          rotate:
            25,

          formatter:
            (
              v
            ) =>
              v?.substring(
                11
              ) || "",
        },
      },

      yAxis: {

        type:
          "value",

        min: 0,

        max:
          yAxisMax,

        splitNumber:
          6,

        axisLabel: {

          color:
            "#94a3b8",

          fontSize:
            9,
        },

        axisLine: {

          lineStyle: {
            color:
              "#334155",
          },
        },

        splitLine: {

          lineStyle: {
            color:
              "rgba(255,255,255,0.05)",
          },
        },
      },

      series: [

        {
          name:
            "Threat Activity",

          type:
            "line",

          smooth:
            0.5,

          connectNulls:
            true,

          sampling:
            "lttb",

          showSymbol:
            false,

          data:
            counts,

          lineStyle: {

            width:
              3,

            color:
              "#ff7043",

            shadowBlur:
              14,

            shadowColor:
              "rgba(255,112,67,0.45)",
          },

          areaStyle: {

            color:
              new echarts.graphic.LinearGradient(
                0,
                0,
                0,
                1,
                [

                  {
                    offset: 0,
                    color:
                      "rgba(255,112,67,0.68)",
                  },

                  {
                    offset: 1,
                    color:
                      "rgba(255,112,67,0)",
                  },
                ]
              ),
          },

          emphasis: {
            focus:
              "series",
          },
        },

        {
          name:
            `SMA-${smaPeriod}`,

          type:
            "line",

          smooth:
            true,

          showSymbol:
            false,

          data:
            movingAvg,

          lineStyle: {

            width:
              2,

            type:
              "dashed",

            color:
              "#4fc3f7",
          },
        },

        ...(maxPoint >
        VISUAL_FLOOR

          ? [

              {
                name:
                  "Peak Event",

                type:
                  "effectScatter",

                data: [

                  [
                    times[
                      maxIndex
                    ],

                    maxPoint,
                  ],
                ],

                symbolSize:
                  18,

                rippleEffect:
                  {
                    scale:
                      4,
                  },

                itemStyle:
                  {

                    color:
                      "#ff1744",

                    shadowBlur:
                      18,

                    shadowColor:
                      "rgba(255,23,68,0.55)",
                  },
              },
            ]

          : []),

        {
          name:
            "Latest",

          type:
            "effectScatter",

          data: [

            [
              times[
                times.length -
                  1
              ],

              latestPoint,
            ],
          ],

          symbolSize:
            latestPoint >
            VISUAL_FLOOR
              ? 10
              : 7,

          rippleEffect:
            {
              scale:
                2,
            },

          itemStyle: {

            color:
              latestPoint >
              VISUAL_FLOOR
                ? "#00e676"
                : "#64748b",

            shadowBlur:
              12,

            shadowColor:
              latestPoint >
              VISUAL_FLOOR
                ? "rgba(0,230,118,0.5)"
                : "rgba(100,116,139,0.45)",
          },
        },
      ],

    }, true);

  }, [
    cleaned,
    smaPeriod,
    loading,
    stale,
    calculateSMA,
  ]);

  // ====================================================
  // SAFE RESIZE
  // ====================================================

  useEffect(() => {

    const chart =
      chartInstanceRef.current;

    if (
      !chart ||
      !chartRef.current
    ) {
      return;
    }

    const handleResize =
      () => {

        requestAnimationFrame(() => {

          if (
            chartInstanceRef.current
          ) {

            chartInstanceRef.current.resize();

          }

        });

      };

    window.addEventListener(
      "resize",
      handleResize
    );

    const timeout =
      setTimeout(
        handleResize,
        150
      );

    return () => {

      clearTimeout(timeout);

      window.removeEventListener(
        "resize",
        handleResize
      );

    };

  }, []);

  // ====================================================
  // CLEANUP
  // ====================================================

  useEffect(() => {

    return () => {

      if (
        chartInstanceRef.current
      ) {

        chartInstanceRef.current.dispose();

        chartInstanceRef.current =
          null;
      }
    };

  }, []);

  // ====================================================
  // UI
  // ====================================================

  return (

    <div className="
      w-full
      h-full
      flex
      flex-col
      overflow-hidden
      min-h-0
    ">

      <div className="
        flex
        items-center
        justify-between
        gap-3
        mb-2
        text-[11px]
        shrink-0
      ">

        <div className="
          flex
          items-center
          gap-3
          flex-wrap
          text-gray-300
        ">

          <span>
            Current:
            {" "}
            <span className="
              text-white
              font-semibold
            ">
              {latestCount}
            </span>
          </span>

          <span>
            Last Hour:
            {" "}
            <span className="
              text-cyan-300
              font-semibold
            ">
              {lastHourTotal}
            </span>
          </span>

          <span>
            Active:
            {" "}
            <span className="
              text-orange-300
              font-semibold
            ">
              {activeMinutes}m
            </span>
          </span>

          <span>
            Peak:
            {" "}
            <span className="
              text-red-400
              font-semibold
            ">
              {peakTraffic}
            </span>
          </span>

        </div>

        <div className="
          flex
          items-center
          gap-2
          text-[11px]
          shrink-0
        ">

          <span className="
            text-gray-400
          ">
            Smoothing
          </span>

          <select
            value={smaPeriod}
            onChange={(e) =>
              setSmaPeriod(
                Number(
                  e.target.value
                )
              )
            }
            className="
              bg-gray-900
              border
              border-gray-700
              px-2
              py-1
              rounded
              text-white
              outline-none
              focus:border-cyan-400
            "
          >

            <option value={0}>
              None
            </option>

            <option value={3}>
              SMA-3
            </option>

            <option value={5}>
              SMA-5
            </option>

            <option value={10}>
              SMA-10
            </option>

          </select>
        </div>
      </div>

      <div
        ref={chartRef}
        className="
          flex-1
          min-h-0
          w-full
        "
      />
    </div>
  );
};

export default AttackTrendsChart;