import React, {
  useEffect,
  useRef
} from "react";

import * as d3 from "d3";
import * as topojson from "topojson-client";

import worldMapData
from "../data/world-110m.json";

import {
  useTelemetry
} from "../context/TelemetryContext";


const ThreatMap = () => {

  // ===================================================
  // TELEMETRY
  // ===================================================

  const {

    geo: attackData,

    loading,

    stale,

    backendHealthy,

    latency,

    lastUpdated

  } = useTelemetry();

  // ===================================================
  // REFS
  // ===================================================

  const svgRef =
    useRef(null);

  const resizeObserverRef =
    useRef(null);

  // ===================================================
  // D3 RENDER
  // ===================================================

  useEffect(() => {

    if (!svgRef.current)
      return;

    const container =
      svgRef.current;

    const render = () => {

      const width =
        container.clientWidth;

      const height =
        container.clientHeight;

      if (
        !width ||
        !height
      ) {
        return;
      }

      // =================================================
      // PROJECTION
      // =================================================

      const projection =
        d3.geoMercator()
          .scale(
            width / 6.2
          )
          .translate([
            width / 2,
            height / 1.6
          ]);

      const path =
        d3.geoPath()
          .projection(
            projection
          );

      // =================================================
      // SVG
      // =================================================

      const svg =
        d3.select(container);

      svg.selectAll("*")
        .remove();

      svg
        .attr("width", width)
        .attr("height", height);

      // =================================================
      // BACKGROUND
      // =================================================

      svg.append("rect")
        .attr(
          "width",
          width
        )
        .attr(
          "height",
          height
        )
        .attr(
          "fill",
          "#071426"
        );

      // =================================================
      // TACTICAL GRID
      // =================================================

      for (
        let i = 0;
        i < width;
        i += 40
      ) {

        svg.append("line")
          .attr("x1", i)
          .attr("y1", 0)
          .attr("x2", i)
          .attr("y2", height)
          .attr(
            "stroke",
            "#00bfff"
          )
          .attr(
            "stroke-opacity",
            0.03
          );
      }

      for (
        let i = 0;
        i < height;
        i += 40
      ) {

        svg.append("line")
          .attr("x1", 0)
          .attr("y1", i)
          .attr("x2", width)
          .attr("y2", i)
          .attr(
            "stroke",
            "#00bfff"
          )
          .attr(
            "stroke-opacity",
            0.03
          );
      }

      // =================================================
      // DEFINITIONS
      // =================================================

      const defs =
        svg.append("defs");

      // -------------------------------------------------
      // GLOW FILTER
      // -------------------------------------------------

      const glow =
        defs.append("filter")
          .attr(
            "id",
            "glow"
          );

      glow.append(
        "feGaussianBlur"
      )
        .attr(
          "stdDeviation",
          "4"
        )
        .attr(
          "result",
          "blur"
        );

      const merge =
        glow.append(
          "feMerge"
        );

      merge.append(
        "feMergeNode"
      )
        .attr(
          "in",
          "blur"
        );

      merge.append(
        "feMergeNode"
      )
        .attr(
          "in",
          "SourceGraphic"
        );

      // =================================================
      // WORLD MAP
      // =================================================

      const countries =
        topojson.feature(
          worldMapData,
          worldMapData.objects
            .countries
        );

      svg.append("g")
        .selectAll("path")
        .data(
          countries.features
        )
        .enter()
        .append("path")
        .attr(
          "d",
          path
        )
        .attr(
          "fill",
          "#132235"
        )
        .attr(
          "stroke",
          "#24364d"
        )
        .attr(
          "stroke-width",
          0.55
        );

      // =================================================
      // GRATICULE
      // =================================================

      const grid =
        d3.geoGraticule();

      svg.append("path")
        .datum(grid())
        .attr(
          "d",
          path
        )
        .attr(
          "fill",
          "none"
        )
        .attr(
          "stroke",
          "#00bfff"
        )
        .attr(
          "stroke-opacity",
          0.08
        )
        .attr(
          "stroke-width",
          0.5
        );

      // =================================================
      // VALID ATTACKS
      // =================================================

      const validAttacks =
        attackData.filter(
          (a) =>
            a.latitude != null &&
            a.longitude != null
        );

      // =================================================
      // SOC CENTER
      // =================================================

      const centerX =
        width / 2;

      const centerY =
        height / 2;

      // =================================================
      // ATTACK ARCS
      // =================================================

      validAttacks.forEach(
        (attack) => {

          const coords =
            projection([
              attack.longitude,
              attack.latitude
            ]);

          if (!coords)
            return;

          const [
            x,
            y
          ] = coords;

          const count =
            attack.count || 1;

          // ----------------------------------------------
          // THREAT COLOR
          // ----------------------------------------------

          let beamColor =
            "#4fc3f7";

          if (count > 5000)
            beamColor =
              "#ff1744";
          else if (
            count > 1000
          )
            beamColor =
              "#ff9100";
          else if (
            count > 100
          )
            beamColor =
              "#ffd600";

          // ----------------------------------------------
          // CURVE
          // ----------------------------------------------

          const dx =
            centerX - x;

          const curveHeight =
            Math.abs(dx) * 0.15;

          const curve =
            `
              M ${x} ${y}
              Q ${(
                x + centerX
              ) / 2}
              ${(
                y + centerY
              ) / 2 -
              curveHeight}
              ${centerX}
              ${centerY}
            `;

          // ----------------------------------------------
          // PATH
          // ----------------------------------------------

          const pathElement =
            svg.append("path")
              .attr(
                "d",
                curve
              )
              .attr(
                "fill",
                "none"
              )
              .attr(
                "stroke",
                beamColor
              )
              .attr(
                "stroke-width",
                1.15
              )
              .attr(
                "opacity",
                0.22
              );

          // ----------------------------------------------
          // MOVING PACKET
          // ----------------------------------------------

          const totalLength =
            pathElement.node()
              .getTotalLength();

          const packet =
            svg.append("circle")
              .attr(
                "r",
                2.2
              )
              .attr(
                "fill",
                beamColor
              )
              .style(
                "filter",
                "url(#glow)"
              );

          const animatePacket =
            () => {

              packet
                .transition()
                .duration(
                  2200 +
                  Math.random() *
                  1500
                )
                .ease(
                  d3.easeLinear
                )
                .attrTween(
                  "transform",
                  () => (t) => {

                    const p =
                      pathElement
                        .node()
                        .getPointAtLength(
                          t *
                          totalLength
                        );

                    return `
                      translate(
                        ${p.x},
                        ${p.y}
                      )
                    `;
                  }
                )
                .on(
                  "end",
                  animatePacket
                );
            };

          animatePacket();
        }
      );

      // =================================================
      // ATTACK MARKERS
      // =================================================

      const markerGroup =
        svg.append("g");

      validAttacks.forEach(
        (attack) => {

          const coords =
            projection([
              attack.longitude,
              attack.latitude
            ]);

          if (!coords)
            return;

          const [
            x,
            y
          ] = coords;

          const count =
            attack.count || 1;

          // ----------------------------------------------
          // SIZE
          // ----------------------------------------------

          let radius = 3;

          if (count > 5000)
            radius = 10;
          else if (
            count > 1000
          )
            radius = 8;
          else if (
            count > 100
          )
            radius = 6;

          // ----------------------------------------------
          // COLOR
          // ----------------------------------------------

          let color =
            "#4fc3f7";

          if (count > 5000)
            color =
              "#ff1744";
          else if (
            count > 1000
          )
            color =
              "#ff9100";
          else if (
            count > 100
          )
            color =
              "#ffd600";

          // ----------------------------------------------
          // OUTER PULSE
          // ----------------------------------------------

          const pulse =
            markerGroup
              .append(
                "circle"
              )
              .attr(
                "cx",
                x
              )
              .attr(
                "cy",
                y
              )
              .attr(
                "r",
                radius
              )
              .attr(
                "fill",
                color
              )
              .attr(
                "opacity",
                0.45
              )
              .style(
                "filter",
                "url(#glow)"
              );

          // ----------------------------------------------
          // CORE
          // ----------------------------------------------

          const core =
            markerGroup
              .append(
                "circle"
              )
              .attr(
                "cx",
                x
              )
              .attr(
                "cy",
                y
              )
              .attr(
                "r",
                radius * 0.55
              )
              .attr(
                "fill",
                color
              )
              .attr(
                "opacity",
                0.95
              )
              .style(
                "filter",
                "url(#glow)"
              );

          // ----------------------------------------------
          // TOOLTIP
          // ----------------------------------------------

          core.append("title")
            .text(
              `
${attack.city}, ${attack.country}
Attacks: ${attack.count}
ASN: ${attack.asn}
Provider: ${attack.provider}
Latency: ${latency}ms
              `
            );

          // ----------------------------------------------
          // PULSE
          // ----------------------------------------------

          const animatePulse =
            () => {

              pulse
                .attr(
                  "r",
                  radius
                )
                .attr(
                  "opacity",
                  0.55
                )
                .transition()
                .duration(1800)
                .ease(
                  d3.easeCubicOut
                )
                .attr(
                  "r",
                  radius * 3
                )
                .attr(
                  "opacity",
                  0
                )
                .on(
                  "end",
                  animatePulse
                );
            };

          animatePulse();
        }
      );

      // =================================================
      // SOC CORE
      // =================================================

      const socCore =
        svg.append("circle")
          .attr(
            "cx",
            centerX
          )
          .attr(
            "cy",
            centerY
          )
          .attr(
            "r",
            6
          )
          .attr(
            "fill",
            stale
              ? "#f59e0b"
              : backendHealthy
              ? "#00e5ff"
              : "#ff1744"
          )
          .attr(
            "opacity",
            0.95
          )
          .style(
            "filter",
            "url(#glow)"
          );

      const animateCore =
        () => {

          socCore
            .transition()
            .duration(1400)
            .attr(
              "r",
              9
            )
            .attr(
              "opacity",
              0.45
            )
            .transition()
            .duration(1400)
            .attr(
              "r",
              6
            )
            .attr(
              "opacity",
              0.95
            )
            .on(
              "end",
              animateCore
            );
        };

      animateCore();

      // =================================================
      // LOADING STATE
      // =================================================

      if (loading) {

        svg.append("text")
          .attr(
            "x",
            width / 2
          )
          .attr(
            "y",
            height / 2
          )
          .attr(
            "text-anchor",
            "middle"
          )
          .attr(
            "fill",
            "#00bfff"
          )
          .attr(
            "font-size",
            15
          )
          .attr(
            "font-weight",
            600
          )
          .text(
            "Loading telemetry engine..."
          );
      }

      // =================================================
      // EMPTY STATE
      // =================================================

      if (
        !loading &&
        validAttacks.length === 0
      ) {

        svg.append("text")
          .attr(
            "x",
            width / 2
          )
          .attr(
            "y",
            height / 2
          )
          .attr(
            "text-anchor",
            "middle"
          )
          .attr(
            "fill",
            "#64748b"
          )
          .attr(
            "font-size",
            15
          )
          .attr(
            "font-weight",
            600
          )
          .text(
            "Waiting for global threat telemetry..."
          );
      }

      // =================================================
      // LIVE COUNTER
      // =================================================

      svg.append("text")
        .attr(
          "x",
          16
        )
        .attr(
          "y",
          height - 18
        )
        .attr(
          "fill",
          "#00e5ff"
        )
        .attr(
          "font-size",
          11
        )
        .attr(
          "font-family",
          "monospace"
        )
        .attr(
          "opacity",
          0.85
        )
        .text(
          `LIVE GLOBAL EVENTS: ${validAttacks.length}`
        );

      // =================================================
      // STATUS
      // =================================================

      let status =
        "SOC ONLINE";

      let statusColor =
        "#22c55e";

      if (!backendHealthy) {

        status =
          "BACKEND OFFLINE";

        statusColor =
          "#ff1744";

      } else if (stale) {

        status =
          "TELEMETRY STALE";

        statusColor =
          "#f59e0b";
      }

      svg.append("text")
        .attr(
          "x",
          width - 16
        )
        .attr(
          "y",
          20
        )
        .attr(
          "text-anchor",
          "end"
        )
        .attr(
          "fill",
          statusColor
        )
        .attr(
          "font-size",
          11
        )
        .attr(
          "font-family",
          "monospace"
        )
        .attr(
          "font-weight",
          700
        )
        .text(
          status
        );

      // =================================================
      // LATENCY
      // =================================================

      svg.append("text")
        .attr(
          "x",
          width - 16
        )
        .attr(
          "y",
          38
        )
        .attr(
          "text-anchor",
          "end"
        )
        .attr(
          "fill",
          "#94a3b8"
        )
        .attr(
          "font-size",
          10
        )
        .attr(
          "font-family",
          "monospace"
        )
        .text(
          `LATENCY ${latency}ms`
        );

      // =================================================
      // LAST UPDATE
      // =================================================

      if (lastUpdated) {

        svg.append("text")
          .attr(
            "x",
            width - 16
          )
          .attr(
            "y",
            54
          )
          .attr(
            "text-anchor",
            "end"
          )
          .attr(
            "fill",
            "#64748b"
          )
          .attr(
            "font-size",
            9
          )
          .attr(
            "font-family",
            "monospace"
          )
          .text(
            `SYNC ${new Date(
              lastUpdated
            ).toLocaleTimeString()}`
          );
      }
    };

    // ===================================================
    // INITIAL
    // ===================================================

    render();

    // ===================================================
    // RESIZE OBSERVER
    // ===================================================

    if (
      resizeObserverRef.current
    ) {

      resizeObserverRef.current
        .disconnect();
    }

    resizeObserverRef.current =
      new ResizeObserver(
        render
      );

    resizeObserverRef.current
      .observe(
        container
      );

    return () => {

      resizeObserverRef.current
        ?.disconnect();

      resizeObserverRef.current =
        null;
    };

  }, [
    attackData,
    loading,
    stale,
    backendHealthy,
    latency,
    lastUpdated
  ]);

  // ===================================================
  // UI
  // ===================================================

  return (

    <svg
      ref={svgRef}
      className="
        w-full
        h-full
        min-h-0
        rounded-lg
        overflow-hidden
      "
    />
  );
};

export default ThreatMap;