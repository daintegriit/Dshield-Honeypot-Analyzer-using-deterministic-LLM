import React, { useEffect, useRef } from "react";
import * as d3 from "d3";
import * as topojson from "topojson-client";
import worldMapData from "../data/world-110m.json";
import apiService from "../services/apiService";

const RealTimeThreatMap = () => {
  const svgRef = useRef(null);
  const wrapperRef = useRef(null);
  const intervalRef = useRef(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    if (!wrapperRef.current) return;

    mountedRef.current = true;

    const wrapper = wrapperRef.current;
    const svg = d3.select(svgRef.current);

    let zoomBehavior;

    const render = async () => {
      const width = wrapper.clientWidth;
      const height = wrapper.clientHeight;

      svg.selectAll("*").remove();

      svg
        .attr("viewBox", `0 0 ${width} ${height}`)
        .attr("preserveAspectRatio", "xMidYMid meet")
        .style("cursor", "grab");

      const g = svg.append("g");

      // ----------------------------
      // Projection
      // ----------------------------
      const projection = d3.geoMercator();

      const geoData = topojson.feature(
        worldMapData,
        worldMapData.objects.countries
      );

      projection.fitSize([width, height], geoData);

      const path = d3.geoPath().projection(projection);

      // ----------------------------
      // Draw Map
      // ----------------------------
      g.append("path")
        .datum(geoData)
        .attr("d", path)
        .attr("fill", "#111827")
        .attr("stroke", "#374151")
        .attr("stroke-width", 0.5);

      // ----------------------------
      // 🔥 Fetch REAL attack data
      // ----------------------------
      let attackData = [];

      try {
        const res = await apiService.getGeolocation();

        if (res?.results && Array.isArray(res.results)) {
          attackData = res.results
            .filter((d) => d.latitude && d.longitude)
            .slice(0, 50); // 🔥 prevent overload
        }
      } catch (err) {
        console.error("Threat map fetch error:", err);
      }

      // ----------------------------
      // Color scale
      // ----------------------------
      const colorScale = d3
        .scaleSequential(d3.interpolateReds)
        .domain([0, d3.max(attackData, (d) => d.count) || 1]);

      // ----------------------------
      // Attack Points
      // ----------------------------
      g.selectAll(".attack-point")
        .data(attackData)
        .enter()
        .append("circle")
        .attr("cx", (d) => projection([d.longitude, d.latitude])[0])
        .attr("cy", (d) => projection([d.longitude, d.latitude])[1])
        .attr("r", (d) => Math.max(2, Math.log(d.count + 1)))
        .attr("fill", (d) => colorScale(d.count))
        .attr("opacity", 0.85)
        .append("title")
        .text((d) => `${d.ip} (${d.country}) → ${d.count} attacks`);

      // ----------------------------
      // Zoom + Pan
      // ----------------------------
      zoomBehavior = d3
        .zoom()
        .scaleExtent([1, 6])
        .on("zoom", (event) => {
          g.attr("transform", event.transform);
        });

      svg.call(zoomBehavior);
    };

    // initial render
    render();

    // live refresh
    intervalRef.current = setInterval(() => {
      if (mountedRef.current) render();
    }, 5000);

    // resize handling
    const resizeObserver = new ResizeObserver(() => {
      render();
    });

    resizeObserver.observe(wrapper);

    // ----------------------------
    // CLEANUP
    // ----------------------------
    return () => {
      mountedRef.current = false;
      clearInterval(intervalRef.current);

      if (zoomBehavior) {
        svg.on(".zoom", null);
      }

      resizeObserver.disconnect();
      svg.selectAll("*").remove();
    };
  }, []);

  return (
    <div className="w-full h-full min-h-0 overflow-hidden" ref={wrapperRef}>
      <svg ref={svgRef} className="w-full h-full" />
    </div>
  );
};

export default RealTimeThreatMap;