import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import worldMapData from '../data/world-110m.json'; // Use a topojson world map file

const ThreatMap = () => {
  const svgRef = useRef();

  useEffect(() => {
    const width = 800;
    const height = 400;

    const projection = d3.geoMercator().scale(100).translate([width / 2, height / 2]);
    const path = d3.geoPath().projection(projection);

    // Clear previous chart
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height);

    // Load map data
    svg.append('path')
      .datum(topojson.feature(worldMapData, worldMapData.objects.countries))
      .attr('d', path)
      .attr('fill', '#ddd')
      .attr('stroke', '#333');

    // Mock attack data
    const mockAttacks = [
      { lat: 40.7128, lon: -74.006, type: 'DDoS' },
      { lat: 51.5074, lon: -0.1278, type: 'Malware' },
      { lat: 35.6895, lon: 139.6917, type: 'Phishing' },
    ];

    // Plot attack points
    svg.selectAll('circle')
      .data(mockAttacks)
      .enter()
      .append('circle')
      .attr('cx', d => projection([d.lon, d.lat])[0])
      .attr('cy', d => projection([d.lon, d.lat])[1])
      .attr('r', 5)
      .attr('fill', 'red')
      .attr('opacity', 0.7)
      .append('title')
      .text(d => `Attack Type: ${d.type}`);
  }, []);

  return <svg ref={svgRef}></svg>;
};

export default ThreatMap;
