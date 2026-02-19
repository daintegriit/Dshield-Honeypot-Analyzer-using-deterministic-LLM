import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';
import * as topojson from 'topojson-client';
import worldMapData from '../data/world-110m.json';

const RealTimeThreatMap = () => {
  const svgRef = useRef(null);
  const wrapperRef = useRef(null);

  useEffect(() => {
    if (!wrapperRef.current) return;

    const wrapper = wrapperRef.current;
    const svg = d3.select(svgRef.current);

    const render = () => {
      const width = wrapper.clientWidth;
      const height = wrapper.clientHeight;

      svg.selectAll('*').remove();

      svg
        .attr('viewBox', `0 0 ${width} ${height}`)
        .attr('preserveAspectRatio', 'xMidYMid meet')
        .style('cursor', 'grab');

      // Root transform layer (IMPORTANT)
      const g = svg.append('g');

      // Projection auto-fit
      const projection = d3.geoMercator();
      const geoData = topojson.feature(
        worldMapData,
        worldMapData.objects.countries
      );

      projection.fitSize([width, height], geoData);

      const path = d3.geoPath().projection(projection);

      // Draw map
      g.append('path')
        .datum(geoData)
        .attr('d', path)
        .attr('fill', '#1f2937')
        .attr('stroke', '#374151')
        .attr('stroke-width', 0.5);

      // Mock attack data
      const attackData = [
        { source: [-74.006, 40.7128], target: [-118.2437, 34.0522], type: 'DDoS' },
        { source: [-0.1278, 51.5074], target: [2.3522, 48.8566], type: 'Malware' },
      ];

      const colorScale = d3
        .scaleOrdinal()
        .domain(['DDoS', 'Malware'])
        .range(['#ef4444', '#f59e0b']);

      // Arcs
      g.selectAll('.arc')
        .data(attackData)
        .enter()
        .append('path')
        .attr('class', 'arc')
        .attr('d', d => {
          const [sx, sy] = projection(d.source);
          const [tx, ty] = projection(d.target);
          const dx = tx - sx;
          const dy = ty - sy;
          const dr = Math.sqrt(dx * dx + dy * dy) * 1.2;
          return `M${sx},${sy}A${dr},${dr} 0 0,1 ${tx},${ty}`;
        })
        .attr('fill', 'none')
        .attr('stroke', d => colorScale(d.type))
        .attr('stroke-width', 2)
        .attr('opacity', 0.8);

      // Attack points
      g.selectAll('.attack-point')
        .data(attackData)
        .enter()
        .append('circle')
        .attr('cx', d => projection(d.source)[0])
        .attr('cy', d => projection(d.source)[1])
        .attr('r', 4)
        .attr('fill', d => colorScale(d.type));

      // 🧭 ZOOM + PAN (Globe-equivalent UX)
      const zoom = d3.zoom()
        .scaleExtent([1, 6]) // zoom limits
        .on('zoom', (event) => {
          g.attr('transform', event.transform);
        });

      svg.call(zoom);
    };

    render();

    const resizeObserver = new ResizeObserver(render);
    resizeObserver.observe(wrapper);

    return () => resizeObserver.disconnect();
  }, []);

  return (
    <div ref={wrapperRef} className="w-full h-full relative">
      <svg ref={svgRef} className="w-full h-full" />
    </div>
  );
};

export default RealTimeThreatMap;