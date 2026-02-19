import React, { useRef, useEffect } from 'react';
import * as d3 from 'd3';

const D3BarChart = () => {
  const chartRef = useRef(null);

  useEffect(() => {
    // Sample data
    const data = [12, 19, 3, 5, 2, 3];

    // Set dimensions
    const width = 400;
    const height = 200;
    const margin = { top: 20, right: 30, bottom: 30, left: 40 };

    // Clear previous chart, if any
    d3.select(chartRef.current).selectAll('*').remove();

    // Create SVG container
    const svg = d3
      .select(chartRef.current)
      .append('svg')
      .attr('width', width + margin.left + margin.right)
      .attr('height', height + margin.top + margin.bottom)
      .append('g')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Create X scale
    const x = d3
      .scaleBand()
      .domain(data.map((_, i) => i))
      .range([0, width])
      .padding(0.1);

    // Create Y scale
    const y = d3
      .scaleLinear()
      .domain([0, d3.max(data)])
      .nice()
      .range([height, 0]);

    // Add X axis
    svg
      .append('g')
      .attr('transform', `translate(0,${height})`)
      .call(d3.axisBottom(x).tickFormat((d) => `Item ${d + 1}`));

    // Add Y axis
    svg.append('g').call(d3.axisLeft(y));

    // Add bars
    svg
      .selectAll('.bar')
      .data(data)
      .enter()
      .append('rect')
      .attr('x', (_, i) => x(i))
      .attr('y', (d) => y(d))
      .attr('width', x.bandwidth())
      .attr('height', (d) => height - y(d))
      .attr('fill', 'steelblue');
  }, []);

  return <div ref={chartRef}></div>;
};

export default D3BarChart;
