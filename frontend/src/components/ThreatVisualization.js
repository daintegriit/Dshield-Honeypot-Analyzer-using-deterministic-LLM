import React, { useState } from 'react';
import ThreeJSGlobe from './ThreeDGlobe';
import RealTimeThreatMap from './RealTimeThreatMap';

const ThreatVisualization = () => {
  const [view, setView] = useState('globe');

  return (
    <div className="w-full h-full bg-gray-800 rounded-lg p-2 overflow-hidden flex flex-col">

      {/* Controls */}
      <div className="flex items-center mb-2 shrink-0">
        <button
          onClick={() => setView('globe')}
          className={`px-3 py-1 rounded text-sm ${
            view === 'globe' ? 'bg-green-600' : 'bg-gray-700'
          }`}
        >
          3D Globe
        </button>

        <button
          onClick={() => setView('map')}
          className={`px-3 py-1 rounded text-sm ml-2 ${
            view === 'map' ? 'bg-green-600' : 'bg-gray-700'
          }`}
        >
          Threat Map
        </button>
      </div>

      {/* Visualization Area */}
      <div className="flex-1 w-full overflow-hidden">
        {view === 'globe' && <ThreeJSGlobe />}
        {view === 'map' && <RealTimeThreatMap />}
      </div>

    </div>
  );
};

export default ThreatVisualization;