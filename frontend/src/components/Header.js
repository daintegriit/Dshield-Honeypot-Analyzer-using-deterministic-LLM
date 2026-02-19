// src/components/Header.js
import React from "react";

const Header = () => {
  return (
    <header className="w-full px-6 py-3 border-b border-gray-800 bg-gray-900/80 backdrop-blur">
      <div className="flex items-center justify-between">
        {/* Left: Title */}
        <div>
          <h1 className="text-xl font-bold text-green-400 tracking-wide">
            Cyber Threat Dashboard
          </h1>
          <p className="text-xs text-gray-400">
            Live honeypot-driven threat intelligence
          </p>
        </div>

        {/* Right: Metadata + Actions */}
        <div className="flex items-center gap-4 text-xs text-gray-400">
          <span>
            Last updated:{" "}
            <span className="text-gray-300">
              {new Date().toLocaleTimeString()}
            </span>
          </span>

          <button
            onClick={() => window.location.reload()}
            className="px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium"
          >
            Refresh
          </button>
        </div>
      </div>
    </header>
  );
};

export default Header;