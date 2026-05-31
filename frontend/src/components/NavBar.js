// src/components/NavBar.js
import React from "react";
import { Link } from "react-router-dom";

const NavBar = () => {
  return (
    <nav className="bg-gray-900 text-white p-4 flex justify-between">
        <div className="flex space-x-6">
                <h1 className="text-2xl font-extrabold text-center text-green-400 mb-3">
          Chiron
        </h1>
        <Link to="/" className="hover:text-green-400 hover:drop-shadow-lg transition-all duration-300">
          Home
        </Link>
        <Link to="/dashboard" className="hover:text-green-400 hover:drop-shadow-lg transition-all duration-300">
          Dashboard
        </Link>
        <Link to="/cti-reports" className="hover:text-green-400 hover:drop-shadow-lg transition-all duration-300">
          CTI Reports
        </Link>
        <Link to="/dashboard2" className="hover:text-green-400 hover:drop-shadow-lg transition-all duration-300">
          Dashboard 2
        </Link>
        <Link to="/risk-fabric" className="hover:text-green-400 hover:drop-shadow-lg transition-all duration-300">
          Risk Fabric
        </Link>
      </div>
    </nav>
  );
};

export default NavBar;