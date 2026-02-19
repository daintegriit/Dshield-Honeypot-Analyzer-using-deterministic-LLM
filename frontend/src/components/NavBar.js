// src/components/NavBar.js
import React from "react";
import { Link } from "react-router-dom";

const NavBar = () => {
  return (
    <nav className="bg-gray-900 text-white p-4 flex justify-between">
      <div className="flex space-x-6">
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
      </div>
    </nav>
  );
};

export default NavBar;