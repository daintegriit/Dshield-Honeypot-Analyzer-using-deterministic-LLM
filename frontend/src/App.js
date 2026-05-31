import React from "react";

import {
  BrowserRouter as Router,
  Route,
  Routes
} from "react-router-dom";

import HomePage
from "./pages/HomePage";

import DashboardPage
from "./pages/DashboardPage";

import DashboardPage2
from "./pages/DashboardPage2";

import CTIReportsPage
from "./pages/CTIReportsPage";

import Register
from "./components/Register";

import Login
from "./components/Login";

import NavBar
from "./components/NavBar";

import {
  AuthProvider
} from "./context/AuthContext";

import {
  TelemetryProvider
} from "./context/TelemetryContext";

import RiskFabricPage
from "./pages/RiskFabricPage";

// ======================================================
// 🔥 CHIRON APP ROOT
// ======================================================

function App() {

  return (

    <AuthProvider>

      <TelemetryProvider>

        <Router>

          {/* ========================================= */}
          {/* 🔥 GLOBAL APP SHELL */}
          {/* ========================================= */}

          <div className="
            bg-black
            text-white
            min-h-screen
            flex
            flex-col
          ">

            {/* ===================================== */}
            {/* 🔥 NAVBAR */}
            {/* ===================================== */}

            <div className="
              sticky
              top-0
              z-50
            ">
              <NavBar />
            </div>

            {/* ===================================== */}
            {/* 🔥 MAIN CONTENT */}
            {/* ===================================== */}

            <main className="
              flex-1
              min-h-0
              flex
              flex-col
            ">

              <Routes>

                {/* ================================= */}
                {/* 🔥 HOME */}
                {/* ================================= */}

                <Route
                  path="/"
                  element={<HomePage />}
                />

                {/* ================================= */}
                {/* 🔥 AUTH */}
                {/* ================================= */}

                <Route
                  path="/register"
                  element={<Register />}
                />

                <Route
                  path="/login"
                  element={<Login />}
                />

                {/* ================================= */}
                {/* 🔥 DASHBOARDS */}
                {/* ================================= */}

                <Route
                  path="/dashboard"
                  element={<DashboardPage />}
                />

                <Route
                  path="/dashboard2"
                  element={<DashboardPage2 />}
                />

                {/* ================================= */}
                {/* 🔥 CTI REPORTS */}
                {/* ================================= */}

                <Route
                  path="/cti-reports"
                  element={<CTIReportsPage />}
                />

                {/* ================================= */}
                {/* 🔥 RISK FABRIC */}
                {/* ================================= */}

                <Route
                  path="/risk-fabric"
                  element={<RiskFabricPage />}
                />

              </Routes>

            </main>

          </div>

        </Router>

      </TelemetryProvider>

    </AuthProvider>
  );
}

export default App;