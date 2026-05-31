// src/pages/RiskFabricPage.jsx

import React from "react";

import MasterRiskFabric
from "../components/riskFabric/MasterRiskFabric";

import BehavioralSignalCard
from "../components/riskFabric/BehavioralSignalCard";

import BehavioralSignalGrid
from "../components/riskFabric/BehavioralSignalGrid";

import ReplayTimeline
from "../components/riskFabric/ReplayTimeline";

import RiskThresholdBands
from "../components/riskFabric/RiskThresholdBands";

import FusionEquationPanel
from "../components/riskFabric/FusionEquationPanel";

import GovernedReasoningPanel
from "../components/riskFabric/GovernedReasoningPanel";

import MathematicalProvenance
from "../components/riskFabric/MathematicalProvenance";

const RiskFabricPage = () => {

  const telemetry = {};

  // =====================================================
  // SAFE VALUES
  // =====================================================

  const safeRiskScore =
    telemetry?.riskScore ?? 0;

  const safeState =
    telemetry?.state ?? "stable";

  return (

    <div
      className="
        relative
        min-h-screen
        bg-black
        text-white
        overflow-y-auto
        overflow-x-hidden
      "
    >

      {/* ===================================== */}
      {/* GLOBAL CYBER BACKGROUND */}
      {/* ===================================== */}

      <div className="
        fixed
        inset-0
        pointer-events-none
        overflow-hidden
      ">

        {/* TOP CYAN GLOW */}

        <div className="
          absolute
          top-[-10%]
          left-[20%]
          w-[600px]
          h-[600px]
          bg-cyan-500/5
          blur-[160px]
          rounded-full
        " />

        {/* LOWER BLUE GLOW */}

        <div className="
          absolute
          bottom-[-15%]
          right-[10%]
          w-[700px]
          h-[700px]
          bg-blue-500/5
          blur-[180px]
          rounded-full
        " />

        {/* RED THREAT GLOW */}

        <div className="
          absolute
          top-[35%]
          left-[50%]
          w-[500px]
          h-[500px]
          bg-red-500/3
          blur-[140px]
          rounded-full
        " />

      </div>

      {/* ===================================== */}
      {/* MAIN CONTENT */}
      {/* ===================================== */}

      <div className="
        relative
        z-10
      ">

        {/* ================================= */}
        {/* MASTER RISK FABRIC */}
        {/* ================================= */}

        <MasterRiskFabric />

        {/* ================================= */}
        {/* FEATURED SIGNAL CARD */}
        {/* ================================= */}

        <div className="
          px-4
          md:px-8
          pb-8
        ">

          <BehavioralSignalCard
            title="Global Threat Escalation"
            value={`${safeRiskScore}/100`}
            subtitle="
              Deterministic fusion confidence
              derived from operational telemetry,
              behavioral correlation,
              entropy analysis,
              replay intelligence,
              and escalation modeling.
            "
            severity={safeState}
          />

        </div>

        {/* ================================= */}
        {/* BEHAVIORAL SIGNAL GRID */}
        {/* ================================= */}

        <div className="
          px-4
          md:px-8
          pb-10
        ">

          <BehavioralSignalGrid
            telemetry={telemetry}
          />

        </div>

        {/* ================================= */}
        {/* REPLAY TIMELINE */}
        {/* ================================= */}

        <ReplayTimeline />

        {/* ================================= */}
        {/* RISK THRESHOLD BANDS */}
        {/* ================================= */}

        <RiskThresholdBands />

        {/* ================================= */}
        {/* FUSION EQUATION PANEL */}
        {/* ================================= */}

        <FusionEquationPanel />

        {/* ================================= */}
        {/* GOVERNED REASONING */}
        {/* ================================= */}

        <GovernedReasoningPanel />

        {/* ================================= */}
        {/* MATHEMATICAL PROVENANCE */}
        {/* ================================= */}

        <MathematicalProvenance />

        {/* ================================= */}
        {/* FOOTER */}
        {/* ================================= */}

        <div className="
          px-4
          md:px-8
          pb-20
          pt-4
        ">

          <div className="
            rounded-3xl
            border
            border-cyan-500/10
            bg-[#071028]/80
            px-6
            py-6
            backdrop-blur-sm
          ">

            <div className="
              flex
              flex-col
              xl:flex-row
              xl:items-center
              xl:justify-between
              gap-5
            ">

              {/* LEFT */}

              <div>

                <div className="
                  text-xl
                  font-black
                  text-white
                  mb-2
                ">
                  CHIRON Risk Fabric
                </div>

                <div className="
                  text-slate-400
                  text-sm
                  leading-relaxed
                  max-w-3xl
                ">
                  Deterministic telemetry fusion,
                  governed escalation reasoning,
                  behavioral intelligence,
                  replay-aligned threat analysis,
                  and explainable cybersecurity
                  mathematics unified into a
                  single operational intelligence
                  surface.
                </div>

              </div>

              {/* RIGHT */}

              <div className="
                flex
                flex-wrap
                items-center
                gap-3
                text-xs
                uppercase
                tracking-widest
              ">

                <div className="
                  px-3
                  py-2
                  rounded-xl
                  bg-cyan-500/10
                  border
                  border-cyan-500/20
                  text-cyan-300
                ">
                  Deterministic
                </div>

                <div className="
                  px-3
                  py-2
                  rounded-xl
                  bg-green-500/10
                  border
                  border-green-500/20
                  text-green-300
                ">
                  Explainable
                </div>

                <div className="
                  px-3
                  py-2
                  rounded-xl
                  bg-orange-500/10
                  border
                  border-orange-500/20
                  text-orange-300
                ">
                  Governed AI
                </div>

                <div className="
                  px-3
                  py-2
                  rounded-xl
                  bg-red-500/10
                  border
                  border-red-500/20
                  text-red-300
                ">
                  Threat Fusion
                </div>

              </div>

            </div>

          </div>

        </div>

      </div>

    </div>

  );

};

export default RiskFabricPage;