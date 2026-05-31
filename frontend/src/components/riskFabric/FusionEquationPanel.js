// src/components/riskFabric/FusionEquationPanel.js

import React, {
  useEffect,
  useMemo,
  useState,
} from "react";

import {
  Sigma,
  Shield,
  Activity,
  Radar,
  Binary,
  BrainCircuit,
  ShieldAlert,
  Workflow,
  SlidersHorizontal,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
} from "lucide-react";

import apiService from "../../services/apiService";

/*

R = V + E + B + A + C + I + K

V = Volume Amplification
E = Severity Escalation
B = Behavioral Pressure
A = Signal Amplification
C = Command-and-Control Escalation
I = Impact Escalation
K = Behavioral Coupling

*/

const safeNumber = (
  value,
  fallback = 0
) => {

  const parsed =
    Number(value);

  return Number.isFinite(parsed)
    ? parsed
    : fallback;

};

const clamp = (
  value,
  min = 0,
  max = 100
) => {

  return Math.min(
    max,
    Math.max(min, value)
  );

};

export default function FusionEquationPanel() {

  const [telemetry, setTelemetry] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [
    simulationMode,
    setSimulationMode,
  ] = useState(false);

  const [
    overrides,
    setOverrides,
  ] = useState({

    V: null,
    E: null,
    B: null,
    A: null,
    C: null,
    I: null,
    K: null,

  });

  // =====================================================
  // FETCH
  // =====================================================

  useEffect(() => {

    let mounted = true;

    const fetchTelemetry =
      async () => {

        try {

          const summary =
            await apiService.getThreatSummary();

          if (!mounted) {
            return;
          }

          setTelemetry(summary);

        } catch (err) {

          console.error(
            "Fusion equation telemetry error:",
            err
          );

          if (mounted) {
            setTelemetry(null);
          }

        } finally {

          if (mounted) {
            setLoading(false);
          }

        }

      };

    fetchTelemetry();

    const interval =
      setInterval(
        fetchTelemetry,
        10000
      );

    return () => {

      mounted = false;

      clearInterval(interval);

    };

  }, []);

  // =====================================================
  // LIVE DATA
  // =====================================================

  const core =
    telemetry?.coreSummary ||
    telemetry ||
    {};

  const riskComponents =
    core?.riskComponents || {};

  const attackClassification =
    core?.attackClassification || {};

  // =====================================================
  // REAL CHIRON COMPONENTS
  // =====================================================

  const liveValues =
    useMemo(() => {

      return {

        V: safeNumber(
          riskComponents.volumeComponent
        ),

        E: safeNumber(
          riskComponents.severityComponent
        ),

        B: safeNumber(
          riskComponents.behaviorComponent
        ),

        A: safeNumber(
          riskComponents.signalAmplifier
        ),

        C: safeNumber(
          riskComponents.c2Bonus
        ),

        I: safeNumber(
          riskComponents.impactBonus
        ),

        K: safeNumber(
          riskComponents.couplingBonus
        ),

      };

    }, [riskComponents]);

  // =====================================================
  // ACTIVE VALUES
  // =====================================================

  const activeValues =
    useMemo(() => {

      if (!simulationMode) {
        return liveValues;
      }

      return {

        V:
          overrides.V ??
          liveValues.V,

        E:
          overrides.E ??
          liveValues.E,

        B:
          overrides.B ??
          liveValues.B,

        A:
          overrides.A ??
          liveValues.A,

        C:
          overrides.C ??
          liveValues.C,

        I:
          overrides.I ??
          liveValues.I,

        K:
          overrides.K ??
          liveValues.K,

      };

    }, [
      simulationMode,
      overrides,
      liveValues,
    ]);

  // =====================================================
  // REAL RISK CALCULATION
  // =====================================================

  const calculatedRisk =
    useMemo(() => {

      const result =

        activeValues.V +
        activeValues.E +
        activeValues.B +
        activeValues.A +
        activeValues.C +
        activeValues.I +
        activeValues.K;

      return clamp(
        Number(
          result.toFixed(2)
        ),
        0,
        100
      );

    }, [activeValues]);

  // =====================================================
  // BACKEND RISK
  // =====================================================

  const backendRisk =
    safeNumber(
      core?.riskScore0to100 ??
      core?.riskScore
    );

  // =====================================================
  // DELTA
  // =====================================================

  const delta =
    Number(
      Math.abs(
        backendRisk -
        calculatedRisk
      ).toFixed(2)
    );

  // =====================================================
  // FUSION INTEGRITY
  // =====================================================

  const fusionIntegrity =
    delta <= 1
      ? "VALIDATED"
      : delta <= 5
      ? "DIVERGENT"
      : "DESYNCHRONIZED";

  const fusionIntegrityStyles =
    delta <= 1
      ? {

          text:
            "text-green-400",

          badge:
            "bg-green-500/10 text-green-300 border-green-500/20",

          icon:
            (
              <CheckCircle2
                size={14}
              />
            ),

        }
      : delta <= 5
      ? {

          text:
            "text-yellow-300",

          badge:
            "bg-yellow-500/10 text-yellow-300 border-yellow-500/20",

          icon:
            (
              <AlertTriangle
                size={14}
              />
            ),

        }
      : {

          text:
            "text-red-400",

          badge:
            "bg-red-500/10 text-red-300 border-red-500/20",

          icon:
            (
              <XCircle
                size={14}
              />
            ),

        };

  // =====================================================
  // DOMINANT ATTACK
  // =====================================================

  const dominantAttack =
    attackClassification
      ?.dominantAttack?.type ||

    attackClassification
      ?.topAttackType ||

    core?.dominantAttack ||

    "unknown";

  // =====================================================
  // REAL EQUATION TERMS
  // =====================================================

  const equationTerms =
    useMemo(() => {

      return [

        {
          label: "V",

          title:
            "Volume Amplification",

          value:
            activeValues.V.toFixed(
              2
            ),

          description:
            "Traffic saturation and burst amplification pressure.",

          icon:
            (
              <Activity
                size={18}
              />
            ),

          color:
            "text-orange-400",
        },

        {
          label: "E",

          title:
            "Severity Escalation",

          value:
            activeValues.E.toFixed(
              2
            ),

          description:
            "Critical and high severity accumulation.",

          icon:
            (
              <ShieldAlert
                size={18}
              />
            ),

          color:
            "text-red-400",
        },

        {
          label: "B",

          title:
            "Behavioral Pressure",

          value:
            activeValues.B.toFixed(
              2
            ),

          description:
            "Authentication and service targeting pressure.",

          icon:
            (
              <Radar
                size={18}
              />
            ),

          color:
            "text-yellow-300",
        },

        {
          label: "A",

          title:
            "Signal Amplification",

          value:
            activeValues.A.toFixed(
              2
            ),

          description:
            "Multi-signal behavioral agreement amplification.",

          icon:
            (
              <Binary
                size={18}
              />
            ),

          color:
            "text-purple-400",
        },

        {
          label: "C",

          title:
            "C2 Escalation",

          value:
            activeValues.C.toFixed(
              2
            ),

          description:
            "Beaconing and command-and-control escalation.",

          icon:
            (
              <BrainCircuit
                size={18}
              />
            ),

          color:
            "text-cyan-400",
        },

        {
          label: "I",

          title:
            "Impact Escalation",

          value:
            activeValues.I.toFixed(
              2
            ),

          description:
            "Cumulative operational impact severity.",

          icon:
            (
              <Shield
                size={18}
              />
            ),

          color:
            "text-green-400",
        },

        {
          label: "K",

          title:
            "Behavioral Coupling",

          value:
            activeValues.K.toFixed(
              2
            ),

          description:
            "Cross-signal escalation reinforcement.",

          icon:
            (
              <Workflow
                size={18}
              />
            ),

          color:
            "text-blue-400",
        },

      ];

    }, [activeValues]);

  // =====================================================
  // RESET
  // =====================================================

  const resetOverrides =
    () => {

      setSimulationMode(false);

      setOverrides({

        V: null,
        E: null,
        B: null,
        A: null,
        C: null,
        I: null,
        K: null,

      });

    };

  // =====================================================
  // UI
  // =====================================================

  return (

    <section className="
      relative
      z-10
      px-4
      md:px-8
      pb-12
    ">

      {/* HEADER */}

      <div className="
        flex
        flex-col
        xl:flex-row
        xl:items-center
        xl:justify-between
        gap-4
        mb-6
      ">

        <div>

          <h2 className="
            text-2xl
            font-black
            text-white
            mb-2
          ">
            Fusion Equation Engine
          </h2>

          <p className="
            text-slate-400
            text-sm
            max-w-4xl
          ">
            Real Chiron deterministic
            Risk Fabric equation using
            live backend fusion components.
          </p>

        </div>

        <div className="
          flex
          items-center
          gap-3
        ">

          <button
            onClick={() =>
              setSimulationMode(
                !simulationMode
              )
            }
            className="
              flex
              items-center
              gap-2
              px-4
              py-2
              rounded-xl
              bg-cyan-500/10
              border
              border-cyan-500/20
              text-cyan-300
              text-xs
              font-bold
              uppercase
              tracking-wider
            "
          >

            <SlidersHorizontal
              size={14}
            />

            {
              simulationMode
                ? "Override Mode"
                : "Live Mode"
            }

          </button>

          <button
            onClick={
              resetOverrides
            }
            className="
              flex
              items-center
              gap-2
              px-4
              py-2
              rounded-xl
              bg-black/30
              border
              border-white/10
              text-slate-300
              text-xs
              font-bold
              uppercase
              tracking-wider
            "
          >

            <RefreshCw
              size={14}
            />

            Reset

          </button>

        </div>

      </div>

      {/* MAIN PANEL */}

      <div className="
        relative
        overflow-hidden
        rounded-3xl
        border
        border-cyan-500/20
        bg-[#071028]/90
        p-8
        mb-6
        shadow-[0_0_60px_rgba(0,255,255,0.06)]
      ">

        <div className="
          relative
          z-10
        ">

          {/* TITLE */}

          <div className="
            flex
            items-center
            gap-3
            mb-6
          ">

            <Sigma
              className="
                text-cyan-400
              "
              size={28}
            />

            <div>

              <h3 className="
                text-2xl
                font-black
                text-white
              ">
                Chiron Risk Equation
              </h3>

              <p className="
                text-slate-400
                text-sm
              ">
                R = V + E + B + A + C + I + K
              </p>

            </div>

          </div>

          {/* EQUATION */}

          <div className="
            overflow-x-auto
            py-8
          ">

            <div className="
              min-w-[1400px]
              flex
              items-center
              justify-center
              gap-4
            ">

              {
                equationTerms.map(
                  (
                    term,
                    index
                  ) => (

                    <React.Fragment
                      key={term.label}
                    >

                      <EquationBubble
                        label={
                          term.label
                        }
                        value={
                          term.value
                        }
                        color={
                          term.color
                        }
                      />

                      {
                        index <
                        equationTerms.length - 1 && (
                          <Operator />
                        )
                      }

                    </React.Fragment>

                  )
                )
              }

              <Equals />

              <ResultBubble
                riskScore={
                  calculatedRisk
                }
                dominantAttack={
                  dominantAttack
                }
              />

            </div>

          </div>

          {/* VALIDATION */}

          <div className="
            mt-6
            pt-5
            border-t
            border-white/5
          ">

            <div className="
              flex
              flex-wrap
              items-center
              gap-x-5
              gap-y-3
              text-sm
            ">

              {/* BACKEND */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Backend Risk
                </div>

                <div className="
                  text-white
                  font-black
                ">
                  {backendRisk.toFixed(2)}
                </div>

              </div>

              {/* RECOMPUTED */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Recomputed
                </div>

                <div className="
                  text-cyan-300
                  font-black
                ">
                  {calculatedRisk.toFixed(2)}
                </div>

              </div>

              {/* DELTA */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Delta
                </div>

                <div className={`
                  font-black
                  ${fusionIntegrityStyles.text}
                `}>

                  {delta.toFixed(2)}

                </div>

              </div>

              {/* FUSION INTEGRITY */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Fusion Integrity
                </div>

                <div className={`
                  flex
                  items-center
                  gap-2
                  px-3
                  py-1
                  rounded-lg
                  text-[10px]
                  font-black
                  uppercase
                  tracking-[0.2em]
                  border
                  ${fusionIntegrityStyles.badge}
                `}>

                  {fusionIntegrityStyles.icon}

                  {fusionIntegrity}

                </div>

              </div>

              {/* ATTACK */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Dominant Attack
                </div>

                <div className="
                  text-red-300
                  font-black
                  uppercase
                  tracking-wider
                ">
                  {dominantAttack}
                </div>

              </div>

              {/* ENGINE */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Fusion Engine
                </div>

                <div className="
                  px-3
                  py-1
                  rounded-lg
                  text-[10px]
                  font-black
                  uppercase
                  tracking-[0.2em]
                  border
                  border-cyan-500/20
                  bg-cyan-500/10
                  text-cyan-300
                ">

                  DETERMINISTIC

                </div>

              </div>

              {/* MODE */}

              <div className="
                flex
                items-center
                gap-2
              ">

                <div className="
                  text-slate-500
                  uppercase
                  tracking-wider
                  text-xs
                ">
                  Mode
                </div>

                <div className={`
                  px-3
                  py-1
                  rounded-lg
                  text-[10px]
                  font-black
                  uppercase
                  tracking-[0.2em]
                  border
                  ${
                    simulationMode
                      ? "bg-yellow-500/10 text-yellow-300 border-yellow-500/20"
                      : "bg-green-500/10 text-green-300 border-green-500/20"
                  }
                `}>

                  {
                    simulationMode
                      ? "SIMULATION"
                      : "LIVE"
                  }

                </div>

              </div>

            </div>

          </div>

        </div>

      </div>

      {/* OVERRIDE CONTROLS */}

      <div className="
        mb-6
        rounded-3xl
        border
        border-cyan-500/20
        bg-[#071028]/90
        p-6
      ">

        <div className="
          flex
          items-center
          justify-between
          gap-4
          mb-5
        ">

          <div>

            <div className="
              text-white
              font-bold
              text-lg
              mb-1
            ">
              Live Equation Inputs
            </div>

            <div className="
              text-sm
              text-slate-400
            ">
              Override deterministic
              fusion inputs in simulation mode.
            </div>

          </div>

          <div className={`
            px-4
            py-2
            rounded-xl
            text-xs
            font-black
            uppercase
            tracking-[0.2em]
            border
            ${
              simulationMode
                ? "bg-yellow-500/10 text-yellow-300 border-yellow-500/20"
                : "bg-cyan-500/10 text-cyan-300 border-cyan-500/20"
            }
          `}>

            {
              simulationMode
                ? "OVERRIDES ENABLED"
                : "LIVE TELEMETRY"
            }

          </div>

        </div>

        <div className="
          grid
          grid-cols-1
          md:grid-cols-2
          xl:grid-cols-4
          gap-5
        ">

          {
            equationTerms.map(
              (term) => (

                <SliderControl
                  key={term.label}
                  label={`${term.label} — ${term.title}`}
                  value={Number(
                    term.value
                  )}
                  disabled={
                    !simulationMode
                  }
                  max={
                    term.label === "V"
                      ? 60
                      : term.label === "E"
                      ? 30
                      : term.label === "B"
                      ? 25
                      : term.label === "A"
                      ? 25
                      : term.label === "C"
                      ? 20
                      : term.label === "I"
                      ? 8
                      : 5
                  }
                  onChange={(
                    value
                  ) =>
                    setOverrides(
                      (
                        prev
                      ) => ({
                        ...prev,
                        [term.label]:
                          value,
                      })
                    )
                  }
                />

              )
            )
          }

        </div>

      </div>

      {/* TERM GRID */}

      <div className="
        grid
        grid-cols-1
        md:grid-cols-2
        xl:grid-cols-3
        gap-5
      ">

        {
          equationTerms.map(
            (
              term,
              index
            ) => (

              <div
                key={index}
                className="
                  relative
                  overflow-hidden
                  rounded-2xl
                  border
                  border-cyan-500/10
                  bg-[#071028]/90
                  p-5
                  transition-all
                  duration-300
                  hover:border-cyan-500/20
                  hover:shadow-[0_0_40px_rgba(0,255,255,0.05)]
                "
              >

                <div className="
                  flex
                  items-center
                  justify-between
                  mb-5
                ">

                  <div
                    className={`
                      text-4xl
                      font-black
                      ${term.color}
                    `}
                  >
                    {term.label}
                  </div>

                  <div
                    className={`
                      ${term.color}
                    `}
                  >
                    {term.icon}
                  </div>

                </div>

                <div className="
                  text-lg
                  font-bold
                  text-white
                  mb-2
                ">
                  {term.title}
                </div>

                <div className="
                  text-3xl
                  font-black
                  text-cyan-300
                  mb-3
                ">
                  {term.value}
                </div>

                <div className="
                  text-sm
                  text-slate-400
                  leading-relaxed
                ">
                  {term.description}
                </div>

              </div>

            )
          )
        }

      </div>

    </section>

  );

}

// =========================================================
// EQUATION BUBBLE
// =========================================================

function EquationBubble({
  label,
  value,
  color,
}) {

  return (

    <div className="
      flex
      flex-col
      items-center
      gap-3
    ">

      <div className="
        w-24
        h-24
        rounded-3xl
        border
        border-cyan-500/20
        bg-black/30
        flex
        items-center
        justify-center
        shadow-[0_0_25px_rgba(0,255,255,0.05)]
      ">

        <div
          className={`
            text-center
            ${color}
          `}
        >

          <div className="
            text-lg
            uppercase
            tracking-widest
            opacity-60
            mb-1
          ">
            {label}
          </div>

          <div className="
            text-2xl
            font-black
            leading-none
          ">
            {value}
          </div>

        </div>

      </div>

    </div>

  );

}

// =========================================================
// OPERATOR
// =========================================================

function Operator() {

  return (

    <div className="
      text-3xl
      font-black
      text-cyan-300
      mt-[-8px]
    ">
      +
    </div>

  );

}

// =========================================================
// EQUALS
// =========================================================

function Equals() {

  return (

    <div className="
      text-3xl
      font-black
      text-cyan-300
      mt-[-8px]
      px-2
    ">
      =
    </div>

  );

}

// =========================================================
// RESULT
// =========================================================

function ResultBubble({
  riskScore,
  dominantAttack,
}) {

  return (

    <div className="
      flex
      flex-col
      items-center
      gap-3
    ">

      <div className="
        w-36
        h-36
        rounded-[2rem]
        border
        border-red-500/20
        bg-gradient-to-br
        from-red-500/10
        to-cyan-500/10
        flex
        items-center
        justify-center
        shadow-[0_0_40px_rgba(239,68,68,0.15)]
      ">

        <div className="
          text-center
        ">

          <div className="
            text-5xl
            font-black
            text-red-400
            leading-none
          ">
            {Number(
              riskScore || 0
            ).toFixed(0)}
          </div>

          <div className="
            text-xs
            uppercase
            tracking-widest
            text-slate-400
            mt-2
          ">
            {dominantAttack}
          </div>

        </div>

      </div>

      <div className="
        text-xs
        uppercase
        tracking-widest
        text-slate-400
      ">
        Fusion Output
      </div>

    </div>

  );

}

// =========================================================
// SLIDER CONTROL
// =========================================================

function SliderControl({
  label,
  value,
  max,
  onChange,
  disabled,
}) {

  return (

    <div className="
      rounded-xl
      border
      border-white/5
      bg-black/20
      p-4
      transition-all
      duration-300
    ">

      <div className="
        flex
        items-center
        justify-between
        mb-3
      ">

        <div className="
          text-sm
          font-semibold
          text-white
        ">
          {label}
        </div>

        <div className="
          text-cyan-300
          font-black
        ">
          {value.toFixed(2)}
        </div>

      </div>

      <input
        type="range"
        min="0"
        max={max}
        step="0.01"
        value={value}
        disabled={disabled}
        onChange={(e) =>
          onChange(
            Number(
              e.target.value
            )
          )
        }
        className="
          w-full
          accent-cyan-400
          cursor-pointer
          disabled:opacity-40
        "
      />

      <div className="
        mt-3
        text-[11px]
        uppercase
        tracking-wider
        text-slate-500
      ">

        {
          disabled
            ? "Locked to live telemetry"
            : "Simulation override active"
        }

      </div>

    </div>

  );

}