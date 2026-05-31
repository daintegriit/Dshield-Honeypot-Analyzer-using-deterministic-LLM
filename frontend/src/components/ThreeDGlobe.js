import React, {
  useRef,
  useEffect
} from "react";

import * as THREE from "three";

import { OrbitControls }
from "three/examples/jsm/controls/OrbitControls";

import {
  useTelemetry
} from "../context/TelemetryContext";

const ThreeDGlobe = () => {

  // ====================================================
  // TELEMETRY CONTEXT
  // ====================================================

  const {

    geo: attackData,

    loading,

    stale,

    backendHealthy,

    latency,

    lastUpdated

  } = useTelemetry();

  // ====================================================
  // REFS
  // ====================================================

  const containerRef =
    useRef(null);

  const rendererRef =
    useRef(null);

  const cameraRef =
    useRef(null);

  const globeRef =
    useRef(null);

  const globeGroupRef =
    useRef(null);

  const attackObjectsRef =
    useRef([]);

  const animationFrameRef =
    useRef(null);

  // ====================================================
  // THREE INIT
  // ====================================================

  useEffect(() => {

    if (!containerRef.current)
      return;

    const container =
      containerRef.current;

    // --------------------------------------------------
    // SCENE
    // --------------------------------------------------

    const scene =
      new THREE.Scene();

    scene.fog =
      new THREE.Fog(
        0x020617,
        25,
        60
      );

    // --------------------------------------------------
    // CAMERA
    // --------------------------------------------------

    const camera =
      new THREE.PerspectiveCamera(
        55,
        1,
        0.1,
        1000
      );

    camera.position.z =
      16;

    cameraRef.current =
      camera;

    // --------------------------------------------------
    // RENDERER
    // --------------------------------------------------

    const renderer =
      new THREE.WebGLRenderer({

        antialias: true,

        alpha: true,

        powerPreference:
          "high-performance",
      });

    renderer.setPixelRatio(
      Math.min(
        window.devicePixelRatio,
        2
      )
    );

    renderer.outputColorSpace =
      THREE.SRGBColorSpace;

    rendererRef.current =
      renderer;

    container.appendChild(
      renderer.domElement
    );

    // --------------------------------------------------
    // GLOBE GROUP
    // --------------------------------------------------

    const globeGroup =
      new THREE.Group();

    globeGroupRef.current =
      globeGroup;

    scene.add(globeGroup);

    // --------------------------------------------------
    // GLOBE
    // --------------------------------------------------

    const globe =
      new THREE.Mesh(

        new THREE.SphereGeometry(
          7,
          64,
          64
        ),

        new THREE.MeshStandardMaterial({

          color:
            0x071426,

          emissive:
            0x0ea5e9,

          emissiveIntensity:
            0.08,

          transparent: true,

          opacity: 0.95,

          metalness: 0.2,

          roughness: 0.78,
        })
      );

    globeRef.current =
      globe;

    globeGroup.add(
      globe
    );

    // --------------------------------------------------
    // OUTER GLOW
    // --------------------------------------------------

    const outerGlow =
      new THREE.Mesh(

        new THREE.SphereGeometry(
          7.25,
          64,
          64
        ),

        new THREE.MeshBasicMaterial({

          color:
            stale
              ? 0xf59e0b
              : backendHealthy
              ? 0x00bfff
              : 0xff1744,

          transparent: true,

          opacity: 0.08,

          side:
            THREE.BackSide,
        })
      );

    globeGroup.add(
      outerGlow
    );

    // --------------------------------------------------
    // WIREFRAME
    // --------------------------------------------------

    const wireframe =
      new THREE.LineSegments(

        new THREE.WireframeGeometry(

          new THREE.SphereGeometry(
            7.03,
            32,
            32
          )
        ),

        new THREE.LineBasicMaterial({

          color:
            0x00bfff,

          transparent: true,

          opacity: 0.32,
        })
      );

    globeGroup.add(
      wireframe
    );

    // --------------------------------------------------
    // STARFIELD
    // --------------------------------------------------

    const starsGeometry =
      new THREE.BufferGeometry();

    const starVertices =
      [];

    for (
      let i = 0;
      i < 2500;
      i++
    ) {

      const x =
        (Math.random() - 0.5) *
        2000;

      const y =
        (Math.random() - 0.5) *
        2000;

      const z =
        (Math.random() - 0.5) *
        2000;

      starVertices.push(
        x,
        y,
        z
      );
    }

    starsGeometry.setAttribute(
      "position",
      new THREE.Float32BufferAttribute(
        starVertices,
        3
      )
    );

    const starsMaterial =
      new THREE.PointsMaterial({

        color:
          0x94a3b8,

        size:
          0.7,

        transparent: true,

        opacity:
          0.6,
      });

    const starField =
      new THREE.Points(
        starsGeometry,
        starsMaterial
      );

    scene.add(
      starField
    );

    // --------------------------------------------------
    // LIGHTING
    // --------------------------------------------------

    const pointLight =
      new THREE.PointLight(
        0xffffff,
        2.4
      );

    pointLight.position.set(
      10,
      10,
      10
    );

    scene.add(
      pointLight
    );

    const pointLight2 =
      new THREE.PointLight(
        0x00bfff,
        1.5
      );

    pointLight2.position.set(
      -10,
      -5,
      -10
    );

    scene.add(
      pointLight2
    );

    const ambient =
      new THREE.AmbientLight(
        0xffffff,
        0.42
      );

    scene.add(
      ambient
    );

    // --------------------------------------------------
    // CONTROLS
    // --------------------------------------------------

    const controls =
      new OrbitControls(
        camera,
        renderer.domElement
      );

    controls.enableZoom =
      true;

    controls.enablePan =
      false;

    controls.autoRotate =
      true;

    controls.autoRotateSpeed =
      0.42;

    controls.enableDamping =
      true;

    controls.dampingFactor =
      0.045;

    controls.minDistance =
      10;

    controls.maxDistance =
      28;

    // --------------------------------------------------
    // RESIZE
    // --------------------------------------------------

    const resize = () => {

      if (!container)
        return;

      const width =
        container.clientWidth;

      const height =
        container.clientHeight;

      renderer.setSize(
        width,
        height
      );

      camera.aspect =
        width / height;

      camera.updateProjectionMatrix();
    };

    const observer =
      new ResizeObserver(
        resize
      );

    observer.observe(
      container
    );

    resize();

    // --------------------------------------------------
    // ANIMATION LOOP
    // --------------------------------------------------

    const animate =
      () => {

        animationFrameRef.current =
          requestAnimationFrame(
            animate
          );

        // ----------------------------------------------
        // ROTATION
        // ----------------------------------------------

        globeGroup.rotation.y +=
          0.0011;

        wireframe.rotation.y +=
          0.0005;

        starField.rotation.y +=
          0.00008;

        // ----------------------------------------------
        // PULSE RINGS
        // ----------------------------------------------

        attackObjectsRef.current
          .forEach((obj) => {

            if (
              obj.userData.isPulse
            ) {

              obj.scale.x +=
                0.012;

              obj.scale.y +=
                0.012;

              obj.material.opacity -=
                0.008;

              if (
                obj.material.opacity <= 0
              ) {

                obj.scale.set(
                  1,
                  1,
                  1
                );

                obj.material.opacity =
                  0.65;
              }
            }

            // ------------------------------------------
            // FLOATING EFFECT
            // ------------------------------------------

            if (
              obj.userData.floatSeed
            ) {

              obj.position.multiplyScalar(
                1
              );
            }
          });

        // ----------------------------------------------
        // SOC CORE COLOR
        // ----------------------------------------------

        outerGlow.material.color
          .set(

            stale
              ? 0xf59e0b
              : backendHealthy
              ? 0x00bfff
              : 0xff1744
          );

        controls.update();

        renderer.render(
          scene,
          camera
        );
      };

    animate();

    // --------------------------------------------------
    // CLEANUP
    // --------------------------------------------------

    return () => {

      observer.disconnect();

      controls.dispose();

      cancelAnimationFrame(
        animationFrameRef.current
      );

      renderer.dispose();

      renderer.forceContextLoss();

      scene.clear();

      if (
        container.contains(
          renderer.domElement
        )
      ) {

        container.removeChild(
          renderer.domElement
        );
      }
    };

  }, [
    stale,
    backendHealthy
  ]);

  // ====================================================
  // LIVE ATTACK POINTS
  // ====================================================

  useEffect(() => {

    const globe =
      globeRef.current;

    if (!globe)
      return;

    // --------------------------------------------------
    // REMOVE OLD OBJECTS
    // --------------------------------------------------

    attackObjectsRef.current
      .forEach((o) => {

        globe.remove(o);

        if (
          o.geometry
        ) {
          o.geometry.dispose();
        }

        if (
          o.material
        ) {
          o.material.dispose();
        }
      });

    attackObjectsRef.current =
      [];

    // --------------------------------------------------
    // LAT/LON → XYZ
    // --------------------------------------------------

    const latLonToVector3 =
      (
        lat,
        lon,
        radius
      ) => {

        const phi =
          (90 - lat) *
          (Math.PI / 180);

        const theta =
          (lon + 180) *
          (Math.PI / 180);

        const x =
          -(
            radius *
            Math.sin(phi) *
            Math.cos(theta)
          );

        const z =
          radius *
          Math.sin(phi) *
          Math.sin(theta);

        const y =
          radius *
          Math.cos(phi);

        return new THREE.Vector3(
          x,
          y,
          z
        );
      };

    // --------------------------------------------------
    // CREATE ATTACK OBJECTS
    // --------------------------------------------------

    attackData.forEach(
      (attack) => {

        const lat =
          Number(
            attack.latitude
          );

        const lon =
          Number(
            attack.longitude
          );

        if (
          Number.isNaN(lat) ||
          Number.isNaN(lon)
        ) {
          return;
        }

        const count =
          Number(
            attack.count || 1
          );

        // ----------------------------------------------
        // COLOR
        // ----------------------------------------------

        let color =
          0x4fc3f7;

        if (count > 5000)
          color =
            0xff1744;
        else if (
          count > 1000
        )
          color =
            0xff9100;
        else if (
          count > 100
        )
          color =
            0xffd600;

        // ----------------------------------------------
        // SIZE
        // ----------------------------------------------

        let markerSize =
          0.11;

        if (count > 5000)
          markerSize =
            0.22;
        else if (
          count > 1000
        )
          markerSize =
            0.18;
        else if (
          count > 100
        )
          markerSize =
            0.14;

        // ----------------------------------------------
        // POSITION
        // ----------------------------------------------

        const pos =
          latLonToVector3(
            lat,
            lon,
            7.25
          );

        // ----------------------------------------------
        // MARKER
        // ----------------------------------------------

        const marker =
          new THREE.Mesh(

            new THREE.SphereGeometry(
              markerSize,
              12,
              12
            ),

            new THREE.MeshBasicMaterial({

              color,
            })
          );

        marker.position.copy(
          pos
        );

        // ----------------------------------------------
        // PULSE RING
        // ----------------------------------------------

        const ring =
          new THREE.Mesh(

            new THREE.RingGeometry(
              markerSize * 1.2,
              markerSize * 2,
              32
            ),

            new THREE.MeshBasicMaterial({

              color,

              transparent: true,

              opacity: 0.65,

              side:
                THREE.DoubleSide,
            })
          );

        ring.position.copy(
          pos );

        ring.lookAt(
          new THREE.Vector3(
            0,
            0,
            0
          )
        );

        ring.userData.isPulse =
          true;

        // ----------------------------------------------
        // GLOW
        // ----------------------------------------------

        const glow =
          new THREE.Mesh(

            new THREE.SphereGeometry(
              markerSize * 1.8,
              10,
              10
            ),

            new THREE.MeshBasicMaterial({

              color,

              transparent: true,

              opacity: 0.15,
            })
          );

        glow.position.copy(
          pos
        );

        // ----------------------------------------------
        // ADD TO GLOBE
        // ----------------------------------------------

        globe.add(
          marker
        );

        globe.add(
          ring
        );

        globe.add(
          glow
        );

        // ----------------------------------------------
        // TRACK
        // ----------------------------------------------

        attackObjectsRef.current.push(
          marker
        );

        attackObjectsRef.current.push(
          ring
        );

        attackObjectsRef.current.push(
          glow
        );
      }
    );

  }, [attackData]);

  // ====================================================
  // STATUS
  // ====================================================

  let status =
    "SOC ONLINE";

  let statusColor =
    "text-green-400";

  if (!backendHealthy) {

    status =
      "BACKEND OFFLINE";

    statusColor =
      "text-red-400";

  } else if (stale) {

    status =
      "TELEMETRY STALE";

    statusColor =
      "text-yellow-400";
  }

  // ====================================================
  // UI
  // ====================================================

  return (

    <div className="
      relative
      w-full
      h-full
      min-h-0
      flex
      items-center
      justify-center
      overflow-hidden
    ">

      {/* ------------------------------------------ */}
      {/* THREE CONTAINER */}
      {/* ------------------------------------------ */}

      <div
        ref={containerRef}
        className="
          w-full
          h-full
          min-h-0
        "
      />

      {/* ------------------------------------------ */}
      {/* LOADING */}
      {/* ------------------------------------------ */}

      {loading && (

        <div className="
          absolute
          inset-0
          flex
          items-center
          justify-center
          bg-black/30
          backdrop-blur-sm
          pointer-events-none
        ">

          <p className="
            text-cyan-300
            text-sm
            font-semibold
            animate-pulse
            tracking-wide
          ">

            Initializing telemetry engine...

          </p>
        </div>
      )}

      {/* ------------------------------------------ */}
      {/* EMPTY */}
      {/* ------------------------------------------ */}

      {!loading &&
        attackData.length === 0 && (

        <div className="
          absolute
          inset-0
          flex
          items-center
          justify-center
          bg-black/20
          pointer-events-none
        ">

          <p className="
            text-slate-400
            text-sm
            font-medium
          ">

            Waiting for live geolocation telemetry...

          </p>
        </div>
      )}

      {/* ------------------------------------------ */}
      {/* LIVE COUNTER */}
      {/* ------------------------------------------ */}

      <div className="
        absolute
        bottom-2
        left-2
        bg-black/40
        backdrop-blur-md
        border
        border-cyan-500/20
        rounded-md
        px-2
        py-1
        text-[10px]
        text-cyan-300
        font-mono
      ">

        LIVE GEO EVENTS:
        {" "}
        {attackData.length}

      </div>

      {/* ------------------------------------------ */}
      {/* STATUS */}
      {/* ------------------------------------------ */}

      <div className={`
        absolute
        top-2
        right-2
        bg-black/40
        backdrop-blur-md
        border
        rounded-md
        px-2
        py-1
        text-[10px]
        font-mono
        border-white/10
        ${statusColor}
      `}>

        {status}

      </div>

      {/* ------------------------------------------ */}
      {/* LATENCY */}
      {/* ------------------------------------------ */}

      <div className="
        absolute
        top-10
        right-2
        bg-black/30
        backdrop-blur-md
        border
        border-white/10
        rounded-md
        px-2
        py-1
        text-[10px]
        text-slate-300
        font-mono
      ">

        LATENCY:
        {" "}
        {latency}ms

      </div>

      {/* ------------------------------------------ */}
      {/* LAST UPDATE */}
      {/* ------------------------------------------ */}

      {lastUpdated && (

        <div className="
          absolute
          top-[72px]
          right-2
          bg-black/20
          backdrop-blur-md
          border
          border-white/10
          rounded-md
          px-2
          py-1
          text-[9px]
          text-slate-400
          font-mono
        ">

          {new Date(
            lastUpdated
          ).toLocaleTimeString()}

        </div>
      )}

    </div>
  );
};

export default ThreeDGlobe;