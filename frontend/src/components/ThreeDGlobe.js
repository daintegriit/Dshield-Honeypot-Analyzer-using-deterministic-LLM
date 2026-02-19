import React, { useRef, useEffect, useState } from "react";
import * as THREE from "three";
import { OrbitControls } from "three/examples/jsm/controls/OrbitControls";

const ThreeDGlobe = () => {
  const containerRef = useRef(null);
  const [attackData, setAttackData] = useState([]); 
  
  useEffect(() => {
    if (!containerRef.current) return;

    const width = containerRef.current.clientWidth;
    const height = containerRef.current.clientHeight;

    // Scene
    const scene = new THREE.Scene();

    // Camera (container-aware)
    const camera = new THREE.PerspectiveCamera(75, width / height, 0.1, 1000);
    camera.position.z = 12;

    // Renderer
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(window.devicePixelRatio);
    containerRef.current.appendChild(renderer.domElement);

    // Globe
    const sphereGeometry = new THREE.SphereGeometry(7, 64, 64);
    const sphereMaterial = new THREE.MeshStandardMaterial({
      color: 0x000020,
      transparent: true,
      opacity: 0.9,
    });
    const globe = new THREE.Mesh(sphereGeometry, sphereMaterial);
    scene.add(globe);

    // Wireframe overlay
    const wireframeGeometry = new THREE.SphereGeometry(7.05, 32, 32);
    const wireframeMaterial = new THREE.LineBasicMaterial({
      color: 0x0077be,
      linewidth: 2,
    });
    const wireframe = new THREE.LineSegments(
      new THREE.WireframeGeometry(wireframeGeometry),
      wireframeMaterial
    );
    scene.add(wireframe);

    // Lighting
    const light = new THREE.PointLight(0xffffff, 1.5);
    light.position.set(10, 10, 10);
    scene.add(light);

    // Controls
    const controls = new OrbitControls(camera, renderer.domElement);
    controls.enableZoom = true;
    controls.enablePan = true;
    controls.enableRotate = true;

    // Attack markers (unchanged)
    const addAttackMarkers = () => {
      attackData.forEach((attack) => {
        const markerGeometry = new THREE.SphereGeometry(0.2, 16, 16);
        const markerMaterial = new THREE.MeshBasicMaterial({ color: 0xff0000 });
        const marker = new THREE.Mesh(markerGeometry, markerMaterial);

        const lat = attack.lat || 0;
        const lon = attack.lon || 0;
        const phi = (90 - lat) * (Math.PI / 180);
        const theta = (lon + 180) * (Math.PI / 180);
        const radius = 7.1;

        marker.position.set(
          radius * Math.sin(phi) * Math.cos(theta),
          radius * Math.cos(phi),
          radius * Math.sin(phi) * Math.sin(theta)
        );

        scene.add(marker);
      });
    };

    if (attackData.length > 0) addAttackMarkers();

    // Animation loop
    const animate = () => {
      requestAnimationFrame(animate);
      globe.rotation.y += 0.001;
      wireframe.rotation.y += 0.001;
      controls.update();
      renderer.render(scene, camera);
    };
    animate();

    // Cleanup
    return () => {
      renderer.dispose();
      containerRef.current.removeChild(renderer.domElement);
    };
  }, [attackData]);

  return (
    <div className="relative w-full h-full flex items-center justify-center">
      
      {/* Container-aware globe */}
      <div
        ref={containerRef}
        className="w-full h-full flex items-center justify-center"
      />

      {/* Overlay (centered relative to globe container) */}
      {attackData.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center text-white text-lg bg-black bg-opacity-30 rounded-lg pointer-events-none">
          <p className="text-red-400 font-bold text-lg text-center animate-pulse">
            🌍 No attack data available yet.
          </p>
        </div>
      )}
    </div>
  );
};

export default ThreeDGlobe;