"use client";

import dynamic from "next/dynamic";
import { useEffect, useRef, useState } from "react";

// ssr:false is load-bearing, not a preference: the panel boots a WebAssembly
// interpreter and touches browser globals that do not exist during a build.
const DemoPanel = dynamic(() => import("./demo-panel"), {
  ssr: false,
  loading: () => <div className="panel panel--placeholder">Loading the demo…</div>,
});

/**
 * Holds the ~7 MB runtime download until the demo is actually on screen, so
 * landing on the page costs nothing. Falls back to a button where
 * IntersectionObserver is unavailable.
 */
export function DemoSection() {
  const [armed, setArmed] = useState(false);
  const anchor = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const node = anchor.current;
    if (!node || typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setArmed(true);
          observer.disconnect();
        }
      },
      { rootMargin: "200px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <div ref={anchor} className="demo-section">
      {armed ? (
        <DemoPanel />
      ) : (
        <div className="panel panel--idle">
          <button type="button" className="load" onClick={() => setArmed(true)}>
            Load the demo
          </button>
          <p className="muted">
            Downloads a Python runtime and the OpenScript package into this tab. Roughly 7 MB,
            once.
          </p>
        </div>
      )}
    </div>
  );
}
