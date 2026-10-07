"use client";

import dynamic from "next/dynamic";
import { useEffect, useRef, useState } from "react";
import { EXAMPLES } from "@/lib/examples";
import { DemoWindow } from "./demo-window";
import { PromptCard } from "./results";

/**
 * The window before the panel is live: the same frame and the same gallery,
 * with nothing wired up. It is what the static export contains, so the page
 * has its list on first paint and the live panel swaps in without a jump.
 */
function Shell({ status, children }: { status: string; children: React.ReactNode }) {
  return (
    <DemoWindow selectedId={EXAMPLES[0].id} status={status}>
      <div className="preview">
        <PromptCard example={EXAMPLES[0]} />
        <div className="preview__run">{children}</div>
      </div>
    </DemoWindow>
  );
}

// ssr:false is load-bearing, not a preference: the panel boots a WebAssembly
// interpreter and touches browser globals that do not exist during a build.
const DemoPanel = dynamic(() => import("./demo-panel"), {
  ssr: false,
  loading: () => (
    <Shell status="Loading the demo…">
      <p className="muted">Loading the demo…</p>
    </Shell>
  ),
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
        <Shell status="Not loaded yet">
          <button type="button" className="btn" onClick={() => setArmed(true)}>
            Load the demo
          </button>
          <p className="muted">
            Downloads a Python runtime and the OpenScript package into this tab. Roughly 7 MB,
            once.
          </p>
        </Shell>
      )}
    </div>
  );
}
