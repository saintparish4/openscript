"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { EXAMPLES, type Example } from "@/lib/examples";
import { outcomeOf, type Outcome } from "@/lib/outcome";
import { loadRuntime, runPipeline, type Progress } from "@/lib/runtime";
import type { PipelineResult } from "@/lib/types";
import { DemoWindow } from "./demo-window";
import { Play } from "./icons";
import { CrisisNotice, headlineOf, PromptCard, Results } from "./results";

type Status = "booting" | "ready" | "failed";

// Matches the breakpoint in globals.css where the list and the detail pane sit
// side by side. Below it they stack, and a result lands under the list.
const SIDE_BY_SIDE = "(min-width: 55rem)";
// Roughly where the fixed nav ends, in pixels.
const NAV_CLEARANCE = 72;

export default function DemoPanel() {
  const [progress, setProgress] = useState<Progress>({
    phase: "runtime",
    message: "Starting…",
  });
  const [status, setStatus] = useState<Status>("booting");
  const [error, setError] = useState("");
  // Two ids, because they part company for the length of a run: the row is
  // highlighted the moment it is clicked, and the pane keeps what it was
  // showing until the new result exists. Swapping the pane first would shrink
  // the page to an empty state and grow it back a few milliseconds later.
  const [selectedId, setSelectedId] = useState(EXAMPLES[0].id);
  const [shownId, setShownId] = useState(EXAMPLES[0].id);
  const [filter, setFilter] = useState("");
  // Every run so far, by prompt. Walking the list with the arrow keys shows
  // what each one came to without running it again.
  const [results, setResults] = useState<Record<string, PipelineResult>>({});
  // The most recent run, for the things that should happen once per run and
  // not once per look: the crisis notice and bringing the result into view.
  const [latest, setLatest] = useState<PipelineResult | null>(null);
  const [said, setSaid] = useState("");
  const [queuedId, setQueuedId] = useState("");

  // The interpreter, kept across submissions. Re-booting per run would re-fetch
  // several megabytes and take seconds each time.
  const runtime = useRef<Awaited<ReturnType<typeof loadRuntime>> | null>(null);
  const alive = useRef(true);
  const running = useRef(false);
  // A prompt picked while the runtime was still downloading. The boot takes
  // seconds and the list is on screen for all of them, so a click in that
  // window is the common case, not the edge case — it runs when the boot ends.
  const queued = useRef<Example | null>(null);
  const windowRef = useRef<HTMLDivElement | null>(null);
  const detailRef = useRef<HTMLDivElement | null>(null);

  const submit = useCallback(async (example: Example) => {
    // One run at a time. They take milliseconds, so this only ever drops a
    // double click.
    if (running.current) return;
    setSelectedId(example.id);
    const py = runtime.current;
    if (!py) {
      queued.current = example;
      setQueuedId(example.id);
      setShownId(example.id);
      return;
    }
    running.current = true;
    try {
      const result = await runPipeline(py, example.text, example.toolCall ?? null);
      if (!alive.current) return;
      setResults((prev) => ({ ...prev, [example.id]: result }));
      setShownId(example.id);
      setLatest(result);
      const { title, line } = headlineOf(result);
      setSaid(`${example.label}. ${title}. ${line}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : String(err));
      setStatus("failed");
    } finally {
      running.current = false;
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    loadRuntime((p) => alive.current && setProgress(p))
      .then((py) => {
        if (!alive.current) return;
        runtime.current = py;
        setStatus("ready");
        const waiting = queued.current;
        if (waiting) {
          queued.current = null;
          setQueuedId("");
          void submit(waiting);
        }
      })
      .catch((err: unknown) => {
        if (!alive.current) return;
        setError(err instanceof Error ? err.message : String(err));
        setStatus("failed");
      });
    return () => {
      alive.current = false;
    };
  }, [submit]);

  // A new result can land out of sight: under the list on a narrow screen, or
  // above the fold after reading to the bottom of a long one.
  useEffect(() => {
    if (!latest) return;
    const stacked = !window.matchMedia(SIDE_BY_SIDE).matches;
    const target = stacked ? detailRef.current : windowRef.current;
    if (!target) return;
    const top = target.getBoundingClientRect().top;
    // Already near the top of the screen and clear of the nav: leave it be.
    if (top >= NAV_CLEARANCE && top <= window.innerHeight * 0.4) return;
    const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    target.scrollIntoView({ block: "start", behavior: calm ? "auto" : "smooth" });
  }, [latest]);

  const preview = useCallback((example: Example) => {
    setSelectedId(example.id);
    setShownId(example.id);
  }, []);

  const pickFilter = useCallback(
    (name: string) => {
      setFilter(name);
      // Keep the selection on something that is still in the list.
      const listed = name ? EXAMPLES.filter((ex) => ex.persona.name === name) : EXAMPLES;
      if (!listed.some((ex) => ex.id === selectedId)) preview(listed[0]);
    },
    [selectedId, preview],
  );

  if (status === "failed") {
    return (
      <div className="window window--error" role="alert">
        <div className="window__error">
          <h2>The demo could not start</h2>
          <p>{error}</p>
          <p className="muted">
            It needs a browser with WebAssembly and access to the jsDelivr CDN. Nothing is sent
            anywhere either way.
          </p>
        </div>
      </div>
    );
  }

  const shown = EXAMPLES.find((ex) => ex.id === shownId) ?? EXAMPLES[0];
  const result = results[shown.id];
  const booting = status === "booting";

  const outcomes: Record<string, Outcome> = {};
  for (const [id, r] of Object.entries(results)) outcomes[id] = outcomeOf(r);

  const footer = booting
    ? progress.message
    : result
      ? `Ran locally in ${result.latency_ms.toFixed(1)} ms`
      : "Runtime ready";

  return (
    <>
      <DemoWindow
        selectedId={selectedId}
        filter={filter}
        outcomes={outcomes}
        status={footer}
        onRun={(ex) => void submit(ex)}
        onPreview={preview}
        onFilter={pickFilter}
        windowRef={windowRef}
        detailRef={detailRef}
      >
        {result ? (
          <Results key={shown.id} result={result} example={shown} />
        ) : (
          <div className="preview">
            <PromptCard example={shown} />

            <div className="preview__run">
              {booting ? (
                <div className="boot">
                  <div className="boot__bar">
                    <span className={`boot__fill boot__fill--${progress.phase}`} />
                  </div>
                  <p className="boot__msg">{progress.message}</p>
                  <p className="muted">
                    First load pulls about 7 MB of Python runtime. It is cached after that.
                  </p>
                </div>
              ) : null}

              <button type="button" className="btn" onClick={() => void submit(shown)}>
                <Play size={14} />
                Run it through the pipeline
              </button>
              <p className="muted">
                {queuedId === shown.id
                  ? "Queued. It runs as soon as the runtime is ready."
                  : booting
                    ? "Pick one now and it runs as soon as the runtime is ready."
                    : "Not run yet. Every prompt in the list goes through the same pipeline."}
              </p>
            </div>
          </div>
        )}
      </DemoWindow>

      {/* One live region for the whole demo, and one that is always mounted:
          a region that arrives already holding its text is often not read out.
          It speaks for runs and for the boot, not for every move through the
          list — the row's own label covers that. */}
      <p className="sr-only" role="status">
        {booting ? progress.message : said}
      </p>

      {/* Outside the live region on purpose: a modal announced by a live
          region and then focused is announced twice. */}
      {latest ? <CrisisNotice result={latest} /> : null}
    </>
  );
}
