"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { EXAMPLES, type Example } from "@/lib/examples";
import { loadRuntime, runPipeline, type Progress } from "@/lib/runtime";
import type { PipelineResult } from "@/lib/types";
import { DiffView } from "./diff-view";
import { VerdictRow } from "./verdict-row";

type Status = "booting" | "ready" | "running" | "failed";

export default function DemoPanel() {
  const [progress, setProgress] = useState<Progress>({
    phase: "runtime",
    message: "Starting…",
  });
  const [status, setStatus] = useState<Status>("booting");
  const [error, setError] = useState("");
  const [text, setText] = useState("");
  const [result, setResult] = useState<PipelineResult | null>(null);
  const [activeId, setActiveId] = useState("");

  // The interpreter, kept across submissions. Re-booting per run would re-fetch
  // several megabytes and take seconds each time.
  const runtime = useRef<Awaited<ReturnType<typeof loadRuntime>> | null>(null);
  const alive = useRef(true);

  useEffect(() => {
    alive.current = true;
    loadRuntime((p) => alive.current && setProgress(p))
      .then((py) => {
        if (!alive.current) return;
        runtime.current = py;
        setStatus("ready");
      })
      .catch((err: unknown) => {
        if (!alive.current) return;
        setError(err instanceof Error ? err.message : String(err));
        setStatus("failed");
      });
    return () => {
      alive.current = false;
    };
  }, []);

  const submit = useCallback(
    async (example: Example | null, value: string) => {
      const py = runtime.current;
      if (!py || !value.trim()) return;
      setStatus("running");
      setActiveId(example?.id ?? "");
      setText(value);
      try {
        setResult(await runPipeline(py, value, example?.toolCall ?? null));
      } catch (err: unknown) {
        setError(err instanceof Error ? err.message : String(err));
        setStatus("failed");
        return;
      }
      setStatus("ready");
    },
    [],
  );

  if (status === "failed") {
    return (
      <div className="panel panel--error" role="alert">
        <h3>The demo could not start</h3>
        <p>{error}</p>
        <p className="muted">
          It needs a browser with WebAssembly and access to the jsDelivr CDN. Nothing is sent
          anywhere either way.
        </p>
      </div>
    );
  }

  const busy = status === "booting" || status === "running";

  return (
    <div className="panel">
      {status === "booting" ? (
        <div className="boot" aria-live="polite">
          <div className="boot__bar">
            <span className={`boot__fill boot__fill--${progress.phase}`} />
          </div>
          <p className="boot__msg">{progress.message}</p>
          <p className="muted">
            First load pulls about 7 MB of Python runtime. It is cached after that.
          </p>
        </div>
      ) : null}

      <fieldset className="chips" disabled={busy}>
        <legend>Try one of these</legend>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.id}
            type="button"
            className={`chip${activeId === ex.id ? " chip--active" : ""}`}
            onClick={() => void submit(ex, ex.text)}
          >
            <span className="chip__label">{ex.label}</span>
            <span className="chip__teaser">{ex.teaser}</span>
          </button>
        ))}
      </fieldset>

      <form
        className="compose"
        onSubmit={(e) => {
          e.preventDefault();
          void submit(null, text);
        }}
      >
        <label htmlFor="prompt">Or write your own</label>
        <textarea
          id="prompt"
          rows={3}
          value={text}
          placeholder="Type anything — an adversarial prompt, a secret, a normal question."
          onChange={(e) => setText(e.target.value)}
          disabled={busy}
        />
        <div className="compose__foot">
          <p className="privacy">
            Your text never leaves this browser. There is no server to send it to — open the
            network tab and watch.
          </p>
          <button type="submit" disabled={busy || !text.trim()}>
            {status === "running" ? "Running…" : "Run the pipeline"}
          </button>
        </div>
      </form>

      {result ? <Results result={result} /> : null}
    </div>
  );
}

/**
 * A response can come back three ways: untouched, rewritten, or intact but with
 * a finding recorded. Collapsing the third into "nothing fired" would hide the
 * policy that did the noticing.
 */
function returnedLine(result: PipelineResult): string {
  if (result.raw_output !== result.output) {
    return "The response came back, rewritten to remove what the policies found.";
  }
  const flagged = result.rows.filter((r) => r.verdict === "flag" || r.verdict === "approval");
  if (flagged.length) {
    return `The response came back unchanged, but ${flagged
      .map((r) => r.policy)
      .join(" and ")} recorded a finding.`;
  }
  return "Nothing fired. The response came back untouched.";
}

function Results({ result }: { result: PipelineResult }) {
  const blockLine =
    result.stage === "tool"
      ? `The reply was returned, but the tool call was refused by the ${result.blocked_by} policy.`
      : result.stage === "response"
        ? `The model replied, but the ${result.blocked_by} policy stopped the response from being returned.`
        : `The ${result.blocked_by} policy stopped this before the model ever saw it.`;

  return (
    <section className="results" aria-live="polite">
      <p className="results__local">
        Every check below ran locally in your browser, in {result.latency_ms.toFixed(1)} ms.
      </p>

      {result.blocked ? (
        <div className="outcome outcome--deny">
          <strong>Blocked</strong>
          <p>{blockLine}</p>
          <p className="outcome__reason">{result.blocked_reason}</p>
        </div>
      ) : (
        <div className="outcome outcome--allow">
          <strong>Returned</strong>
          <p>{returnedLine(result)}</p>
        </div>
      )}

      <DiffView before={result.raw_output} after={result.output} />

      <ol className="verdicts">
        {result.rows.map((row) => (
          <VerdictRow key={row.key} row={row} />
        ))}
      </ol>

      <dl className="totals">
        <div>
          <dt>Combined risk</dt>
          <dd>{result.risk.toFixed(2)}</dd>
        </div>
        <div>
          <dt>Pipeline time</dt>
          <dd>{result.latency_ms.toFixed(1)} ms</dd>
        </div>
        <div>
          <dt>Audit events</dt>
          <dd>{result.events}</dd>
        </div>
      </dl>
    </section>
  );
}
