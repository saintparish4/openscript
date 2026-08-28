import type { PipelineResult, ToolCall } from "./types";

// Pinned deliberately: this version decides which pydantic and pyyaml the
// browser gets, which is what the dependency floors in pyproject.toml are
// matched against. Bumping it can invalidate them.
const PYODIDE_VERSION = "0.28.3";
const CDN = `https://cdn.jsdelivr.net/pyodide/v${PYODIDE_VERSION}/full/`;

export type Phase = "runtime" | "packages" | "install" | "pipeline" | "ready";

export interface Progress {
  phase: Phase;
  message: string;
}

interface PyodideApi {
  loadPackage(names: string[]): Promise<void>;
  runPythonAsync(code: string): Promise<unknown>;
  globals: { get(name: string): ((arg: string) => Promise<string>) | undefined };
}

let bootPromise: Promise<PyodideApi> | null = null;

/**
 * Boot the interpreter and install the package. Idempotent: the first caller
 * starts the download, everyone after gets the same promise. Re-booting per
 * submission would re-fetch ~7 MB and cost several seconds each time.
 */
export function loadRuntime(onProgress: (p: Progress) => void): Promise<PyodideApi> {
  if (bootPromise) return bootPromise;

  bootPromise = (async () => {
    onProgress({ phase: "runtime", message: "Downloading the Python runtime (~5 MB)…" });
    const { loadPyodide } = (await import(/* webpackIgnore: true */ `${CDN}pyodide.mjs`)) as {
      loadPyodide: (opts: { indexURL: string }) => Promise<PyodideApi>;
    };
    const py = await loadPyodide({ indexURL: CDN });

    onProgress({ phase: "packages", message: "Loading pydantic and pyyaml…" });
    await py.loadPackage(["micropip", "pydantic", "pyyaml"]);

    onProgress({ phase: "install", message: "Installing the OpenScript package…" });
    const wheels: Record<string, string> = await (await fetch("./wheels/manifest.json")).json();
    // structlog first: with the requirement already satisfied locally, micropip
    // never resolves against PyPI, so nothing is fetched from a third party.
    await py.runPythonAsync(`
import micropip
await micropip.install("${wheels.structlog}")
await micropip.install("${wheels.openscript}")
`);

    onProgress({ phase: "pipeline", message: "Compiling the policy pipeline…" });
    const source = await (await fetch("./pipeline.py")).text();
    await py.runPythonAsync(source);

    onProgress({ phase: "ready", message: "Ready" });
    return py;
  })();

  bootPromise.catch(() => {
    // Let a later attempt retry from scratch rather than replaying the failure.
    bootPromise = null;
  });

  return bootPromise;
}

export async function runPipeline(
  py: PyodideApi,
  text: string,
  toolCall: ToolCall | null = null,
): Promise<PipelineResult> {
  const run = py.globals.get("run_pipeline");
  if (!run) throw new Error("the pipeline module did not define run_pipeline");
  return JSON.parse(await run(JSON.stringify({ text, tool_call: toolCall })));
}
