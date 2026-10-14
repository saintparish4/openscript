/**
 * Boot the Python runtime inside the panel and install OpenScript into it.
 *
 * Everything comes from this extension's own files: an unpacked extension may
 * not load remote code, and this one has no reason to. vendor/ is assembled by
 * tools/build_extension.sh from the same pinned Pyodide the demo site loads
 * from jsDelivr, and the same wheels.
 *
 * micropip refuses to download from a chrome-extension:// URL, so the two
 * project wheels are fetched here and handed over through Pyodide's file
 * system. structlog goes first, so the openscript wheel's one requirement is
 * already satisfied and nothing is ever resolved against PyPI.
 */

async function vendorWheel(py, name) {
  const bytes = new Uint8Array(
    await (await fetch(chrome.runtime.getURL(`vendor/${name}`))).arrayBuffer(),
  );
  py.FS.writeFile(`/wheels/${name}`, bytes);
  return `emfs:/wheels/${name}`;
}

/**
 * `browser` is the module agent.py imports its one JS function from: the
 * bodies of the tools, which run only after the firewall has let a call
 * through. `onProgress(phase, message)` is called at each stage of the boot.
 *
 * Returns `run(payload)`, which runs one task and resolves with the result.
 */
export async function boot({ onProgress, browser }) {
  onProgress("runtime", "Starting the Python runtime…");
  const { loadPyodide } = await import("./vendor/pyodide.mjs");
  const py = await loadPyodide({ indexURL: chrome.runtime.getURL("vendor/") });

  onProgress("packages", "Loading pydantic and pyyaml…");
  await py.loadPackage(["micropip", "pydantic", "pyyaml"]);

  onProgress("install", "Installing OpenScript…");
  const manifest = await (await fetch(chrome.runtime.getURL("vendor/manifest.json"))).json();
  py.FS.mkdir("/wheels");
  const structlog = await vendorWheel(py, manifest.structlog);
  const openscript = await vendorWheel(py, manifest.openscript);
  await py.runPythonAsync(`
import micropip
await micropip.install("${structlog}")
await micropip.install("${openscript}")
`);

  onProgress("agent", "Loading the agent and its rules…");
  py.registerJsModule("browser", browser);
  await py.runPythonAsync(await (await fetch(chrome.runtime.getURL("agent.py"))).text());
  const setup = py.globals.get("setup");
  setup(await (await fetch(chrome.runtime.getURL("tools.yaml"))).text());
  const runTask = py.globals.get("run_task");

  return {
    py,
    run: async (payload) => JSON.parse(await runTask(JSON.stringify(payload))),
  };
}
