/**
 * Phase 1 gate: prove the real OpenScript wheel installs and runs under Pyodide
 * using the SAME mechanism the browser page uses (micropip fetching wheels over
 * HTTP), not an Emscripten-FS shortcut.
 *
 *   node web/probe.mjs
 *
 * Exit 0 = Phase 1 criterion 2 is met. Exit non-zero = it is not.
 */
import { loadPyodide } from "pyodide";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WHEELS = path.join(HERE, "wheels");

const wheelFiles = fs.existsSync(WHEELS)
  ? fs.readdirSync(WHEELS).filter((f) => f.endsWith(".whl"))
  : [];
const openscript = wheelFiles.find((f) => f.startsWith("openscript-"));
const structlog = wheelFiles.find((f) => f.startsWith("structlog-"));
if (!openscript || !structlog) {
  console.error(`missing wheels in ${WHEELS}: run \`make browser-wheels\` first`);
  process.exit(1);
}

// Serve web/wheels the way the demo's static host will.
const server = http.createServer((req, res) => {
  const file = path.join(WHEELS, path.basename(decodeURIComponent(req.url)));
  if (!fs.existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "Content-Type": "application/octet-stream" });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const fail = (msg) => { console.error("FAIL: " + msg); server.close(); process.exit(1); };
const t0 = Date.now();

const py = await loadPyodide();
await py.loadPackage(["micropip", "pydantic", "pyyaml"]);

const env = await py.runPythonAsync(`
import sys, pydantic, yaml
{"python": sys.version.split()[0], "pydantic": pydantic.VERSION, "pyyaml": yaml.__version__}
`);
console.log("pyodide env:", JSON.stringify(Object.fromEntries(env.toJs())));
env.destroy();

try {
  // structlog first so the openscript wheel's requirement is already satisfied
  // and micropip never has to reach PyPI at runtime.
  await py.runPythonAsync(`
import micropip
await micropip.install("${base}/${structlog}")
await micropip.install("${base}/${openscript}")
`);
} catch (e) {
  fail("micropip could not install the wheel:\n" + String(e).split("\n").slice(-6).join("\n"));
}
console.log(`install OK (${((Date.now() - t0) / 1000).toFixed(1)}s)`);

let report;
try {
  report = JSON.parse(await py.runPythonAsync(fs.readFileSync(path.join(HERE, "smoke.py"), "utf8")));
} catch (e) {
  fail("policy smoke test raised:\n" + String(e).split("\n").slice(-12).join("\n"));
}

server.close();
console.log(JSON.stringify(report, null, 2));

const bad = Object.entries(report).filter(([, v]) => v && v.ok === false);
if (bad.length) {
  console.error("\nFAILED CHECKS: " + bad.map(([k, v]) => `${k} (${v.detail})`).join(", "));
  process.exit(1);
}
console.log("\nPHASE 1 GATE: PASS — all 8 policies ran in Pyodide.");
