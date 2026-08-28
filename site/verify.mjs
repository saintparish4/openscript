/**
 * End-to-end check of the exported demo: boot the interpreter, install the
 * wheels the page ships, load the page's own pipeline module, and run every
 * gallery example through it.
 *
 *   npm run build && npm run verify
 *
 * This is the same install path the browser takes — wheels fetched over HTTP
 * from the exported directory, not read off the filesystem — so a broken
 * manifest, a missing wheel or a stale pipeline.py fails here rather than in
 * front of a visitor.
 */
import { loadPyodide } from "pyodide";
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(HERE, "out");
const EXAMPLES = JSON.parse(fs.readFileSync(path.join(HERE, "lib/examples.json"), "utf8"));

if (!fs.existsSync(path.join(OUT, "pipeline.py"))) {
  console.error(`no export found in ${OUT} — run \`npm run build\` first`);
  process.exit(1);
}

// public/ is copied into the export verbatim, so anything left lying around in
// it ships to every visitor. Running pipeline.py locally leaves a __pycache__
// behind, and a stale .pyc next to the real source is worth failing over.
if (fs.existsSync(path.join(OUT, "__pycache__"))) {
  console.error("the export contains __pycache__ — remove site/public/__pycache__ and rebuild");
  process.exit(1);
}

const TYPES = { ".whl": "application/octet-stream", ".json": "application/json", ".py": "text/plain" };
const server = http.createServer((req, res) => {
  const rel = decodeURIComponent(req.url.split("?")[0]).replace(/^\/+/, "");
  const file = path.join(OUT, rel);
  if (!file.startsWith(OUT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "Content-Type": TYPES[path.extname(file)] ?? "text/html" });
  fs.createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const die = (msg) => {
  console.error("FAIL: " + msg);
  server.close();
  process.exit(1);
};

const py = await loadPyodide();
await py.loadPackage(["micropip", "pydantic", "pyyaml"]);

const manifest = await (await fetch(`${base}/wheels/manifest.json`)).json();
try {
  await py.runPythonAsync(`
import micropip
await micropip.install("${base}/${manifest.structlog.replace(/^\.\//, "")}")
await micropip.install("${base}/${manifest.openscript.replace(/^\.\//, "")}")
`);
} catch (e) {
  die("the wheels the page ships did not install:\n" + String(e).split("\n").slice(-6).join("\n"));
}

try {
  await py.runPythonAsync(await (await fetch(`${base}/pipeline.py`)).text());
} catch (e) {
  die("pipeline.py did not load:\n" + String(e).split("\n").slice(-10).join("\n"));
}

const run = py.globals.get("run_pipeline");
if (!run) die("pipeline.py defined no run_pipeline");

let failures = 0;
const times = [];

for (const ex of EXAMPLES) {
  let result;
  try {
    result = JSON.parse(await run(JSON.stringify({ text: ex.text, tool_call: ex.toolCall ?? null })));
  } catch (e) {
    console.error(`  ${ex.id}: raised ${String(e).split("\n").slice(-3).join(" ")}`);
    failures++;
    continue;
  }
  times.push(result.latency_ms);

  const row = result.rows.find((r) => r.key === ex.expect);
  const fired = row && ["deny", "mutate", "approval", "flag"].includes(row.verdict);
  const quiet = result.rows.every((r) => ["allow", "skipped", "not_reached"].includes(r.verdict));

  // A chip that advertises a policy must actually trip it; the benign one must
  // trip nothing, which is the claim that it is not just blocking everything.
  const ok = ex.expect ? fired : quiet;
  if (!ok) failures++;

  const verdict = ex.expect ? `${ex.expect}=${row ? row.verdict : "absent"}` : quiet ? "all clear" : "unexpectedly flagged";
  console.log(
    `  ${ok ? "ok  " : "FAIL"} ${ex.id.padEnd(10)} ${verdict.padEnd(24)} risk ${String(result.risk).padEnd(5)} ${result.latency_ms.toFixed(1)}ms`,
  );
  if (!ok) {
    for (const r of result.rows) console.error(`         ${r.verdict.padEnd(12)} ${r.policy}: ${r.explanation}`);
  }
}

server.close();

const sorted = [...times].sort((a, b) => a - b);
console.log(
  `\n${EXAMPLES.length - failures}/${EXAMPLES.length} examples behave as advertised ` +
    `(p50 ${sorted[Math.floor(sorted.length / 2)].toFixed(1)}ms, max ${Math.max(...times).toFixed(1)}ms)`,
);
process.exit(failures ? 1 : 0);
