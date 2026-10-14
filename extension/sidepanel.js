/**
 * The panel: boots the runtime, picks the tab the agent acts on, runs a task
 * when a button is pressed and shows every step the agent took with the
 * firewall's verdict on it.
 *
 * The DOM actions live here because only this side can reach the tab. They
 * are the bodies of the Python tools: `perform` is called by a tool body,
 * after the firewall has let the call through, and nothing in this file
 * touches the tab any other way. Whether an action may happen is never
 * decided here.
 *
 * Page text is the attacker's text. It is written with textContent, never
 * innerHTML.
 */
import { boot } from "./runtime.js";

// The one site the agent may act on. tools.yaml says the same in its own
// words, and tests/test_extension.py checks the two agree.
const VENDOR = "http://localhost:8090";

const $ = (id) => document.getElementById(id);
const statusEl = $("status");
const tabEl = $("tab");
const log = $("log");
const saidEl = $("said");
const approvalEl = $("approval");
const approvalText = $("approval-text");
const buttons = ["task-read", "task-price", "task-buy", "approve", "deny"].map($);

// ── The tab ─────────────────────────────────────────────────────────────────

let tab = null;

/**
 * The page the agent acts on: the active tab that is a web page. When this
 * panel is opened as a tab of its own (which is how check.mjs drives it),
 * the extension's own pages are skipped.
 */
async function pickTab() {
  const pages = (await chrome.tabs.query({})).filter(
    (t) => t.url && !t.url.startsWith("chrome-extension://") && !t.url.startsWith("chrome://"),
  );
  const found = pages.find((t) => t.active) ?? pages.at(-1);
  if (!found) throw new Error("no page to act on: open one first");
  return found;
}

// ── The tools' bodies, on the browser side ──────────────────────────────────
//
// readPage and submitForm are serialized into the tab by chrome.scripting, so
// they must stand alone: nothing from this module is in scope when they run.

function readPage(url) {
  if (location.href !== url) return { error: `the tab is at ${location.href}, not ${url}` };
  return { url: location.href, title: document.title, text: document.body ? document.body.innerText : "" };
}

function submitForm(url, fields) {
  const form = Array.from(document.forms).find((f) => f.action === url);
  if (!form) return { error: `no form on this page posts to ${url}` };
  for (const [name, value] of Object.entries(fields)) {
    const field = form.elements.namedItem(name);
    if (!field) return { error: `the form has no field called ${name}` };
    field.value = String(value);
  }
  form.requestSubmit();
  return { action: form.action, fields };
}

async function inTab(func, args) {
  const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func, args });
  return result;
}

async function openPage(url) {
  const loaded = new Promise((resolve) => {
    const done = (id, info) => {
      if (id === tab.id && info.status === "complete") {
        chrome.tabs.onUpdated.removeListener(done);
        resolve();
      }
    };
    chrome.tabs.onUpdated.addListener(done);
    // A page that never finishes loading must not hang the agent.
    setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(done);
      resolve();
    }, 10000);
  });
  await chrome.tabs.update(tab.id, { url });
  await loaded;
  tab = await chrome.tabs.get(tab.id);
  return { url: tab.url, title: tab.title };
}

/** What agent.py imports as `browser.perform`. Always answers in JSON. */
const browser = {
  async perform(name, argsJson) {
    const args = JSON.parse(argsJson);
    try {
      if (name === "open_page") return JSON.stringify(await openPage(args.url));
      if (name === "read_page") return JSON.stringify(await inTab(readPage, [args.url]));
      if (name === "submit_form") return JSON.stringify(await inTab(submitForm, [args.url, args.fields]));
      return JSON.stringify({ error: `no such action: ${name}` });
    } catch (e) {
      return JSON.stringify({ error: String(e?.message ?? e) });
    }
  },
};

// ── Rendering ───────────────────────────────────────────────────────────────

const VERDICT = {
  ran: "Allowed, ran",
  held: "Held for a person",
  refused: "Refused by the rules",
  skipped: "Not retried",
  failed: "Failed in the browser",
};

function fmtArgs(args) {
  return Object.entries(args)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderStep(step) {
  const li = el("li", `step step--${step.status}`);
  li.dataset.tool = step.tool;
  li.dataset.status = step.status;
  li.dataset.executed = String(step.executed);
  li.append(el("code", "", `${step.tool}(${fmtArgs(step.args)})`));
  li.append(el("strong", "", VERDICT[step.status] ?? step.status));
  if (step.reason) li.append(el("p", "", step.reason));
  li.append(
    el(
      "p",
      "",
      step.executed
        ? "The tool ran, once. Read off the tool, not inferred from the verdict."
        : "The tool itself never ran. Read off the tool, not inferred from the verdict.",
    ),
  );
  if (step.scan) {
    const scan = el(
      "p",
      step.scan.flagged ? "scan scan--flagged" : "scan scan--missed",
      step.scan.flagged
        ? `The scan of what came back scored it ${step.scan.risk.toFixed(2)} for injection and recorded that. It did not block it.`
        : `The scan of what came back scored it ${step.scan.risk.toFixed(2)}: nothing matched a pattern. If the page carries a note for the agent, this is the detector missing it, and the rules are what act.`,
    );
    scan.dataset.flagged = String(step.scan.flagged);
    li.append(scan);
  }
  if (step.tool === "read_page" && typeof step.returned === "string") {
    li.append(el("div", "returned", step.returned));
  }
  return li;
}

let lastTask = "";

function render(task, result) {
  lastTask = task;
  log.replaceChildren(...result.steps.map(renderStep));
  saidEl.textContent = result.said;

  const approval = result.approval;
  approvalEl.hidden = !approval;
  if (approval) {
    approvalEl.dataset.status = approval.status;
    const held = result.steps.find((s) => s.approval_id === approval.id) ?? result.steps.at(-1);
    const call = `${held.tool}(${fmtArgs(held.args)})`;
    approvalText.textContent =
      approval.status === "pending"
        ? `${call} is waiting on you. Nothing has been submitted, and nothing will be until you answer. Left alone, the request expires in an hour.`
        : approval.status === "approved"
          ? `You approved ${call}. It was retried with the approval attached and ran once; the approval is now spent.`
          : approval.status === "denied"
            ? `You denied ${call}. It never ran, and the agent got your reason: “${approval.note}”`
            : `That approval was already used or has expired. ${call} did not run.`;
    $("approve").hidden = $("deny").hidden = approval.status !== "pending";
  }
}

// ── Running ─────────────────────────────────────────────────────────────────

let run = null;
let busy = false;
let runs = 0;

async function doTask(task, decision = null) {
  if (busy || !run) return;
  busy = true;
  for (const b of buttons) b.disabled = true;
  try {
    tab = await pickTab();
    tabEl.textContent = `${tab.title || "(untitled)"} — ${tab.url}`;
    const result = await run({
      task,
      vendor: VENDOR,
      tab: { url: tab.url, title: tab.title },
      approval: decision,
    });
    render(task, result);
    log.dataset.last = JSON.stringify(result);
    statusEl.textContent = `Ran locally in ${result.latency_ms.toFixed(1)} ms`;
    // open_page may have moved the tab; say where it is now.
    tabEl.textContent = `${tab.title || "(untitled)"} — ${tab.url}`;
  } catch (e) {
    statusEl.textContent = `Failed: ${e?.message ?? e}`;
  } finally {
    busy = false;
    for (const b of buttons) b.disabled = false;
    runs += 1;
    log.dataset.runs = String(runs);
  }
}

$("task-read").addEventListener("click", () => doTask("read"));
$("task-price").addEventListener("click", () => doTask("price"));
$("task-buy").addEventListener("click", () => doTask("buy"));
for (const approved of [true, false]) {
  $(approved ? "approve" : "deny").addEventListener("click", () => {
    const id = approvalEl.dataset.status === "pending" && JSON.parse(log.dataset.last ?? "{}").approval?.id;
    if (!id) return;
    void doTask(lastTask, {
      id,
      approved,
      decided_by: "you",
      note: approved ? "" : "Not from the agent. Raise a purchase order and it goes through purchasing.",
    });
  });
}

// ── Boot ────────────────────────────────────────────────────────────────────

const t0 = performance.now();
try {
  ({ run } = await boot({
    onProgress: (_phase, message) => {
      statusEl.textContent = message;
    },
    browser,
  }));
  const bootMs = Math.round(performance.now() - t0);
  statusEl.textContent = `Ready in ${(bootMs / 1000).toFixed(1)} s`;
  statusEl.dataset.ready = "1";
  statusEl.dataset.bootMs = String(bootMs);
  for (const b of buttons) b.disabled = false;
  try {
    tab = await pickTab();
    tabEl.textContent = `${tab.title || "(untitled)"} — ${tab.url}`;
  } catch {
    tabEl.textContent = "No page open.";
  }
} catch (e) {
  statusEl.textContent = `The runtime could not start: ${e?.message ?? e}`;
  console.error(e);
}
