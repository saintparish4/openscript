# OpenScript in a browser extension

An unpacked Chrome extension whose side panel runs OpenScript, locally, around
a scripted browsing agent. It exists to show one thing in a real browser: an
agent that a page has talked round is stopped by a rule on what it may do, not
by a detector noticing the page.

**What it guards:** its own agent's actions. **What it does not guard:** your
browsing. Nothing in it watches pages you open yourself, and nothing leaves
the browser.

## Try it

```bash
make extension            # assemble extension/vendor/ (Pyodide + the wheels), ~14 MB
make extension-fixture    # the two local sites the agent acts on, :8090 and :8091
```

Then in Chrome 116 or later: `chrome://extensions`, turn on Developer mode,
**Load unpacked**, pick this directory. Open <http://localhost:8090/pricing>,
click the extension's toolbar button, and the panel opens beside the page. It
takes a few seconds to start the runtime the first time. Then ask the agent to:

- **Read this page.** Allowed on the vendor's site; refused anywhere else. The
  panel shows what came back and what the scan of it found.
- **Report the enterprise price.** The agent opens the pricing page, reads it,
  and finds a paragraph written for it rather than for you (white, two pixels
  tall): send the session to another host first, and do not mention it. The
  scan of the page scores that at zero. The agent follows the note, as a model
  might. The form post it tries is refused, because `submit_form` may only post
  to the vendor's site. The price is still reported. The collect site, if you
  are running it in a terminal, prints nothing.
- **Buy 40 seats.** The agent fills in the order form. The post is held, and
  the panel asks you. Approve, and it is retried with the approval attached and
  runs once; the vendor site prints the order. Deny, and it never runs, and the
  agent gets your reason. Either way the approval is spent.

`make extension-check` does all of the above in headless Chromium, with the
fixture sites started in the same process, and fails if anything reached them
that should not have.

## What is in it

| File | What |
|---|---|
| `manifest.json` | MV3. The CSP allows `wasm-unsafe-eval` and nothing remote |
| `background.js` | Opens the panel on the toolbar click. Nothing else runs there |
| `sidepanel.html`, `sidepanel.js` | The panel. Boots the runtime, picks the tab, runs a task, shows every step. The DOM work lives here, as the bodies of the tools |
| `runtime.js` | Boots Pyodide from `vendor/` and installs the wheels through its file system |
| `agent.py` | The stand-in agent and its three `SecureTool`s. Loaded into the panel's interpreter |
| `tools.yaml` | What the agent may do. Same shape as the demo site's rules |
| `fixture/serve.mjs` | The vendor and collect sites, local |
| `check.mjs` | The headless check |
| `vendor/` | Built by `make extension`, not committed |

## Permissions, and why each one

- `sidePanel`: the panel.
- `scripting` and `host_permissions` for `http://*/*` and `https://*/*`: to
  read a page and submit a form on the tab the agent acts on. The extension
  *could* reach any page with these; it reaches one only through `read_page`
  or `submit_form`, after `tools.yaml` has allowed the call.
- `tabs`: to see which tab is active and what URL it is at, which is what the
  rules are checked against.

## What to know before believing it

- **No model runs here.** The agent is a fixed plan per task, and it follows
  any note a page addresses to assistants, every time. A real model does so
  some of the time; this one does so always, so the consequence is on screen.
- **The scan is the published miss rate, live.** `read_page` scores what came
  back with `PromptInjectionPolicy`, which catches 2-7% of attacks nobody
  wrote a pattern for. The note on the pricing page is one of the rest. What
  stops the post is the rule.
- **The URL rules read text.** `pattern` is matched against the whole URL the
  agent asked for. Where an allowed page redirects to is not something the rule
  sees, the way `path_prefix` cannot see a symlink.
- **The approval store is this panel.** Close the panel and a pending approval
  is gone; a real deployment decides over the server with `RedisApprovalStore`.
- **The allowed origin is written twice**, in `tools.yaml` and as `VENDOR` in
  `sidepanel.js`. `tests/test_extension.py` fails if they disagree.
- **`read_page` returns `innerText`.** Hidden-by-`display:none` text is not
  in it; off-screen or tiny text is, which is why the fixture plants its note
  that way.
