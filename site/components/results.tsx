"use client";

import { useEffect, useRef } from "react";
import type { Example } from "@/lib/examples";
import { outcomeOf, rewrites } from "@/lib/outcome";
import type { AttemptedToolCall, PipelineResult } from "@/lib/types";
import { DiffView } from "./diff-view";
import { VerdictRow } from "./verdict-row";

/**
 * Who sent it, what they sent, and what it is reaching for. A prompt blocked
 * on the way in produces no output at all, so without this the visitor never
 * sees the text they just ran.
 *
 * Shown before a run as well as after: it is everything the page knows about a
 * prompt without the runtime, so it is what the window opens on.
 */
export function PromptCard({ example }: { example: Example }) {
  return (
    <div className="sender">
      <p className="sender__who">
        <span className="avatar avatar--lg" aria-hidden="true">
          {example.persona.name[0]}
        </span>
        <span>
          <strong>{example.persona.name}</strong>
          <span className="sender__role">{example.persona.role}</span>
        </span>
      </p>
      <p className="sender__prompt">{example.text}</p>
      <dl className="sender__attempt">
        <dt>What {example.persona.name} is asking for</dt>
        <dd>{example.attempt}</dd>
      </dl>
    </div>
  );
}

/**
 * A response can come back three ways: untouched, rewritten, or intact but with
 * a finding recorded. Collapsing the third into a clean pass would hide the
 * policy that did the noticing.
 *
 * "Rewritten" has two places it can happen, and the line says which. Masked on
 * the way in means the model was never given the thing; masked on the way out
 * means it was, and repeated it. Those are not the same protection.
 *
 * The clean case is worded as what the policies did — none of them matched —
 * rather than as a verdict on the prompt. These are local heuristics; a prompt
 * they miss is a prompt they miss, not a prompt that is safe, and a demo whose
 * green state reads as an endorsement is making a claim it cannot support.
 */
function returnedLine(result: PipelineResult): string {
  const { input, output } = rewrites(result);
  if (input && output) {
    return "The prompt was rewritten before the model saw it, and the response was rewritten again on the way back.";
  }
  if (input) {
    return "The prompt was rewritten before the model saw it, to remove what the policies found. The response needed nothing taken out.";
  }
  if (output) {
    return "The response came back, rewritten to remove what the policies found.";
  }
  const flagged = result.rows.filter((r) => r.verdict === "flag");
  if (flagged.length) {
    return `The response came back unchanged, but ${flagged
      .map((r) => r.policy)
      .join(" and ")} recorded a finding.`;
  }
  return "No policy matched, so the response came back untouched. That is what these checks did not find — not a verdict that the prompt is safe.";
}

/**
 * Shown when a policy scored self-harm. A demo whose entire response to "how
 * many pills would it take" is a red Blocked badge has answered the wrong
 * question, so this runs ahead of the verdict table rather than inside it.
 *
 * A native <dialog> is doing the work: showModal() brings focus handling and
 * Escape-to-close for free, and `method="dialog"` closes without any JS. There
 * is nothing to dismiss on the results underneath, so nothing else is needed.
 *
 * Keyed on the run rather than on what is on screen: walking back to an
 * earlier result with the arrow keys must not open it a second time.
 */
export function CrisisNotice({ result }: { result: PipelineResult }) {
  const ref = useRef<HTMLDialogElement | null>(null);

  useEffect(() => {
    const node = ref.current;
    if (result.crisis && node && !node.open) node.showModal();
  }, [result]);

  return (
    <dialog ref={ref} className="crisis" aria-labelledby="crisis-title">
      <h3 id="crisis-title">If this is about you, someone will talk to you now</h3>
      <ul>
        <li>
          <strong>US &amp; Canada</strong> — call or text <strong>988</strong>
        </li>
        <li>
          <strong>UK &amp; Ireland</strong> — call <strong>116 123</strong> (Samaritans)
        </li>
        <li>
          <strong>Anywhere else</strong> —{" "}
          <a href="https://findahelpline.com" target="_blank" rel="noreferrer">
            findahelpline.com
          </a>
        </li>
      </ul>
      <p className="muted">
        A policy on this page matched a self-harm pattern in the prompt you ran. Refusing the
        request and saying nothing else would be the wrong response to it, so this says
        something else.
      </p>
      <form method="dialog">
        <button type="submit" className="btn">
          Close
        </button>
      </form>
    </dialog>
  );
}

/**
 * The attempted call, spelled out next to the rule it was held to.
 *
 * "Blocked by the tool firewall" is a claim; refund_tool(amount=9999) against
 * max_amount 100 is the reason, and it is the part that shows the check is a
 * rule rather than a vibe. Without it a visitor has to take the verdict on
 * trust, which is the thing this page exists not to ask for.
 */
function ToolCallView({ call }: { call: AttemptedToolCall }) {
  const args = Object.entries(call.args)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");
  const rule = Object.entries(call.rule);

  return (
    <div className="toolcall">
      <span className="label">The call the agent tried to make</span>
      <code className="toolcall__code">
        {call.name}({args})
      </code>
      {rule.length ? (
        <p className="toolcall__rule">
          Rule for <code>{call.name}</code>:{" "}
          {rule.map(([k, v]) => `${k.replace(/_/g, " ")} ${JSON.stringify(v)}`).join(", ")}
        </p>
      ) : (
        <p className="toolcall__rule">No rule covers this tool, so the default applies.</p>
      )}
      <p className="toolcall__rule">
        {call.executed
          ? "The tool ran."
          : "The tool itself never ran. That is read off the tool, not inferred from the verdict."}
      </p>
    </div>
  );
}

export interface Headline {
  title: string;
  line: string;
  /** The policy's own words for it, where it gave any. */
  reason: string;
}

/**
 * The headline for a run. Three cases, because "held" is neither of the other
 * two: the reply came back and the tool call did not go out, and calling that
 * either Blocked or Returned would misdescribe half of it.
 *
 * Plain strings so the same words can be read out as well as shown.
 */
export function headlineOf(result: PipelineResult): Headline {
  if (result.blocked) {
    return {
      title: "Blocked",
      line:
        result.stage === "tool"
          ? `The reply was returned, but the tool call was refused by the ${result.blocked_by} policy.`
          : result.stage === "response"
            ? `The model replied, but the ${result.blocked_by} policy stopped the response from being returned.`
            : `The ${result.blocked_by} policy stopped this before the model ever saw it.`,
      reason: result.blocked_reason,
    };
  }

  const held = result.rows.filter((r) => r.verdict === "approval");
  if (held.length) {
    return {
      title: "Held for approval",
      line: `The reply was returned, but the tool call is waiting on a human decision from the ${held
        .map((r) => r.policy)
        .join(" and ")} policy.`,
      reason: result.blocked_reason,
    };
  }

  return { title: "Returned", line: returnedLine(result), reason: "" };
}

export function Results({ result, example }: { result: PipelineResult; example: Example }) {
  const { tone } = outcomeOf(result);
  const headline = headlineOf(result);

  return (
    <section className={`results tone--${tone}`}>
      <PromptCard example={example} />

      <div className="outcome">
        <strong>{headline.title}</strong>
        <p>{headline.line}</p>
        {headline.reason ? <p className="outcome__reason">{headline.reason}</p> : null}
      </div>

      {/* A badge says a policy fired. It does not say what the agent would
          have done with the prompt, or what the pipeline did instead — which
          is what a visitor cannot work out from the prompt alone. The two
          halves are coloured the way the verdicts are: what would have
          happened, against what did. */}
      <dl className="compare">
        <div className="compare__side compare__side--without">
          <dt>Without the gateway</dt>
          <dd>{example.without}</dd>
        </div>
        <div className="compare__side compare__side--with">
          <dt>With OpenScript</dt>
          <dd>{example.withGateway}</dd>
        </div>
      </dl>

      {result.tool_call ? <ToolCallView call={result.tool_call} /> : null}

      <DiffView
        before={result.prompt}
        after={result.model_input}
        beforeLabel={`What ${example.persona.name} sent`}
        afterLabel="What the model was given"
      />
      <DiffView
        before={result.raw_output}
        after={result.output}
        beforeLabel="What the model produced"
        afterLabel="What the caller received"
      />

      <div className="steps">
        <h3 className="steps__title">The pipeline, in order</h3>
        <p className="steps__local">
          Every check below ran locally in your browser, in {result.latency_ms.toFixed(1)} ms.
        </p>
        <ol className="verdicts">
          {result.rows.map((row) => (
            <VerdictRow key={row.key} row={row} />
          ))}
        </ol>
      </div>

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
