"use client";

import { useEffect, useRef } from "react";
import { EXAMPLES, type Example } from "@/lib/examples";
import { missedOutcome, outcomeOf, rewrites, stagesOf } from "@/lib/outcome";
import type { AttemptedToolCall, FetchedTool, PipelineResult } from "@/lib/types";
import { ApprovalFlow } from "./approval-flow";
import { DiffView } from "./diff-view";
import { ArrowRight } from "./icons";
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
 * "Blocked by the tool firewall" is a claim; refund_tool(amount=129) against
 * max_amount 100 is the reason, and it is the part that shows the check is a
 * rule rather than a vibe. Without it a visitor has to take the verdict on
 * trust, which is the thing this page exists not to ask for.
 */
/**
 * What the agent read before it acted, and what the scan made of it.
 *
 * The text is shown in full because it is the attack. The sender's prompt was
 * innocent; this is where the instruction came from, and a visitor who cannot
 * read it has to take "indirect injection" on trust.
 */
function FetchedView({ fetched, missed }: { fetched: FetchedTool; missed: boolean }) {
  const args = Object.entries(fetched.args)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");
  return (
    <div className="toolcall toolcall--read">
      <span className="label">What the agent read first</span>
      <code className="toolcall__code">
        {fetched.name}({args})
      </code>
      <p className="toolcall__rule">This call is allowed, and it ran. It returned:</p>
      <p className="diff__text toolcall__returned">{fetched.returned}</p>
      <p className={`toolcall__scan${fetched.flagged || missed ? " toolcall__scan--flagged" : ""}`}>
        {fetched.flagged
          ? `The scan of this result scored it ${fetched.risk.toFixed(2)} for injection and recorded that. It did not block it: the result still reached the agent.`
          : missed
            ? `The scan of this result scored it ${fetched.risk.toFixed(2)}: nothing in it matched a pattern. The instruction is there, in the last paragraph. This is what the detector missing an attack looks like, and the call below is what the rules do about it.`
            : "The scan of this result found nothing that read as an instruction to the model."}
      </p>
    </div>
  );
}

function ToolCallView({ call, after = false }: { call: AttemptedToolCall; after?: boolean }) {
  const args = Object.entries(call.args)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");
  const rule = Object.entries(call.rule);

  return (
    <div className="toolcall">
      <span className="label">
        {after ? "The call the agent tried to make next" : "The call the agent tried to make"}
      </span>
      <code className="toolcall__code">
        {call.name}({args})
      </code>
      {call.role ? (
        <p className="toolcall__rule">
          Made with the role <code>{call.role}</code>.
        </p>
      ) : null}
      {rule.length ? (
        <p className="toolcall__rule">
          Rule for <code>{call.name}</code>:{" "}
          {rule.map(([k, v]) => `${k.replace(/_/g, " ")} ${JSON.stringify(v)}`).join(", ")}
        </p>
      ) : (
        <p className="toolcall__rule">
          No rule names this tool, and a tool with no rule is refused.
        </p>
      )}
      <p className="toolcall__rule">
        {call.executed
          ? "The tool ran, once. That is read off the tool, not inferred from the verdict."
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

  const who = result.approval?.decided_by || "A human";
  if (result.approval?.status === "approved") {
    return {
      title: "Approved",
      line: `${who} approved the call, so it went back to the session that asked and the tool ran, once.`,
      reason: result.approval.note,
    };
  }
  if (result.approval?.status === "denied") {
    return {
      title: "Denied",
      line: `${who} turned the call down. The tool never ran, and the reason went back with the refusal.`,
      reason: result.approval.note,
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

/**
 * Where on its way through the call was acted on. Every result gets the same
 * strip, so walking the gallery shows the checkpoints rather than describing
 * them: the first five stop at the prompt, the last two at the tool.
 */
function StageStrip({
  result,
  miss,
  scanMiss,
}: {
  result: PipelineResult;
  miss: boolean;
  scanMiss: boolean;
}) {
  const stages = stagesOf(result, miss, scanMiss);
  return (
    <ol
      className={`checkpoints checkpoints--${stages.length}`}
      aria-label="Where the pipeline acted"
    >
      {stages.map((stage) => (
        <li key={stage.name} className={`checkpoint checkpoint--${stage.state}`}>
          <span className="checkpoint__name">{stage.name}</span>
          <span className="checkpoint__note">{stage.note}</span>
        </li>
      ))}
    </ol>
  );
}

interface ResultsProps {
  result: PipelineResult;
  example: Example;
  /** The prompt after this one in the list as it is filtered, if there is one. */
  next?: Example;
  /** Where this one sits in that list, counted from 1. */
  position?: number;
  total?: number;
  onNext?: (example: Example) => void;
  /** Answer a held call as the person it was sent to. */
  onDecide?: (example: Example, approved: boolean) => void;
  /** Put a decided call back to waiting, to try the other answer. */
  onReset?: (example: Example) => void;
}

export function Results({
  result,
  example,
  next,
  position = 0,
  total = EXAMPLES.length,
  onNext,
  onDecide,
  onReset,
}: ResultsProps) {
  const plain = outcomeOf(result);
  // Only a miss if it really did get through: verify.mjs holds that to be so.
  const missed = example.miss === true && plain.tone === "clean";
  // Same discipline for the scan of a tool result: only a miss if it really
  // did find nothing, which verify.mjs holds it to as well.
  const scanMissed =
    example.scanMiss === true && result.fetched !== null && !result.fetched.flagged;
  const { tone } = missed ? missedOutcome(plain) : plain;
  const headline = missed
    ? {
        title: "Missed",
        line: "This is an attack, and no policy matched it. The model was given the prompt and the reply came back untouched.",
        reason: "",
      }
    : headlineOf(result);
  const unchanged = result.output !== "" && result.output === result.raw_output;
  const findings = result.rows.filter((r) => r.verdict === "flag");
  const ran = result.rows.filter(
    (r) => r.verdict !== "skipped" && r.verdict !== "not_reached",
  ).length;

  return (
    <section className={`results tone--${tone}`}>
      <PromptCard example={example} />

      <div className="outcome">
        <strong>{headline.title}</strong>
        <p>{headline.line}</p>
        {headline.reason ? <p className="outcome__reason">{headline.reason}</p> : null}
      </div>

      <StageStrip result={result} miss={missed} scanMiss={scanMissed} />

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

      {result.fetched ? <FetchedView fetched={result.fetched} missed={scanMissed} /> : null}
      {result.tool_call ? (
        <ToolCallView call={result.tool_call} after={result.fetched !== null} />
      ) : null}

      {result.approval && result.tool_call && example.approval ? (
        <ApprovalFlow
          // A new request, or a decision on this one, is a new flow: the
          // pressed-button state of the last one must not carry over.
          key={`${result.approval.id}:${result.approval.status}`}
          approval={result.approval}
          call={result.tool_call}
          sender={example.persona.name}
          approver={example.approval.approver}
          denyNote={example.approval.denyNote}
          onDecide={onDecide ? (approved) => onDecide(example, approved) : undefined}
          onReset={onReset ? () => onReset(example) : undefined}
        />
      ) : null}

      <DiffView
        before={result.prompt}
        after={result.model_input}
        beforeLabel={`What ${example.persona.name} sent`}
        afterLabel="What the model was given"
      />
      {/* Said on the result as well as under the window: a reply that parrots
          the prompt reads as a bug unless the page owns up to why. */}
      {result.raw_output ? (
        <p className="standin">
          No LLM runs on this page. The agent is a stand-in that repeats what it is given, so
          anything sensitive in the prompt comes straight back out — the same leak a real model
          makes when it quotes its input.
        </p>
      ) : null}
      <DiffView
        before={result.raw_output}
        after={result.output}
        beforeLabel="What the stand-in model produced"
        afterLabel="What the caller received"
      />
      {/* A reply nothing was taken out of is still a reply. Without this a
          flagged or clean run shows a verdict about a response it never shows. */}
      {unchanged ? (
        <div className="reply">
          <span className="label">What the caller received, unchanged</span>
          <p className="diff__text">{result.output}</p>
          {findings.map((row) => (
            <p key={row.key} className="reply__finding">
              <strong>{row.policy} recorded a finding and let it through.</strong>{" "}
              {row.explanation}
            </p>
          ))}
        </div>
      ) : null}

      {/* The answer is above; this is the working. Closed by default so the
          pane reads as a result first, and one tap away for anyone checking. */}
      <details className="steps">
        <summary className="steps__summary">
          <span className="steps__title">Every check, in order</span>
          <span className="steps__local">
            {ran} of {result.rows.length} ran, locally in your browser, in{" "}
            {result.latency_ms.toFixed(1)} ms
          </span>
        </summary>
        <ol className="verdicts">
          {result.rows.map((row) => (
            <VerdictRow key={row.key} row={row} />
          ))}
        </ol>
      </details>

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

      {/* The list is above this on a phone and a long way up on any screen
          once a result has been read. This is the way on without going back. */}
      {onNext ? (
        <div className="onward">
          {next ? (
            <button type="button" className="btn" onClick={() => onNext(next)}>
              Next: {next.label}
              <ArrowRight size={14} />
            </button>
          ) : (
            <p className="onward__end">
              That was the last one.{" "}
              <a href="#policies">What each policy does</a>
            </p>
          )}
          {position ? (
            <span className="onward__count">
              {position} of {total}
            </span>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
