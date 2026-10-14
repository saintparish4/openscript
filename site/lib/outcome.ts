import type { PipelineResult } from "./types";

/**
 * What a run came to, in one word — for the list, where there is room for one.
 *
 * `clean` is deliberately not called "allow" or "safe". It means no policy
 * matched, which is a statement about the policies and not about the prompt.
 */
export type Tone = "deny" | "approval" | "mutate" | "flag" | "clean";

export interface Outcome {
  tone: Tone;
  label: string;
}

/**
 * Where text was rewritten. There are two places and they are different
 * guarantees: on the way in, the model never held the thing; on the way out,
 * it did and the caller did not get it back.
 */
export function rewrites(result: PipelineResult): { input: boolean; output: boolean } {
  return {
    input: result.model_input !== "" && result.model_input !== result.prompt,
    output: result.raw_output !== result.output,
  };
}

export function outcomeOf(result: PipelineResult): Outcome {
  if (result.blocked) return { tone: "deny", label: "Blocked" };
  // A human's decision outranks the hold it resolves.
  if (result.approval?.status === "approved") return { tone: "clean", label: "Approved" };
  if (result.approval?.status === "denied") return { tone: "deny", label: "Denied" };
  if (result.rows.some((r) => r.verdict === "approval")) return { tone: "approval", label: "Held" };
  const { input, output } = rewrites(result);
  if (input || output) return { tone: "mutate", label: "Redacted" };
  // Kept apart from a clean run: an annotate-mode policy found something and
  // chose not to act, which is not the same as finding nothing.
  if (result.rows.some((r) => r.verdict === "flag")) return { tone: "flag", label: "Flagged" };
  return { tone: "clean", label: "No match" };
}

/**
 * The path a call takes, and what happened at each point on it. The gallery is
 * eleven different verdicts until this is on screen; with it they are the same
 * four checkpoints, acting in different places.
 *
 * `acted` is where a policy did something, `passed` where it looked and let
 * the call on, `unreached` where the call never got to.
 */
export interface Stage {
  name: string;
  /** `noted` is a finding that was recorded and deliberately not acted on. */
  state: "passed" | "acted" | "noted" | "unreached";
  /** One word for what happened here. */
  note: string;
}

/**
 * A run of a prompt the gallery shows *because* nothing catches it. The
 * pipeline reports "no policy matched", and for this one prompt that is a
 * miss, so it is not allowed to look like the green of an ordinary pass.
 */
export function missedOutcome(outcome: Outcome): Outcome {
  return outcome.tone === "clean" ? { tone: "flag", label: "Missed" } : outcome;
}

export function stagesOf(result: PipelineResult, miss = false, scanMiss = false): Stage[] {
  const stoppedAtPrompt = result.blocked && result.stage === "prompt";
  const { input, output } = rewrites(result);
  const held = result.rows.some((r) => r.verdict === "approval");

  const stages: Stage[] = [
    stoppedAtPrompt
      ? { name: "Prompt", state: "acted", note: "Blocked" }
      : input
        ? { name: "Prompt", state: "acted", note: "Redacted" }
        : miss
          ? { name: "Prompt", state: "noted", note: "Missed" }
          : { name: "Prompt", state: "passed", note: "Checked" },
    stoppedAtPrompt
      ? { name: "Agent", state: "unreached", note: "Never ran" }
      : { name: "Agent", state: "passed", note: "Ran" },
  ];

  // What a tool handed back is a second way in, and gets its own checkpoint
  // when the agent read something.
  if (result.fetched) {
    stages.push(
      result.fetched.flagged
        ? { name: "Tool result", state: "noted", note: "Flagged" }
        : scanMiss
          ? { name: "Tool result", state: "noted", note: "Missed" }
          : { name: "Tool result", state: "passed", note: "Read" },
    );
  }

  // Only when the agent reached for a tool: most prompts never do, and an
  // empty checkpoint on every other result would be noise.
  if (result.tool_call) {
    stages.push(
      result.blocked && result.stage === "tool"
        ? { name: "Tool call", state: "acted", note: "Refused" }
        : result.approval?.status === "approved"
          ? { name: "Tool call", state: "acted", note: "Approved, ran" }
          : result.approval?.status === "denied"
            ? { name: "Tool call", state: "acted", note: "Denied" }
            : held
              ? { name: "Tool call", state: "acted", note: "Held" }
          : { name: "Tool call", state: "passed", note: result.tool_call.executed ? "Ran" : "Checked" },
    );
  }

  stages.push(
    stoppedAtPrompt
      ? { name: "Reply", state: "unreached", note: "None" }
      : result.blocked && result.stage === "response"
        ? { name: "Reply", state: "acted", note: "Withheld" }
        : output
          ? { name: "Reply", state: "acted", note: "Redacted" }
          : { name: "Reply", state: "passed", note: "Returned" },
  );
  return stages;
}
