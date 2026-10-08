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
  if (result.rows.some((r) => r.verdict === "approval")) return { tone: "approval", label: "Held" };
  const { input, output } = rewrites(result);
  if (input || output) return { tone: "mutate", label: "Redacted" };
  // Kept apart from a clean run: an annotate-mode policy found something and
  // chose not to act, which is not the same as finding nothing.
  if (result.rows.some((r) => r.verdict === "flag")) return { tone: "flag", label: "Flagged" };
  return { tone: "clean", label: "No match" };
}
