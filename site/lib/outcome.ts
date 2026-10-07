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

export function outcomeOf(result: PipelineResult): Outcome {
  if (result.blocked) return { tone: "deny", label: "Blocked" };
  if (result.rows.some((r) => r.verdict === "approval")) return { tone: "approval", label: "Held" };
  if (result.raw_output !== result.output) return { tone: "mutate", label: "Redacted" };
  // Kept apart from a clean run: an annotate-mode policy found something and
  // chose not to act, which is not the same as finding nothing.
  if (result.rows.some((r) => r.verdict === "flag")) return { tone: "flag", label: "Flagged" };
  return { tone: "clean", label: "No match" };
}
