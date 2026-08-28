import type { ToolCall } from "./types";
import data from "./examples.json";

export interface Example {
  id: string;
  /** Short label for the chip. */
  label: string;
  /** What a visitor should expect to see, in one clause. */
  teaser: string;
  text: string;
  toolCall?: ToolCall;
  /** The policy this example is meant to demonstrate, asserted by verify.mjs. */
  expect: string;
}

/**
 * The gallery lives in examples.json so the page and the end-to-end check read
 * the same list. Every entry is asserted against the real pipeline: if a
 * policy's patterns drift and an example stops firing the policy it advertises,
 * `npm run verify` fails.
 */
export const EXAMPLES: Example[] = data as Example[];
