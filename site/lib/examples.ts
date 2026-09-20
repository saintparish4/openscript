import type { ToolCall } from "./types";
import data from "./examples.json";

export interface Persona {
  name: string;
  /** Who they are to the system, which is what makes the prompt plausible. */
  role: string;
}

export interface Example {
  id: string;
  /** Short label for the chip, written as the thing the persona did. */
  label: string;
  /** What a visitor should expect to see, in one clause. */
  teaser: string;
  /** Three fictional people share the gallery: a customer, a contractor and a
   *  support agent. Attack prompts arriving from named users with a reason to
   *  be talking to the agent is closer to what a gateway actually sees than a
   *  list of disembodied payloads. */
  persona: Persona;
  text: string;
  /** What the prompt is trying to do, in the sender's terms. */
  attempt: string;
  /** What reaching the agent unchecked would have meant. */
  without: string;
  /** What the pipeline does with it instead. Must match what actually happens:
   *  verify.mjs runs every one of these against the real policies. */
  withGateway: string;
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
