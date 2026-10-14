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
  /** The senders are fictional people with a reason to be talking to the
   *  agent: a customer, a contractor, a support agent, three engineers and an
   *  analyst with a browsing agent. Attack prompts arriving from named users
   *  is closer to what a gateway actually sees than a list of disembodied
   *  payloads. */
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
  /** A document the agent reads through a tool before it acts, and the text
   *  of it. This is how an injection arrives without the sender writing one. */
  fetched?: { name: string; args: Record<string, unknown>; returns: string };
  /** For a prompt whose tool call is held: who it goes to, and what they say
   *  if they turn it down. The visitor makes the decision in their place. */
  approval?: {
    approver: Persona;
    denyNote: string;
    /** A different call to the same tool, which the approval must not cover. */
    otherArgs: Record<string, unknown>;
  };
  /** An attack the policies are known not to catch, shown on purpose. Asserted
   *  the same way as everything else: if a pattern ever starts catching it,
   *  the copy that says it gets through is wrong and verify.mjs fails. */
  miss?: boolean;
  /** The injection in `fetched` is one the scan of the tool's result is known
   *  not to catch, shown on purpose: the tool rule stops the call anyway.
   *  Asserted both ways by verify.mjs, like `miss`. */
  scanMiss?: boolean;
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
