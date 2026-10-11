export type Verdict =
  | "allow"
  | "flag"
  | "mutate"
  | "deny"
  | "approval"
  | "skipped"
  | "not_reached";

export interface PolicyRow {
  key: string;
  policy: string;
  blurb: string;
  verdict: Verdict;
  risk: number | null;
  explanation: string;
}

export interface PipelineResult {
  prompt: string;
  /** What the model was actually handed. Differs from `prompt` when an
   *  input-side policy redacted it; empty when the prompt was stopped first. */
  model_input: string;
  output: string;
  /** What the model produced, before any policy rewrote it. */
  raw_output: string;
  blocked: boolean;
  blocked_by: string;
  blocked_reason: string;
  /** Where the block happened, so it can be described accurately. */
  stage: "" | "prompt" | "response" | "tool";
  /** A self-harm pattern matched, at or below threshold. Routes to resources. */
  crisis: boolean;
  /** The call the agent attempted, and the rule it was held to. */
  tool_call: AttemptedToolCall | null;
  /** What the agent read through a tool before it made that call, if anything. */
  fetched: FetchedTool | null;
  /** Set when the tool call needed a human: waiting, or what was decided. */
  approval: Approval | null;
  rows: PolicyRow[];
  risk: number;
  categories: Record<string, number>;
  /** Measured inside Python around the pipeline call only — not runtime boot. */
  latency_ms: number;
  events: number;
}

export interface Approval {
  id: string;
  /** "spent" is an id that was already decided or has expired. */
  status: "pending" | "approved" | "denied" | "spent";
  decided_by: string;
  /** The decider's reason, where they gave one. */
  note: string;
}

/** A human's answer to a held call, sent back with the same submission. */
export interface Decision {
  id: string;
  approved: boolean;
  decided_by: string;
  note: string;
}

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
  /** Who the call is made as, where the tool is restricted by role. */
  role?: string;
}

/** A tool the agent called first, to read something, and what came back. */
export interface FetchedTool {
  name: string;
  args: Record<string, unknown>;
  returned: string;
  executed: boolean;
  /** The scan of the result matched an injection at or above threshold. */
  flagged: boolean;
  risk: number;
}

export interface AttemptedToolCall extends ToolCall {
  /** Only the fields the rule actually sets, so the page shows the constraint
   *  that was applied rather than a wall of defaults. */
  rule: Record<string, unknown>;
  /** Whether the tool's own code ran. Reported by the tool, not worked out
   *  from the verdict: "refused" is only worth saying if this is false. */
  executed: boolean;
}
