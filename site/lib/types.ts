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
  rows: PolicyRow[];
  risk: number;
  categories: Record<string, number>;
  /** Measured inside Python around the pipeline call only — not runtime boot. */
  latency_ms: number;
  events: number;
}

export interface ToolCall {
  name: string;
  args: Record<string, unknown>;
}
