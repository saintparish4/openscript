"use client";

import { useState } from "react";
import type { Persona } from "@/lib/examples";
import type { Approval, AttemptedToolCall } from "@/lib/types";
import { CheckIcon, SlashIcon } from "./icons";

interface Props {
  approval: Approval;
  call: AttemptedToolCall;
  /** Whose session the call belongs to. */
  sender: string;
  /** Who it was sent to for a decision. */
  approver: Persona;
  /** What the approver says when they turn it down. */
  denyNote: string;
  onDecide?: (approved: boolean) => void;
  onReset?: () => void;
}

/**
 * Where a held call goes, and how it comes back.
 *
 * "Requires approval" on its own is a verdict with no second half: held for
 * whom, and then what? This is the second half. The call goes to a named
 * person, waits on them, and returns to the session that asked either to run
 * once or with a reason for the refusal.
 *
 * The visitor plays the approver. Both buttons go through the real approval
 * store: the decision is recorded against the id the pipeline issued, and an
 * approved call is retried with that id, which is the only way it ever runs.
 */
export function ApprovalFlow({
  approval,
  call,
  sender,
  approver,
  denyNote,
  onDecide,
  onReset,
}: Props) {
  // Which button was pressed, for the moment between the press and the answer.
  const [sending, setSending] = useState<"" | "approve" | "deny">("");
  const args = Object.entries(call.args)
    .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
    .join(", ");
  const pending = approval.status === "pending";
  const approved = approval.status === "approved";

  const decide = (yes: boolean) => {
    if (sending || !onDecide) return;
    setSending(yes ? "approve" : "deny");
    onDecide(yes);
  };

  return (
    <div className={`approval approval--${approval.status}`}>
      <span className="label">Where the held call went</span>
      <ol className="approval__steps">
        <li className="approval__step approval__step--done">
          <strong>{sender}&rsquo;s agent called the tool</strong>
          <code className="toolcall__code">
            {call.name}({args})
          </code>
          <p>The firewall held it: this tool needs a person to say yes.</p>
        </li>

        <li className={`approval__step approval__step--${pending ? "waiting" : "done"}`}>
          <strong>
            Sent to {approver.name}, {approver.role}
          </strong>
          {pending ? (
            <>
              <p className="approval__waiting" role="status">
                <span className="spinner" aria-hidden="true" />
                Waiting on {approver.name}. Nothing has been sent, and nothing will be until
                {approver.name} answers. Left alone, the request expires in an hour.
              </p>
              <p>You are {approver.name} for this one. Decide:</p>
              <div className="approval__actions">
                <button
                  type="button"
                  className="btn"
                  disabled={!onDecide || sending !== ""}
                  onClick={() => decide(true)}
                >
                  <CheckIcon size={14} />
                  {sending === "approve" ? "Approving…" : `Approve as ${approver.name}`}
                </button>
                <button
                  type="button"
                  className="btn btn--ghost"
                  disabled={!onDecide || sending !== ""}
                  onClick={() => decide(false)}
                >
                  <SlashIcon size={14} />
                  {sending === "deny" ? "Denying…" : `Deny as ${approver.name}`}
                </button>
              </div>
              <p className="approval__note">
                If {approver.name} denies it, the reason given is: &ldquo;{denyNote}&rdquo;
              </p>
            </>
          ) : approved ? (
            <p>
              <span className="approval__verdict approval__verdict--yes">
                {approver.name} approved it.
              </span>
            </p>
          ) : (
            <>
              <p>
                <span className="approval__verdict approval__verdict--no">
                  {approver.name} denied it.
                </span>
              </p>
              <blockquote className="approval__reason">{approval.note}</blockquote>
            </>
          )}
        </li>

        {pending ? null : (
          <li className="approval__step approval__step--done">
            <strong>Back to {sender}</strong>
            {approved ? (
              <p>
                The call was retried with the approval attached, and <code>{call.name}</code>{" "}
                ran. The approval is now spent: it cannot be used a second time, or for a
                different recipient.
              </p>
            ) : (
              <p>
                {sender} gets the refusal and {approver.name}&rsquo;s reason.{" "}
                <code>{call.name}</code> never ran, and the denied request cannot be redeemed
                later.
              </p>
            )}
          </li>
        )}
      </ol>

      {!pending && onReset ? (
        <button type="button" className="btn btn--ghost" onClick={onReset}>
          {approved ? `See what happens if ${approver.name} denies it` : `See what happens if ${approver.name} approves it`}
        </button>
      ) : null}
    </div>
  );
}
