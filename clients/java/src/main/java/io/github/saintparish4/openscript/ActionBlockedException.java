package io.github.saintparish4.openscript;

/**
 * A policy refused the action, or is holding it for a person. Python's {@code ActionBlockedError}.
 *
 * <p>When {@link #requiresApproval()} is true, {@link #approvalId()} names a pending approval.
 * Once someone approves it (through {@link OpenScriptClient#decideApproval}, the server's
 * dashboard, or {@code POST /v1/approvals/{id}/decide}), retry the same call with {@code
 * options.withApprovalId(id)}. The approval is single-use and bound to the exact input: for a
 * tool, its name and arguments.
 */
public class ActionBlockedException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final transient GuardResult result;
  private final String phase;

  public ActionBlockedException(GuardResult result, String phase) {
    super(message(result, phase));
    this.result = result;
    this.phase = phase;
  }

  private static String message(GuardResult result, String phase) {
    String by = result.blockedBy().isEmpty() ? "" : " by " + result.blockedBy();
    String what = result.decision() == Decision.REQUIRE_APPROVAL ? "held for approval" : "blocked";
    return "Action " + what + by + " (" + phase + "): " + result.reason();
  }

  /** The full answer, including risk and per-policy findings. */
  public GuardResult result() {
    return result;
  }

  /** "input" or "output". After an output refusal, a tool has already run. */
  public String phase() {
    return phase;
  }

  public String reason() {
    return result.reason();
  }

  /** The policy that refused, by its Python class name, e.g. "ToolFirewallPolicy". */
  public String blockedBy() {
    return result.blockedBy();
  }

  public double riskScore() {
    return result.riskScore();
  }

  public boolean requiresApproval() {
    return result.decision() == Decision.REQUIRE_APPROVAL;
  }

  /** The pending approval's id, or "" when this is a refusal. */
  public String approvalId() {
    return result.approvalId();
  }
}
