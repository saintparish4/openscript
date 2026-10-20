package io.github.saintparish4.openscript;

import java.util.Map;

/**
 * The server's answer for one phase of one action.
 *
 * @param input the input as the policies left it. Give the agent or tool this, not what was sent:
 *     a redacting policy replaces what it redacts.
 * @param output the output as the policies left it; null for the input phase and whenever the
 *     decision is not {@link Decision#ALLOW}
 * @param findings what each policy wrote, keyed by category ({@code "threat"}, {@code "pii"},
 *     {@code "tool_firewall"}, ...), in the same shape as Python's {@code context.metadata}
 */
public record GuardResult(
    Decision decision,
    String reason,
    String blockedBy,
    String approvalId,
    Map<String, Object> input,
    Map<String, Object> output,
    double riskScore,
    Map<String, Double> riskCategories,
    Map<String, Object> findings) {

  public boolean allowed() {
    return decision == Decision.ALLOW;
  }

  /** This result, or an {@link ActionBlockedException} if the policies did not allow it. */
  public GuardResult orThrow(String phase) {
    if (!allowed()) {
      throw new ActionBlockedException(this, phase);
    }
    return this;
  }
}
