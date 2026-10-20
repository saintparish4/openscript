package io.github.saintparish4.openscript;

import java.util.Objects;

/**
 * Who is asking, and on whose behalf: the keyword arguments of Python's {@code invoke()} and
 * {@code SecureTool.call()}.
 *
 * <pre>{@code
 * CheckOptions opts = CheckOptions.defaults().withSessionId("s-42").withRole("finance");
 * }</pre>
 *
 * @param sessionId groups calls for policies that remember (the session rule) and for the record
 * @param role the caller's role, for tool rules restricted by role; null for none, which a
 *     role-restricted rule refuses
 * @param approvalId an approved approval to redeem; "" for none
 */
public record CheckOptions(String sessionId, String agentId, String role, String approvalId) {

  public CheckOptions {
    Objects.requireNonNull(sessionId, "sessionId");
    Objects.requireNonNull(agentId, "agentId");
    Objects.requireNonNull(approvalId, "approvalId");
  }

  public static CheckOptions defaults() {
    return new CheckOptions("default", "default", null, "");
  }

  public CheckOptions withSessionId(String sessionId) {
    return new CheckOptions(sessionId, agentId, role, approvalId);
  }

  public CheckOptions withAgentId(String agentId) {
    return new CheckOptions(sessionId, agentId, role, approvalId);
  }

  public CheckOptions withRole(String role) {
    return new CheckOptions(sessionId, agentId, role, approvalId);
  }

  public CheckOptions withApprovalId(String approvalId) {
    return new CheckOptions(sessionId, agentId, role, approvalId);
  }
}
