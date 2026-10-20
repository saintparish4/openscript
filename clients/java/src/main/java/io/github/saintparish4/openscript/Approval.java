package io.github.saintparish4.openscript;

/**
 * An approval record as the server stores it. Timestamps are ISO-8601 strings, as sent.
 *
 * @param status "pending", "approved" or "denied"
 */
public record Approval(
    String approvalId,
    String sessionId,
    String agentId,
    String action,
    String reason,
    String status,
    String createdAt,
    String expiresAt,
    String decidedBy,
    String decisionNote) {}
