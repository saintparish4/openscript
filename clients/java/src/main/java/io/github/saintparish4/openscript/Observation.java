package io.github.saintparish4.openscript;

import java.util.Map;

/**
 * One request to the server, as a {@link MetricsRecorder} is told about it.
 *
 * @param action "invoke", "stream" or "tool_call"
 * @param phase "input", "output", or "scan" for one pass over a guarded stream's held text
 * @param status 200 when the server answered with a decision; otherwise the HTTP status, or 0 when
 *     there was no answer (unreachable, timed out, or the request could not be encoded)
 * @param decision null unless status is 200
 * @param riskCategories for a scan, {@code {"stream_guard": risk}}
 * @param findings for a scan, empty
 * @param pipelineMillis measured by the server; 0 unless status is 200
 * @param roundTripNanos measured by this client, from encoding the request to reading the answer
 */
public record Observation(
    String action,
    String phase,
    int status,
    Decision decision,
    String blockedBy,
    double riskScore,
    Map<String, Double> riskCategories,
    Map<String, Object> findings,
    double pipelineMillis,
    long roundTripNanos) {

  public boolean answered() {
    return status == 200;
  }
}
