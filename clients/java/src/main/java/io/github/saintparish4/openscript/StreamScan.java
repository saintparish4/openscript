package io.github.saintparish4.openscript;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One pass of the stream guards over held-back text, as {@code /v1/guard/stream} answers it. */
record StreamScan(
    Decision decision,
    String text,
    String reason,
    String blockedBy,
    List<String> labels,
    double risk,
    double pipelineMillis,
    long roundTripNanos) {

  static StreamScan from(Map<String, Object> body, long nanos) {
    Decision decision = Decision.fromWire(OpenScriptClient.string(body, "decision"));
    if (decision == Decision.REQUIRE_APPROVAL) {
      // The guards allow, redact or deny. Anything else is not an answer this client knows.
      throw new OpenScriptException("a stream scan cannot require approval");
    }
    List<String> labels = new ArrayList<>();
    for (Object label : OpenScriptClient.asList(body.getOrDefault("labels", List.of()))) {
      labels.add(String.valueOf(label));
    }
    return new StreamScan(
        decision,
        OpenScriptClient.string(body, "text"),
        OpenScriptClient.string(body, "reason"),
        OpenScriptClient.string(body, "blocked_by"),
        labels,
        OpenScriptClient.number(body.getOrDefault("risk", 0.0)),
        OpenScriptClient.number(body.getOrDefault("pipeline_ms", 0.0)),
        nanos);
  }

  Map<String, Double> categories() {
    return risk > 0 ? Map.of("stream_guard", risk) : Map.of();
  }

  Observation observation() {
    return new Observation(
        "stream", "scan", 200, decision, blockedBy, risk, categories(), Map.of(),
        pipelineMillis, roundTripNanos);
  }

  /** The refusal as a GuardResult, so it is thrown the way every other refusal is. */
  GuardResult refusal(Map<String, Object> input) {
    Map<String, Object> found = new LinkedHashMap<>();
    found.put("risk", risk);
    found.put("category", "stream_guard");
    found.put("labels", labels);
    found.put("denied", true);
    return new GuardResult(
        Decision.DENY, reason, blockedBy, "", input, null, risk, categories(),
        Map.of("stream_guard", found), pipelineMillis, roundTripNanos);
  }
}
