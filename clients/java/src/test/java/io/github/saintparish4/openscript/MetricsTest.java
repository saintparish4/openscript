package io.github.saintparish4.openscript;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MetricsTest {

  private StubServer stub;
  private InMemoryMetrics metrics;
  private OpenScriptClient client;

  @BeforeEach
  void start() throws IOException {
    stub = new StubServer();
    metrics = new InMemoryMetrics();
    client = stub.client().metrics(metrics).build();
  }

  @AfterEach
  void stop() {
    stub.close();
  }

  private static Map<String, Object> withFindings(
      String decision, Map<String, Object> findings, Map<String, Object> categories) {
    Map<String, Object> body = StubServer.answer(decision, Map.of("prompt", "x"), Map.of("output", "y"));
    body.put("findings", findings);
    body.put("risk_categories", categories);
    body.put("risk_score", 0.8);
    body.put("pipeline_ms", 3.0);
    return body;
  }

  @Test
  void countsDecisionsAndWhatThePoliciesFound() {
    stub.handle(
        r ->
            StubServer.Reply.ok(
                withFindings(
                    "deny",
                    Map.of("threat", Map.of("risk", 0.8, "category", "threat", "flagged", true)),
                    Map.of("threat", 0.8))));
    client.checkInput(Map.of("prompt", "x"), CheckOptions.defaults());

    stub.handle(
        r ->
            StubServer.Reply.ok(
                withFindings(
                    "deny",
                    Map.of("tool_firewall", Map.of("risk", 0.8, "allowed", false)),
                    Map.of("tool_firewall", 0.8))));
    client.checkToolCall("drop", Map.of(), CheckOptions.defaults());

    stub.handle(
        r ->
            StubServer.Reply.ok(
                withFindings(
                    "allow",
                    Map.of("pii", Map.of("risk", 0.5, "redacted", true)),
                    Map.of("pii", 0.5, "secrets", 0.0))));
    client.checkOutput(Map.of(), Map.of("output", "a"), CheckOptions.defaults());

    assertEquals(1, metrics.checks("invoke", "input", Decision.DENY));
    assertEquals(1, metrics.checks("tool_call", "input", Decision.DENY));
    assertEquals(1, metrics.checks("invoke", "output", Decision.ALLOW));
    assertEquals(0, metrics.checks("invoke", "input", Decision.ALLOW));
    assertEquals(1, metrics.injectionsFlagged());
    assertEquals(1, metrics.toolCallsDenied());
    assertEquals(1, metrics.piiRedacted());
    assertEquals(1, metrics.policyViolations("threat"));
    assertEquals(1, metrics.policyViolations("pii"));
    assertEquals(0, metrics.policyViolations("secrets"));
    assertEquals(1, metrics.pipeline("invoke", "input").count());
    assertEquals(0.003, metrics.pipeline("invoke", "input").sum(), 1e-9);
    assertEquals(1, metrics.roundTrip("invoke", "input").count());
  }

  @Test
  void countsRequestsThatGotNoDecision() {
    stub.handle(r -> new StubServer.Reply(500, Map.of("detail", "policy failed")));
    assertThrows(OpenScriptException.class, () -> client.checkInput(Map.of(), CheckOptions.defaults()));
    stub.close();
    assertThrows(OpenScriptException.class, () -> client.checkInput(Map.of(), CheckOptions.defaults()));

    assertEquals(2, metrics.errors("invoke", "input"));
    assertEquals(2, metrics.roundTrip("invoke", "input").count());
    assertEquals(0, metrics.pipeline("invoke", "input").count());
    String text = metrics.toPrometheus();
    assertTrue(text.contains("openscript_client_errors_total{action=\"invoke\",phase=\"input\",status=\"500\"} 1"), text);
    assertTrue(text.contains("openscript_client_errors_total{action=\"invoke\",phase=\"input\",status=\"0\"} 1"), text);
  }

  @Test
  void asyncCallsAreCountedToo() throws Exception {
    stub.handle(StubServer::echo);
    client.secureAgent(input -> "ok").invokeAsync(Map.of("p", "x")).get();
    assertEquals(1, metrics.checks("invoke", "input", Decision.ALLOW));
    assertEquals(1, metrics.checks("invoke", "output", Decision.ALLOW));
  }

  @Test
  void aRecorderThatThrowsDoesNotChangeTheAnswer() throws Exception {
    stub.handle(StubServer::echo);
    OpenScriptClient noisy =
        stub.client()
            .metrics(
                o -> {
                  throw new IllegalStateException("recorder broke");
                })
            .build();
    assertEquals("ok", noisy.secureAgent(input -> "ok").invoke(Map.of("p", "x")));
  }

  @Test
  void writesPrometheusText() {
    stub.handle(r -> StubServer.Reply.ok(withFindings("allow", Map.of(), Map.of())));
    client.checkInput(Map.of(), CheckOptions.defaults());
    client.checkInput(Map.of(), CheckOptions.defaults());
    String text = metrics.toPrometheus();

    assertTrue(text.contains("# TYPE openscript_client_checks_total counter\n"), text);
    assertTrue(
        text.contains("openscript_client_checks_total{action=\"invoke\",phase=\"input\",decision=\"allow\"} 2\n"),
        text);
    assertTrue(text.contains("# TYPE openscript_client_round_trip_seconds histogram\n"), text);
    assertTrue(
        text.contains("openscript_client_pipeline_seconds_bucket{action=\"invoke\",phase=\"input\",le=\"0.005\"} 2\n"),
        text);
    assertTrue(
        text.contains("openscript_client_pipeline_seconds_bucket{action=\"invoke\",phase=\"input\",le=\"0.0025\"} 0\n"),
        text);
    assertTrue(
        text.contains("openscript_client_pipeline_seconds_bucket{action=\"invoke\",phase=\"input\",le=\"+Inf\"} 2\n"),
        text);
    assertTrue(text.contains("openscript_client_pipeline_seconds_count{action=\"invoke\",phase=\"input\"} 2\n"), text);
    assertTrue(text.contains("openscript_client_check_risk_score_bucket{le=\"0.8\"} 2\n"), text);
    assertTrue(text.contains("openscript_client_injections_flagged_total 0\n"), text);
  }

  @Test
  void labelValuesAreEscaped() {
    InMemoryMetrics m = new InMemoryMetrics();
    m.record(new Observation("a\"b", "in\\put", 200, Decision.ALLOW, "", 0, Map.of(), Map.of(), 0, 1));
    assertTrue(m.toPrometheus().contains("action=\"a\\\"b\",phase=\"in\\\\put\""), m.toPrometheus());
  }

  @Test
  void quantileUpperBoundReadsTheBuckets() {
    InMemoryMetrics m = new InMemoryMetrics();
    for (int i = 0; i < 100; i++) {
      double ms = i < 90 ? 0.8 : 20;
      m.record(
          new Observation("invoke", "input", 200, Decision.ALLOW, "", 0, Map.of(), Map.of(), ms, 1));
    }
    InMemoryMetrics.HistogramSnapshot s = m.pipeline("invoke", "input");
    assertEquals(100, s.count());
    assertEquals(0.001, s.quantileUpperBound(0.5));
    assertEquals(0.001, s.quantileUpperBound(0.9));
    assertEquals(0.025, s.quantileUpperBound(0.95));
  }

  @Test
  void streamScansAreCounted() throws Exception {
    stub.handle(
        r -> {
          if (r.path().equals("/v1/guard/stream")) {
            Map<String, Object> scan = new LinkedHashMap<>();
            scan.put("decision", "allow");
            scan.put("text", r.body().get("text"));
            scan.put("risk", 0.0);
            return StubServer.Reply.ok(scan);
          }
          Map<String, Object> reply = StubServer.answer("allow", r.body().get("input"), r.body().get("output"));
          reply.put("stream_guards", java.util.List.of("PIIPolicy"));
          reply.put("stream_window", 2);
          return StubServer.Reply.ok(reply);
        });
    try (var s =
        client
            .secureStreamingAgent(input -> java.util.stream.Stream.of("abc", "def"), CheckOptions.defaults(), StreamMode.GUARDED)
            .stream(Map.of())) {
      s.forEach(chunk -> {});
    }
    assertTrue(metrics.checks("stream", "scan", Decision.ALLOW) >= 2);
    assertEquals(1, metrics.checks("stream", "input", Decision.ALLOW));
    assertEquals(1, metrics.checks("stream", "output", Decision.ALLOW));
  }
}
