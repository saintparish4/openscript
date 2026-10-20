package io.github.saintparish4.openscript;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The client's own behaviour, against a stub that answers what each test scripts. */
class OpenScriptClientTest {

  private record Reply(int status, String body) {}

  private HttpServer server;
  private final Deque<Reply> replies = new ArrayDeque<>();
  private final List<Map<String, Object>> requests = new ArrayList<>();
  private final List<String> keys = new ArrayList<>();
  private OpenScriptClient client;

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          Map<String, Object> seen = new LinkedHashMap<>();
          seen.put("method", exchange.getRequestMethod());
          seen.put("path", exchange.getRequestURI().getPath());
          seen.put("body", body.isEmpty() ? null : Json.parse(body));
          synchronized (requests) {
            requests.add(seen);
            keys.add(exchange.getRequestHeaders().getFirst("X-API-KEY"));
          }
          Reply reply;
          synchronized (replies) {
            reply = replies.isEmpty() ? new Reply(500, "{\"detail\":\"unscripted\"}") : replies.poll();
          }
          byte[] bytes = reply.body().getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(reply.status(), bytes.length);
          try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
          }
        });
    server.start();
    client =
        OpenScriptClient.builder()
            .baseUrl("http://127.0.0.1:" + server.getAddress().getPort())
            .apiKey("k")
            .timeout(Duration.ofSeconds(5))
            .build();
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  private void reply(Map<String, Object> body) {
    replies.add(new Reply(200, Json.write(body)));
  }

  private static Map<String, Object> answer(String decision, Map<String, ?> input, Object output) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decision", decision);
    body.put("reason", decision.equals("allow") ? "" : "because");
    body.put("blocked_by", decision.equals("allow") ? "" : "SomePolicy");
    body.put("approval_id", decision.equals("require_approval") ? "ap-1" : "");
    body.put("input", input);
    body.put("output", output);
    body.put("risk_score", decision.equals("allow") ? 0.0 : 0.9);
    body.put("risk_categories", Map.of());
    body.put("findings", Map.of());
    return body;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> sent(int index) {
    return (Map<String, Object>) requests.get(index).get("body");
  }

  @Test
  void agentIsGivenTheInputThePoliciesLeft() throws Exception {
    reply(answer("allow", Map.of("prompt", "key [REDACTED]"), null));
    reply(answer("allow", Map.of("prompt", "key [REDACTED]"), Map.of("output", "mail [EMAIL]")));
    AtomicReference<Object> given = new AtomicReference<>();
    SecureAgent agent =
        client.secureAgent(
            input -> {
              given.set(input.get("prompt"));
              return "mail bob@corp.example";
            });

    Object result = agent.invoke(Map.of("prompt", "key AKIA..."));

    assertEquals("key [REDACTED]", given.get());
    assertEquals("mail [EMAIL]", result);
    assertEquals("input", sent(0).get("phase"));
    assertEquals("invoke", sent(0).get("action"));
    assertEquals(Map.of("prompt", "key AKIA..."), sent(0).get("input"));
    assertEquals("output", sent(1).get("phase"));
    // The output phase is told what the agent was actually given.
    assertEquals(Map.of("prompt", "key [REDACTED]"), sent(1).get("input"));
    assertEquals(Map.of("output", "mail bob@corp.example"), sent(1).get("output"));
    assertEquals(List.of("k", "k"), keys);
  }

  @Test
  void agentReturningAMapGetsAMapBack() throws Exception {
    reply(answer("allow", Map.of("q", 1L), null));
    reply(answer("allow", Map.of("q", 1L), Map.of("answer", "x", "score", 2L)));
    Object result = client.secureAgent(input -> Map.of("answer", "y", "score", 2)).invoke(Map.of("q", 1));
    assertEquals(Map.of("answer", "x", "score", 2L), result);
  }

  @Test
  void deniedInputNeverReachesTheAgent() {
    reply(answer("deny", Map.of("prompt", "ignore"), null));
    AtomicReference<Boolean> ran = new AtomicReference<>(false);
    SecureAgent agent =
        client.secureAgent(
            input -> {
              ran.set(true);
              return "";
            });

    ActionBlockedException blocked =
        assertThrows(ActionBlockedException.class, () -> agent.invoke(Map.of("prompt", "ignore")));
    assertFalse(ran.get());
    assertEquals("input", blocked.phase());
    assertEquals("SomePolicy", blocked.blockedBy());
    assertEquals(0.9, blocked.riskScore());
    assertFalse(blocked.requiresApproval());
    assertEquals(1, requests.size());
  }

  @Test
  void deniedOutputIsWithheld() {
    reply(answer("allow", Map.of("prompt", "x"), null));
    reply(answer("deny", Map.of("prompt", "x"), null));
    ActionBlockedException blocked =
        assertThrows(
            ActionBlockedException.class,
            () -> client.secureAgent(input -> "secret").invoke(Map.of("prompt", "x")));
    assertEquals("output", blocked.phase());
  }

  @Test
  void toolRunsWithTheCheckedArgumentsAndReportsItsResult() throws Exception {
    reply(answer("allow", Map.of("name", "send", "args", Map.of("to", "a@example.com")), null));
    reply(answer("allow", Map.of("name", "send", "args", Map.of("to", "a@example.com")), Map.of("output", "sent")));
    AtomicReference<Map<String, Object>> given = new AtomicReference<>();
    SecureTool send =
        client.secureTool(
            "send",
            args -> {
              given.set(args);
              return "sent";
            },
            CheckOptions.defaults().withSessionId("s1").withRole("ops"));

    assertEquals("sent", send.call(Map.of("to", "a@example.com")));
    assertEquals(Map.of("to", "a@example.com"), given.get());
    assertEquals("tool_call", sent(0).get("action"));
    assertEquals(Map.of("name", "send", "args", Map.of("to", "a@example.com")), sent(0).get("input"));
    assertEquals("s1", sent(0).get("session_id"));
    assertEquals("ops", sent(0).get("role"));
    assertEquals(Map.of("output", "sent"), sent(1).get("output"));
  }

  @Test
  void heldToolCallCarriesItsApprovalAndTheRetrySpendsIt() throws Exception {
    Map<String, Object> call = Map.of("name", "wire", "args", Map.of("amount", 10L));
    reply(answer("require_approval", call, null));
    SecureTool wire = client.secureTool("wire", args -> "ok");

    ActionBlockedException held =
        assertThrows(ActionBlockedException.class, () -> wire.call(Map.of("amount", 10)));
    assertTrue(held.requiresApproval());
    assertEquals("ap-1", held.approvalId());

    reply(answer("allow", call, null));
    reply(answer("allow", call, Map.of("output", "ok")));
    assertEquals("ok", wire.call(Map.of("amount", 10), CheckOptions.defaults().withApprovalId("ap-1")));
    assertEquals("ap-1", sent(1).get("approval_id"));
    // Spent on the input; the result is checked without it.
    assertEquals("", sent(2).get("approval_id"));
  }

  @Test
  void serverErrorIsARefusal() {
    replies.add(new Reply(500, "{\"detail\":\"Action blocked: PIIPolicy failed during before_action\"}"));
    AtomicReference<Boolean> ran = new AtomicReference<>(false);
    OpenScriptException error =
        assertThrows(
            OpenScriptException.class,
            () ->
                client
                    .secureTool(
                        "t",
                        args -> {
                          ran.set(true);
                          return null;
                        })
                    .call(Map.of()));
    assertFalse(ran.get());
    assertEquals(500, error.status());
    assertTrue(error.getMessage().contains("PIIPolicy failed"), error.getMessage());
  }

  @Test
  void unreachableServerIsARefusal() {
    server.stop(0);
    AtomicReference<Boolean> ran = new AtomicReference<>(false);
    OpenScriptException error =
        assertThrows(
            OpenScriptException.class,
            () ->
                client
                    .secureAgent(
                        input -> {
                          ran.set(true);
                          return "";
                        })
                    .invoke(Map.of("prompt", "hi")));
    assertFalse(ran.get());
    assertEquals(0, error.status());
  }

  @Test
  void unknownDecisionIsNotAnAllow() {
    Map<String, Object> body = answer("allow", Map.of(), null);
    body.put("decision", "maybe");
    reply(body);
    assertThrows(OpenScriptException.class, () -> client.checkInput(Map.of(), CheckOptions.defaults()));
  }

  @Test
  void unsendableArgumentIsRefusedBeforeAnythingRuns() {
    AtomicReference<Boolean> ran = new AtomicReference<>(false);
    assertThrows(
        OpenScriptException.class,
        () ->
            client
                .secureTool(
                    "t",
                    args -> {
                      ran.set(true);
                      return null;
                    })
                .call(Map.of("when", new Object())));
    assertFalse(ran.get());
    assertTrue(requests.isEmpty());
  }

  @Test
  void approvals() {
    Map<String, Object> record = new LinkedHashMap<>();
    record.put("approval_id", "ap-1");
    record.put("session_id", "s");
    record.put("agent_id", "a");
    record.put("action", "tool_call");
    record.put("reason", "needs a person");
    record.put("action_hash", "h");
    record.put("status", "pending");
    record.put("created_at", "2026-10-20T00:00:00+00:00");
    record.put("expires_at", "2026-10-20T01:00:00+00:00");
    record.put("decided_by", "");
    record.put("decision_note", "");
    reply(Map.of("count", 1L, "approvals", List.of(record)));
    List<Approval> pending = client.pendingApprovals();
    assertEquals(1, pending.size());
    assertEquals("ap-1", pending.get(0).approvalId());
    assertEquals("GET", requests.get(0).get("method"));
    assertNull(requests.get(0).get("body"));

    Map<String, Object> decided = new LinkedHashMap<>(record);
    decided.put("status", "approved");
    decided.put("decided_by", "ops");
    reply(decided);
    Approval approval = client.decideApproval("ap-1", true, "ops", "checked the amount");
    assertEquals("approved", approval.status());
    assertEquals("/v1/approvals/ap-1/decide", requests.get(1).get("path"));
    assertEquals(
        Map.of("approved", true, "decided_by", "ops", "note", "checked the amount"), sent(1));
  }

  @Test
  void conflictIsAnError() {
    replies.add(new Reply(409, "{\"detail\":\"approval already decided\"}"));
    OpenScriptException error =
        assertThrows(OpenScriptException.class, () -> client.decideApproval("ap-1", true, "", ""));
    assertEquals(409, error.status());
  }
}
