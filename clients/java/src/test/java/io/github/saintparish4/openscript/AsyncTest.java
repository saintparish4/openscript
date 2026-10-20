package io.github.saintparish4.openscript;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AsyncTest {

  private StubServer stub;
  private OpenScriptClient client;

  @BeforeEach
  void start() throws IOException {
    stub = new StubServer();
    client = stub.client().build();
  }

  @AfterEach
  void stop() {
    stub.close();
  }

  private static Throwable failure(CompletableFuture<?> future) {
    ExecutionException ex =
        assertThrows(ExecutionException.class, () -> future.get(5, TimeUnit.SECONDS));
    return ex.getCause();
  }

  @Test
  void invokeAsyncGivesTheAgentWhatThePoliciesLeft() throws Exception {
    stub.handle(
        r ->
            r.body().get("phase").equals("input")
                ? StubServer.Reply.ok(StubServer.answer("allow", Map.of("prompt", "[MASKED]"), null))
                : StubServer.echo(r));
    AtomicReference<Object> given = new AtomicReference<>();
    SecureAgent agent =
        client.secureAsyncAgent(
            input -> {
              given.set(input.get("prompt"));
              return CompletableFuture.completedFuture("done");
            });

    assertEquals("done", agent.invokeAsync(Map.of("prompt", "key AKIA")).get(5, TimeUnit.SECONDS));
    assertEquals("[MASKED]", given.get());
    assertEquals(Map.of("prompt", "[MASKED]"), stub.requests().get(1).body().get("input"));
  }

  @Test
  void blockingAgentRunsOnTheExecutorWhenCalledAsync() throws Exception {
    stub.handle(StubServer::echo);
    AtomicReference<Thread> ranOn = new AtomicReference<>();
    OpenScriptClient withExecutor =
        stub.client()
            .executor(
                task ->
                    new Thread(task, "openscript-test-worker").start())
            .build();
    Object answer =
        withExecutor
            .secureAgent(
                input -> {
                  ranOn.set(Thread.currentThread());
                  return Map.of("n", 1);
                })
            .invokeAsync(Map.of("q", "x"))
            .get(5, TimeUnit.SECONDS);
    assertEquals(Map.of("n", 1L), answer);
    assertEquals("openscript-test-worker", ranOn.get().getName());
  }

  @Test
  void asyncAgentCanBeCalledBlocking() throws Exception {
    stub.handle(StubServer::echo);
    SecureAgent agent =
        client.secureAsyncAgent(input -> CompletableFuture.supplyAsync(() -> "later"));
    assertEquals("later", agent.invoke(Map.of("prompt", "hi")));
  }

  @Test
  void deniedInputFailsTheFutureAndTheAgentNeverRuns() {
    stub.handle(r -> StubServer.Reply.ok(StubServer.answer("deny", r.body().get("input"), null)));
    AtomicBoolean ran = new AtomicBoolean();
    CompletableFuture<Object> future =
        client
            .secureAsyncAgent(
                input -> {
                  ran.set(true);
                  return CompletableFuture.completedFuture("");
                })
            .invokeAsync(Map.of("prompt", "ignore"));
    ActionBlockedException blocked =
        assertInstanceOf(ActionBlockedException.class, failure(future));
    assertEquals("input", blocked.phase());
    assertFalse(ran.get());
  }

  @Test
  void blockingCallOfAnAsyncAgentThrowsTheRefusalItself() {
    stub.handle(r -> StubServer.Reply.ok(StubServer.answer("deny", r.body().get("input"), null)));
    SecureAgent agent = client.secureAsyncAgent(input -> CompletableFuture.completedFuture(""));
    ActionBlockedException blocked =
        assertThrows(ActionBlockedException.class, () -> agent.invoke(Map.of("prompt", "x")));
    assertEquals("SomePolicy", blocked.blockedBy());
  }

  @Test
  void agentFailurePropagatesAsTheCause() {
    stub.handle(StubServer::echo);
    IOException boom = new IOException("model down");
    CompletableFuture<Object> future =
        client
            .secureAgent(
                input -> {
                  throw boom;
                })
            .invokeAsync(Map.of("prompt", "x"));
    assertSame(boom, failure(future));
    // and the output was never checked
    assertEquals(1, stub.requests().size());
  }

  @Test
  void unreachableServerFailsTheFuture() {
    stub.close();
    AtomicBoolean ran = new AtomicBoolean();
    CompletableFuture<Object> future =
        client
            .secureAsyncTool(
                "t",
                args -> {
                  ran.set(true);
                  return CompletableFuture.completedFuture(null);
                })
            .callAsync(Map.of());
    OpenScriptException error = assertInstanceOf(OpenScriptException.class, failure(future));
    assertEquals(0, error.status());
    assertFalse(ran.get());
  }

  @Test
  void serverErrorFailsTheFutureWithItsStatus() {
    stub.handle(r -> new StubServer.Reply(503, Map.of("detail", "no policies configured")));
    OpenScriptException error =
        assertInstanceOf(
            OpenScriptException.class,
            failure(client.checkInputAsync(Map.of("p", "x"), CheckOptions.defaults())));
    assertEquals(503, error.status());
    assertTrue(error.getMessage().contains("no policies configured"));
  }

  @Test
  void unsendableArgumentFailsTheFutureBeforeAnythingIsSent() {
    CompletableFuture<GuardResult> future =
        client.checkToolCallAsync("t", Map.of("x", new Object()), CheckOptions.defaults());
    assertInstanceOf(OpenScriptException.class, failure(future));
    assertTrue(stub.requests().isEmpty());
  }

  @Test
  void toolRunsWithCheckedArgumentsAndReportsItsResult() throws Exception {
    stub.handle(
        r ->
            r.body().get("phase").equals("input")
                ? StubServer.Reply.ok(
                    StubServer.answer(
                        "allow", Map.of("name", "send", "args", Map.of("to", "a@example.com")), null))
                : StubServer.echo(r));
    AtomicReference<Map<String, Object>> given = new AtomicReference<>();
    SecureTool send =
        client.secureAsyncTool(
            "send",
            args -> {
              given.set(args);
              return CompletableFuture.completedFuture("sent");
            });
    assertEquals("sent", send.callAsync(Map.of("to", "A@EXAMPLE.COM")).get(5, TimeUnit.SECONDS));
    assertEquals(Map.of("to", "a@example.com"), given.get());
    List<StubServer.Request> sent = stub.requests();
    assertEquals("output", sent.get(1).body().get("phase"));
    assertEquals(Map.of("output", "sent"), sent.get(1).body().get("output"));
    assertEquals("", sent.get(1).body().get("approval_id"));
  }

  @Test
  void heldToolCallCarriesItsApproval() {
    stub.handle(r -> StubServer.Reply.ok(StubServer.answer("require_approval", r.body().get("input"), null)));
    ActionBlockedException held =
        assertInstanceOf(
            ActionBlockedException.class,
            failure(client.secureTool("wire", args -> "ok").callAsync(Map.of("amount", 1))));
    assertTrue(held.requiresApproval());
    assertEquals("ap-1", held.approvalId());
  }

  @Test
  void approvalsAsync() throws Exception {
    stub.handle(r -> StubServer.Reply.ok(Map.of("count", 0, "approvals", List.of())));
    assertTrue(client.pendingApprovalsAsync().get(5, TimeUnit.SECONDS).isEmpty());
    stub.handle(r -> new StubServer.Reply(404, Map.of("detail", "approval 'x' not found")));
    OpenScriptException error =
        assertInstanceOf(
            OpenScriptException.class,
            failure(client.decideApprovalAsync("x", true, "ops", "")));
    assertEquals(404, error.status());
  }

  @Test
  void manyCallsInFlight() throws Exception {
    stub.handle(StubServer::echo);
    SecureAgent agent = client.secureAgent(input -> input.get("n"));
    List<CompletableFuture<Object>> futures =
        java.util.stream.IntStream.range(0, 32)
            .mapToObj(i -> agent.invokeAsync(Map.of("n", i)))
            .toList();
    CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).get(10, TimeUnit.SECONDS);
    for (int i = 0; i < 32; i++) {
      assertEquals((long) i, futures.get(i).get());
    }
    assertEquals(64, stub.requests().size());
  }
}
