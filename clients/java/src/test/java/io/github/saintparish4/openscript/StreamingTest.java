package io.github.saintparish4.openscript;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Streaming against a stub whose "guard" redacts SECRET to [X] and refuses BOOM, deferring a
 * possible match at the edge of the text until the final scan, as the real guards do.
 */
class StreamingTest {

  private static final int WINDOW = 6;

  private StubServer stub;
  private OpenScriptClient client;
  private String outputDecision = "allow";

  @BeforeEach
  void start() throws IOException {
    stub = new StubServer();
    stub.handle(this::answer);
    client = stub.client().build();
  }

  @AfterEach
  void stop() {
    stub.close();
  }

  @SuppressWarnings("unchecked")
  private StubServer.Reply answer(StubServer.Request r) {
    Map<String, Object> body = r.body();
    if (r.path().equals("/v1/guard/stream")) {
      return StubServer.Reply.ok(scan((String) body.get("text"), (Boolean) body.get("final")));
    }
    if (body.get("phase").equals("input")) {
      Map<String, Object> reply = StubServer.answer("allow", body.get("input"), null);
      if (body.get("action").equals("stream")) {
        reply.put("stream_guards", List.of("FakeGuard"));
        reply.put("stream_window", WINDOW);
      }
      return StubServer.Reply.ok(reply);
    }
    Map<String, Object> output = new LinkedHashMap<>((Map<String, Object>) body.get("output"));
    if (output.get("output") instanceof String text) {
      output.put("output", text.replace("SECRET", "[X]"));
    }
    return StubServer.Reply.ok(StubServer.answer(outputDecision, body.get("input"), output));
  }

  private static Map<String, Object> scan(String text, boolean last) {
    Map<String, Object> reply = new LinkedHashMap<>();
    if (text.contains("BOOM")) {
      reply.put("decision", "deny");
      reply.put("text", "");
      reply.put("reason", "boom in stream");
      reply.put("blocked_by", "FakeGuard");
      reply.put("labels", List.of("boom"));
      reply.put("risk", 0.9);
      return reply;
    }
    // A tail that could still grow into a match is left alone until the end.
    int keep = text.length();
    if (!last) {
      for (int n = Math.min(5, text.length()); n > 0; n--) {
        if ("SECRET".startsWith(text.substring(text.length() - n))) {
          keep = text.length() - n;
          break;
        }
      }
    }
    String scanned = text.substring(0, keep).replace("SECRET", "[X]") + text.substring(keep);
    reply.put("decision", "allow");
    reply.put("text", scanned);
    reply.put("labels", scanned.equals(text) ? List.of() : List.of("secret"));
    reply.put("risk", scanned.equals(text) ? 0.0 : 0.9);
    return reply;
  }

  private SecureStreamingAgent agent(StreamMode mode, Object... chunks) {
    return client.secureStreamingAgent(
        input -> Stream.of(chunks), CheckOptions.defaults(), mode);
  }

  private static List<Object> drain(Stream<Object> stream) {
    try (stream) {
      return stream.collect(Collectors.toList());
    }
  }

  @Test
  void bufferJoinsTextAndDeliversItOnceChecked() throws Exception {
    List<Object> got =
        drain(agent(StreamMode.BUFFER, "my SE", "CRET is ", "here").stream(Map.of("prompt", "x")));
    assertEquals(List.of("my [X] is here"), got);
    StubServer.Request output = stub.requests().get(1);
    assertEquals("stream", output.body().get("action"));
    assertEquals(Map.of("output", "my SECRET is here"), output.body().get("output"));
  }

  @Test
  void bufferKeepsStructuredChunksApart() throws Exception {
    List<Object> got =
        drain(agent(StreamMode.BUFFER, Map.of("a", 1), Map.of("b", 2)).stream(Map.of()));
    assertEquals(List.of(Map.of("a", 1L), Map.of("b", 2L)), got);
  }

  @Test
  void bufferRefusalDeliversNothing() throws Exception {
    outputDecision = "deny";
    Stream<Object> stream = agent(StreamMode.BUFFER, "a", "b").stream(Map.of());
    Iterator<Object> it = stream.iterator();
    ActionBlockedException blocked = assertThrows(ActionBlockedException.class, it::hasNext);
    assertEquals("output", blocked.phase());
  }

  @Test
  void refusedInputNeverStartsTheAgent() {
    stub.handle(r -> StubServer.Reply.ok(StubServer.answer("deny", r.body().get("input"), null)));
    AtomicBoolean started = new AtomicBoolean();
    SecureStreamingAgent agent =
        client.secureStreamingAgent(
            input -> {
              started.set(true);
              return Stream.of("x");
            },
            CheckOptions.defaults(),
            StreamMode.GUARDED);
    assertThrows(ActionBlockedException.class, () -> agent.stream(Map.of("prompt", "ignore")));
    assertFalse(started.get());
  }

  @Test
  void passthroughDeliversEverythingThenRefusesLoudly() throws Exception {
    outputDecision = "deny";
    Iterator<Object> it = agent(StreamMode.PASSTHROUGH, "a", "SECRET", "b").stream(Map.of()).iterator();
    List<Object> got = new ArrayList<>();
    ActionBlockedException blocked =
        assertThrows(
            ActionBlockedException.class,
            () -> {
              while (it.hasNext()) got.add(it.next());
            });
    // Unscanned, and all of it: too late, by design.
    assertEquals(List.of("a", "SECRET", "b"), got);
    assertEquals("output", blocked.phase());
  }

  @Test
  void guardedRedactsAcrossChunksAndNeverReleasesPartOfAMatch() throws Exception {
    List<String> chunks = List.of("hello ", "wor", "ld, the ", "SE", "CR", "ET", " is out");
    List<Object> got =
        drain(agent(StreamMode.GUARDED, chunks.toArray()).stream(Map.of("prompt", "x")));
    String joined = got.stream().map(String::valueOf).collect(Collectors.joining());
    assertEquals("hello world, the [X] is out", joined);
    for (Object release : got) {
      String text = (String) release;
      for (String part : List.of("SE", "SEC", "CRET", "ET ")) {
        assertFalse(text.contains(part) && !text.contains("[X]"), "leaked " + text);
      }
    }
    // More than one release: it streamed.
    assertTrue(got.size() > 1, got.toString());
    // The after phase saw what was released.
    StubServer.Request last = stub.requests().get(stub.requests().size() - 1);
    assertEquals(Map.of("output", joined), last.body().get("output"));
  }

  @Test
  void guardedRefusalReleasesNothingOfTheMatch() throws Exception {
    Iterator<Object> it =
        agent(StreamMode.GUARDED, "fine text here, ", "then BO", "OM and more").stream(Map.of()).iterator();
    StringBuilder got = new StringBuilder();
    ActionBlockedException blocked =
        assertThrows(
            ActionBlockedException.class,
            () -> {
              while (it.hasNext()) got.append(it.next());
            });
    assertEquals("stream", blocked.phase());
    assertEquals("FakeGuard", blocked.blockedBy());
    assertFalse(got.toString().contains("BO"), got.toString());
  }

  @Test
  void guardedNeedsText() throws Exception {
    Iterator<Object> it = agent(StreamMode.GUARDED, "a", Map.of("x", 1)).stream(Map.of()).iterator();
    assertThrows(IllegalArgumentException.class, () -> {
      while (it.hasNext()) it.next();
    });
  }

  @Test
  void guardedRefusesWithoutAWindowBeforeTheAgentStarts() {
    stub.handle(r -> StubServer.Reply.ok(StubServer.answer("allow", r.body().get("input"), null)));
    AtomicBoolean started = new AtomicBoolean();
    SecureStreamingAgent agent =
        client.secureStreamingAgent(
            input -> {
              started.set(true);
              return Stream.of("x");
            },
            CheckOptions.defaults(),
            StreamMode.GUARDED);
    assertThrows(OpenScriptException.class, () -> agent.stream(Map.of()));
    assertFalse(started.get());
  }

  @Test
  void minReleaseMeansFewerScans() throws Exception {
    Object[] chunks = new Object[60];
    for (int i = 0; i < chunks.length; i++) chunks[i] = "ab";
    drain(agent(StreamMode.GUARDED, chunks).stream(Map.of()));
    int eager = stub.requests("/v1/guard/stream").size();

    stub.close();
    stub = new StubServer();
    stub.handle(this::answer);
    client = stub.client().build();
    List<Object> got = drain(agent(StreamMode.GUARDED, chunks).withMinRelease(40).stream(Map.of()));
    int batched = stub.requests("/v1/guard/stream").size();

    assertEquals("ab".repeat(60), got.stream().map(String::valueOf).collect(Collectors.joining()));
    assertTrue(batched < eager / 4, "eager " + eager + ", batched " + batched);
  }

  @Test
  void closingTheStreamClosesTheAgents() throws Exception {
    AtomicBoolean closed = new AtomicBoolean();
    SecureStreamingAgent agent =
        client.secureStreamingAgent(
            input -> Stream.of("a", "b").onClose(() -> closed.set(true)),
            CheckOptions.defaults(),
            StreamMode.PASSTHROUGH);
    try (Stream<Object> stream = agent.stream(Map.of())) {
      stream.findFirst();
    }
    assertTrue(closed.get());
  }
}
