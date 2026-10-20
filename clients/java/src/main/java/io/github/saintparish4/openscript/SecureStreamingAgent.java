package io.github.saintparish4.openscript;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * A streaming agent behind the server's {@code agent} policies: Python's {@code
 * SecureAgent.stream()}, with the same three {@link StreamMode}s.
 *
 * <pre>{@code
 * SecureStreamingAgent agent = client.secureStreamingAgent(
 *     input -> model.streamText((String) input.get("prompt")),
 *     CheckOptions.defaults(), StreamMode.GUARDED);
 *
 * try (Stream<Object> answer = agent.stream(Map.of("prompt", userText))) {
 *   answer.forEach(chunk -> out.print(chunk));
 * }
 * }</pre>
 *
 * <p>The input is checked when {@code stream()} is called, and the agent is started on what the
 * policies left; a refused input throws there, before the agent runs. The answer is checked as the
 * returned stream is consumed, so a refusal of the output throws from the stream's terminal
 * operation: in {@code BUFFER} before anything is delivered, in {@code GUARDED} before the
 * matching text is, in {@code PASSTHROUGH} after everything has been.
 *
 * <p>Close the returned stream (try-with-resources) to close the agent's. Consuming it blocks
 * while the server is asked; there is no async form of streaming.
 */
public final class SecureStreamingAgent {
  private final OpenScriptClient client;
  private final StreamingAgent agent;
  private final CheckOptions options;
  private final StreamMode mode;
  private final int minRelease;

  SecureStreamingAgent(
      OpenScriptClient client,
      StreamingAgent agent,
      CheckOptions options,
      StreamMode mode,
      int minRelease) {
    if (minRelease < 0) throw new IllegalArgumentException("minRelease < 0");
    this.client = client;
    this.agent = agent;
    this.options = options;
    this.mode = mode;
    this.minRelease = minRelease;
  }

  /**
   * In {@code GUARDED} mode, hold back at least this many characters beyond the guards' window
   * before asking the server to scan and release. 0 (the default) releases as soon as anything is
   * past the window, as Python does, at the cost of one request per chunk once the window is
   * full. A larger value means fewer requests and later delivery; it never weakens the guarantee,
   * which only depends on the window.
   */
  public SecureStreamingAgent withMinRelease(int characters) {
    return new SecureStreamingAgent(client, agent, options, mode, characters);
  }

  public StreamMode mode() {
    return mode;
  }

  public Stream<Object> stream(Map<String, ?> input) throws Exception {
    return stream(input, options, mode);
  }

  public Stream<Object> stream(Map<String, ?> input, CheckOptions options) throws Exception {
    return stream(input, options, mode);
  }

  public Stream<Object> stream(Map<String, ?> input, CheckOptions options, StreamMode mode)
      throws Exception {
    OpenScriptClient.Answer answer = client.checkStreamInput(input, options);
    GuardResult checked = answer.result().orThrow("input");
    Map<String, Object> given = checked.input();

    // Read before the agent starts: a server that cannot say what to hold
    // back cannot be streamed through in guarded mode.
    Guarding guarding = mode == StreamMode.GUARDED ? Guarding.from(answer.body()) : null;

    Stream<?> source = agent.stream(given);
    if (source == null) {
      throw new IllegalStateException("the agent returned no stream");
    }
    CheckOptions output = options.withApprovalId("");
    Chunks chunks =
        switch (mode) {
          case BUFFER -> new Buffered(source.iterator(), given, output);
          case PASSTHROUGH -> new Passthrough(source.iterator(), given, output);
          case GUARDED -> new Guarded(source.iterator(), given, output, guarding);
        };
    return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(chunks, Spliterator.ORDERED | Spliterator.NONNULL),
            false)
        .onClose(source::close);
  }

  private record Guarding(List<String> guards, int window) {
    static Guarding from(Map<String, Object> body) {
      Object window = body.get("stream_window");
      if (!(window instanceof Number n) || n.longValue() < 0) {
        throw new OpenScriptException("the server did not say how much of a stream to hold back");
      }
      List<String> guards = new ArrayList<>();
      for (Object g : OpenScriptClient.asList(body.getOrDefault("stream_guards", List.of()))) {
        guards.add(String.valueOf(g));
      }
      return new Guarding(guards, n.intValue());
    }
  }

  /** A pull iterator that fills a queue one step at a time. */
  private abstract static class Chunks implements Iterator<Object> {
    final Deque<Object> ready = new ArrayDeque<>();
    boolean done;

    /** Add to {@link #ready}, or set {@link #done}. May throw a refusal. */
    abstract void advance();

    @Override
    public boolean hasNext() {
      while (ready.isEmpty() && !done) advance();
      return !ready.isEmpty();
    }

    @Override
    public Object next() {
      if (!hasNext()) throw new NoSuchElementException();
      return ready.poll();
    }
  }

  /** Nothing reaches the caller until the output policies have run over all of it. */
  private final class Buffered extends Chunks {
    private final Iterator<?> source;
    private final Map<String, Object> input;
    private final CheckOptions options;

    Buffered(Iterator<?> source, Map<String, Object> input, CheckOptions options) {
      this.source = source;
      this.input = input;
      this.options = options;
    }

    @Override
    void advance() {
      done = true;
      List<Object> chunks = new ArrayList<>();
      source.forEachRemaining(chunks::add);
      boolean text = !chunks.isEmpty() && chunks.stream().allMatch(c -> c instanceof String);
      GuardResult answered =
          client.checkStreamOutput(input, assemble(chunks), options).orThrow("output");
      if (text) {
        ready.add(String.valueOf(answered.output().getOrDefault("output", "")));
      } else {
        Object scanned = answered.output().get("chunks");
        if (scanned != null) {
          for (Object chunk : OpenScriptClient.asList(scanned)) {
            if (chunk != null) ready.add(chunk);
          }
        }
      }
    }
  }

  /** Chunks go out as they come; the output policies run after, for the record and a late deny. */
  private final class Passthrough extends Chunks {
    private final Iterator<?> source;
    private final Map<String, Object> input;
    private final CheckOptions options;
    private final List<Object> seen = new ArrayList<>();

    Passthrough(Iterator<?> source, Map<String, Object> input, CheckOptions options) {
      this.source = source;
      this.input = input;
      this.options = options;
    }

    @Override
    void advance() {
      if (source.hasNext()) {
        Object chunk = source.next();
        seen.add(chunk);
        if (chunk != null) ready.add(chunk);
        return;
      }
      done = true;
      // Post-hoc: what it redacts is a copy the caller never sees, and a deny
      // arrives after the caller has everything. Loud, and too late, by design.
      client.checkStreamOutput(input, assemble(seen), options).orThrow("output");
    }
  }

  /** A sliding window over text: release all but the held tail, after the guards have seen it. */
  private final class Guarded extends Chunks {
    private final Iterator<?> source;
    private final Map<String, Object> input;
    private final CheckOptions options;
    private final Guarding guarding;
    private final StringBuilder emitted = new StringBuilder();
    private String held = "";
    private boolean flushed;

    Guarded(
        Iterator<?> source, Map<String, Object> input, CheckOptions options, Guarding guarding) {
      this.source = source;
      this.input = input;
      this.options = options;
      this.guarding = guarding;
    }

    @Override
    void advance() {
      int window = guarding.window();
      while (source.hasNext()) {
        Object chunk = source.next();
        if (!(chunk instanceof String text)) {
          throw new IllegalArgumentException(
              "guarded stream mode needs text chunks; use StreamMode.BUFFER for structured ones");
        }
        held += text;
        if (guarding.guards().isEmpty()) {
          // Nothing scans as it goes: everything can go now.
          release(held);
          held = "";
          return;
        }
        if (held.length() > window + minRelease) {
          held = scan(held, false);
          if (held.length() > window) {
            release(held.substring(0, held.length() - window));
            held = held.substring(held.length() - window);
            return;
          }
        }
      }
      if (!flushed) {
        // Stream end: a match deferred at the edge is now definite.
        flushed = true;
        if (!held.isEmpty() && !guarding.guards().isEmpty()) held = scan(held, true);
        if (!held.isEmpty()) {
          release(held);
          held = "";
          return;
        }
      }
      done = true;
      // Policies without a guard (schema, grounding, audit) run over what was
      // released. Their refusal comes after the text, as in Python.
      client
          .checkStreamOutput(input, Map.of("output", emitted.toString()), options)
          .orThrow("output");
    }

    private String scan(String text, boolean last) {
      StreamScan scan = client.scanStream(input, text, last, options);
      if (scan.decision() != Decision.ALLOW) {
        throw new ActionBlockedException(scan.refusal(input), "stream");
      }
      return scan.text();
    }

    private void release(String text) {
      emitted.append(text);
      ready.add(text);
    }
  }

  /** Text joins into one output, so a pattern across chunks is caught; anything else stays apart. */
  private static Map<String, Object> assemble(List<Object> chunks) {
    if (!chunks.isEmpty() && chunks.stream().allMatch(c -> c instanceof String)) {
      StringBuilder joined = new StringBuilder();
      chunks.forEach(c -> joined.append((String) c));
      return Map.of("output", joined.toString());
    }
    return Map.of("chunks", chunks);
  }
}
