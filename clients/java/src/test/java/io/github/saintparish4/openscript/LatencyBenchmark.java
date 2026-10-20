package io.github.saintparish4.openscript;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

/**
 * What a guarded call costs from Java, against a real server. Not a test: {@code make java-latency}
 * starts the server with {@code server/guard_example.yaml} and runs this.
 *
 * <p>Every timing is wall clock on the client ({@code System.nanoTime()}) around the whole call,
 * with the agent or tool returning at once, so what is measured is the guard. The server's own
 * {@code pipeline_ms} is reported beside it, to separate the policies from HTTP and JSON.
 *
 * <pre>
 * java -cp target/classes:target/test-classes io.github.saintparish4.openscript.LatencyBenchmark \
 *     URL KEY [RUNS] [WARMUP]
 * </pre>
 */
public final class LatencyBenchmark {

  private static final String PROMPT = "Summarise the open tickets for the billing team this week.";

  private LatencyBenchmark() {}

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      System.err.println("usage: LatencyBenchmark URL KEY [RUNS] [WARMUP]");
      System.exit(2);
    }
    int runs = args.length > 2 ? Integer.parseInt(args[2]) : 2000;
    int warmup = args.length > 3 ? Integer.parseInt(args[3]) : 300;
    OpenScriptClient client = OpenScriptClient.builder().baseUrl(args[0]).apiKey(args[1]).build();
    CheckOptions session = CheckOptions.defaults().withSessionId("bench-" + UUID.randomUUID());

    System.out.printf(Locale.ROOT, "Java %s, %d runs after %d warm-up%n%n",
        System.getProperty("java.version"), runs, warmup);
    System.out.println("| Call | Requests | p50 | p95 | p99 | max | server pipeline p50 |");
    System.out.println("|---|---|---|---|---|---|---|");

    double[] pipeline = new double[runs];
    row("checkInput, a clean prompt", 1, time(warmup, runs, i -> {
      GuardResult r = client.checkInput(Map.of("prompt", PROMPT), session);
      if (i >= 0) pipeline[i] = r.pipelineMillis();
    }), pipeline);

    SecureAgent agent = client.secureAgent(in -> "Three tickets are open.", session);
    row("SecureAgent.invoke", 2, time(warmup, runs, i -> agent.invoke(Map.of("prompt", PROMPT))), null);

    SecureTool fetch = client.secureTool("fetch_page", a -> "<p>notes</p>", session);
    Map<String, Object> page = Map.of("url", "https://docs.example.com/notes");
    row("SecureTool.call, allowed", 2, time(warmup, runs, i -> fetch.call(page)), null);

    SecureTool drop = client.secureTool("drop_tables", a -> "", session);
    row("SecureTool.call, refused by the firewall", 1, time(warmup, runs, i -> {
      try {
        drop.call(Map.of());
        throw new IllegalStateException("drop_tables was allowed");
      } catch (ActionBlockedException expected) {
        // the point
      }
    }), null);

    int streamRuns = Math.max(20, runs / 20);
    int streamWarmup = Math.max(5, warmup / 20);
    String answer = "The billing team has three open tickets this week. ".repeat(20);
    for (StreamMode mode : StreamMode.values()) {
      SecureStreamingAgent streaming =
          client.secureStreamingAgent(input -> chunks(answer, 4), session, mode);
      // One run with a counting recorder, to report how many requests a stream makes.
      AtomicInteger requests = new AtomicInteger();
      OpenScriptClient countingClient =
          OpenScriptClient.builder().baseUrl(args[0]).apiKey(args[1])
              .metrics(o -> requests.incrementAndGet()).build();
      SecureStreamingAgent countedAgent =
          countingClient.secureStreamingAgent(input -> chunks(answer, 4), session, mode);
      drain(countedAgent.stream(Map.of("prompt", PROMPT)));
      row(String.format(Locale.ROOT, "stream %s, %d chars in 4-char chunks",
              mode.name().toLowerCase(Locale.ROOT), answer.length()),
          requests.get(),
          time(streamWarmup, streamRuns, i -> drain(streaming.stream(Map.of("prompt", PROMPT)))),
          null);
    }
    SecureStreamingAgent batched =
        client.secureStreamingAgent(input -> chunks(answer, 4), session, StreamMode.GUARDED)
            .withMinRelease(256);
    AtomicInteger batchedRequests = new AtomicInteger();
    OpenScriptClient.builder().baseUrl(args[0]).apiKey(args[1])
        .metrics(o -> batchedRequests.incrementAndGet()).build()
        .secureStreamingAgent(input -> chunks(answer, 4), session, StreamMode.GUARDED)
        .withMinRelease(256)
        .stream(Map.of("prompt", PROMPT)).forEach(c -> {});
    row(String.format(Locale.ROOT, "stream guarded, minRelease 256, %d chars", answer.length()),
        batchedRequests.get(),
        time(streamWarmup, streamRuns, i -> drain(batched.stream(Map.of("prompt", PROMPT)))),
        null);

    System.out.println();
    System.out.println("Throughput of SecureAgent (2 requests per call):");
    System.out.println();
    System.out.println("| How | Calls | Wall time | Calls per second |");
    System.out.println("|---|---|---|---|");
    int calls = runs;
    long start = System.nanoTime();
    for (int i = 0; i < calls; i++) agent.invoke(Map.of("prompt", PROMPT));
    throughput("invoke, one after another", calls, System.nanoTime() - start);
    for (int inFlight : new int[] {4, 16}) {
      start = System.nanoTime();
      Semaphore slots = new Semaphore(inFlight);
      List<CompletableFuture<Object>> futures = new ArrayList<>(calls);
      for (int i = 0; i < calls; i++) {
        slots.acquire();
        futures.add(agent.invokeAsync(Map.of("prompt", PROMPT)).whenComplete((r, e) -> slots.release()));
      }
      CompletableFuture.allOf(futures.toArray(CompletableFuture[]::new)).join();
      throughput("invokeAsync, " + inFlight + " in flight", calls, System.nanoTime() - start);
    }
  }

  @FunctionalInterface
  private interface Call {
    void run(int index) throws Exception;
  }

  /** Milliseconds per run; warm-up runs are called with a negative index and not kept. */
  private static double[] time(int warmup, int runs, Call call) throws Exception {
    for (int i = 0; i < warmup; i++) call.run(-1 - i);
    double[] ms = new double[runs];
    for (int i = 0; i < runs; i++) {
      long start = System.nanoTime();
      call.run(i);
      ms[i] = (System.nanoTime() - start) / 1e6;
    }
    return ms;
  }

  private static void row(String name, int requests, double[] ms, double[] pipeline) {
    double[] sorted = ms.clone();
    Arrays.sort(sorted);
    String server = "";
    if (pipeline != null) {
      double[] p = pipeline.clone();
      Arrays.sort(p);
      server = String.format(Locale.ROOT, "%.2f ms", percentile(p, 0.50));
    }
    System.out.printf(Locale.ROOT, "| %s | %d | %.2f ms | %.2f ms | %.2f ms | %.2f ms | %s |%n",
        name, requests, percentile(sorted, 0.50), percentile(sorted, 0.95),
        percentile(sorted, 0.99), sorted[sorted.length - 1], server);
  }

  /** Nearest rank. */
  private static double percentile(double[] sorted, double q) {
    int rank = (int) Math.ceil(q * sorted.length);
    return sorted[Math.max(0, Math.min(sorted.length - 1, rank - 1))];
  }

  private static void throughput(String how, int calls, long nanos) {
    double seconds = nanos / 1e9;
    System.out.printf(Locale.ROOT, "| %s | %d | %.2f s | %.0f |%n", how, calls, seconds, calls / seconds);
  }

  private static Stream<String> chunks(String text, int size) {
    List<String> out = new ArrayList<>();
    for (int i = 0; i < text.length(); i += size) {
      out.add(text.substring(i, Math.min(text.length(), i + size)));
    }
    return out.stream();
  }

  private static void drain(Stream<Object> stream) {
    try (stream) {
      stream.forEach(chunk -> {});
    }
  }
}
