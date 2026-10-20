package io.github.saintparish4.openscript;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ForkJoinPool;

/**
 * The OpenScript policies, from Java, through the server's {@code /v1/guard} endpoint.
 *
 * <p>The policies are the Python ones, unchanged: the server runs them over each phase of an
 * action that this side runs. Nothing is reimplemented here, so a Java agent is held to exactly
 * what a Python agent with the same config is held to.
 *
 * <pre>{@code
 * OpenScriptClient client = OpenScriptClient.builder()
 *     .baseUrl("http://localhost:8000")
 *     .apiKey(System.getenv("OPENSCRIPT_API_KEY"))
 *     .build();
 *
 * SecureAgent agent = client.secureAgent(input -> model.complete((String) input.get("prompt")));
 * SecureTool send = client.secureTool("send_email", args -> mailer.send(args));
 * }</pre>
 *
 * <p>Every check has a blocking form and an {@code ...Async} form that returns a {@link
 * CompletableFuture}. A failed future's cause is the same exception the blocking form throws.
 *
 * <p>It fails closed: every way of not getting a decision (no server, a wrong key, a policy that
 * raised) is an {@link OpenScriptException}, and the wrappers run nothing without an allow.
 *
 * <p>Thread-safe; build one and share it.
 */
public final class OpenScriptClient {
  private static final System.Logger LOG = System.getLogger(OpenScriptClient.class.getName());

  private final URI baseUrl;
  private final String apiKey;
  private final Duration timeout;
  private final HttpClient http;
  private final Executor executor;
  private final MetricsRecorder metrics;

  private OpenScriptClient(Builder builder) {
    String base = Objects.requireNonNull(builder.baseUrl, "baseUrl");
    this.baseUrl = URI.create(base.endsWith("/") ? base : base + "/");
    this.apiKey = Objects.requireNonNull(builder.apiKey, "apiKey");
    this.timeout = builder.timeout;
    this.executor = builder.executor != null ? builder.executor : ForkJoinPool.commonPool();
    if (builder.http != null) {
      this.http = builder.http;
    } else {
      HttpClient.Builder http = HttpClient.newBuilder().connectTimeout(builder.timeout);
      if (builder.executor != null) http.executor(builder.executor);
      this.http = http.build();
    }
    this.metrics = builder.metrics;
  }

  public static Builder builder() {
    return new Builder();
  }

  // ── Wrappers ──────────────────────────────────────────────────────────────

  /** An agent behind the {@code agent} policies, with default options. */
  public SecureAgent secureAgent(Agent agent) {
    return secureAgent(agent, CheckOptions.defaults());
  }

  /** An agent behind the {@code agent} policies; {@code options} apply to every invoke. */
  public SecureAgent secureAgent(Agent agent, CheckOptions options) {
    return new SecureAgent(this, Objects.requireNonNull(agent, "agent"), null, options);
  }

  /** An agent that answers with a future, behind the {@code agent} policies. */
  public SecureAgent secureAsyncAgent(AsyncAgent agent) {
    return secureAsyncAgent(agent, CheckOptions.defaults());
  }

  public SecureAgent secureAsyncAgent(AsyncAgent agent, CheckOptions options) {
    return new SecureAgent(this, null, Objects.requireNonNull(agent, "agent"), options);
  }

  /** An agent that streams its answer, behind the {@code agent} policies, buffered by default. */
  public SecureStreamingAgent secureStreamingAgent(StreamingAgent agent) {
    return secureStreamingAgent(agent, CheckOptions.defaults(), StreamMode.BUFFER);
  }

  public SecureStreamingAgent secureStreamingAgent(
      StreamingAgent agent, CheckOptions options, StreamMode mode) {
    return new SecureStreamingAgent(
        this, Objects.requireNonNull(agent, "agent"), options, Objects.requireNonNull(mode), 0);
  }

  /** A tool behind the {@code tool} policies, with default options. */
  public SecureTool secureTool(String name, Tool tool) {
    return secureTool(name, tool, CheckOptions.defaults());
  }

  /** A tool behind the {@code tool} policies; {@code options} apply to every call. */
  public SecureTool secureTool(String name, Tool tool, CheckOptions options) {
    return new SecureTool(this, name, Objects.requireNonNull(tool, "tool"), null, options);
  }

  /** A tool that answers with a future, behind the {@code tool} policies. */
  public SecureTool secureAsyncTool(String name, AsyncTool tool) {
    return secureAsyncTool(name, tool, CheckOptions.defaults());
  }

  public SecureTool secureAsyncTool(String name, AsyncTool tool, CheckOptions options) {
    return new SecureTool(this, name, null, Objects.requireNonNull(tool, "tool"), options);
  }

  // ── Checks ────────────────────────────────────────────────────────────────

  /** The input phase for an agent: what it is about to be given. */
  public GuardResult checkInput(Map<String, ?> input, CheckOptions options) {
    return guard("input", "invoke", input, null, options).result();
  }

  public CompletableFuture<GuardResult> checkInputAsync(
      Map<String, ?> input, CheckOptions options) {
    return guardAsync("input", "invoke", input, null, options).thenApply(Answer::result);
  }

  /** The output phase for an agent: what it was given (as checked) and what it returned. */
  public GuardResult checkOutput(
      Map<String, ?> input, Map<String, ?> output, CheckOptions options) {
    return guard("output", "invoke", input, Objects.requireNonNull(output, "output"), options)
        .result();
  }

  public CompletableFuture<GuardResult> checkOutputAsync(
      Map<String, ?> input, Map<String, ?> output, CheckOptions options) {
    return guardAsync("output", "invoke", input, Objects.requireNonNull(output, "output"), options)
        .thenApply(Answer::result);
  }

  /** The input phase for a tool: its name and the arguments it is about to be called with. */
  public GuardResult checkToolCall(String name, Map<String, ?> args, CheckOptions options) {
    return guard("input", "tool_call", toolInput(name, args), null, options).result();
  }

  public CompletableFuture<GuardResult> checkToolCallAsync(
      String name, Map<String, ?> args, CheckOptions options) {
    return guardAsync("input", "tool_call", toolInput(name, args), null, options)
        .thenApply(Answer::result);
  }

  /** The output phase for a tool: the call (as checked) and what it returned. */
  public GuardResult checkToolResult(
      String name, Map<String, ?> args, Object result, CheckOptions options) {
    return guard("output", "tool_call", toolInput(name, args), wrap(result), options).result();
  }

  public CompletableFuture<GuardResult> checkToolResultAsync(
      String name, Map<String, ?> args, Object result, CheckOptions options) {
    return guardAsync("output", "tool_call", toolInput(name, args), wrap(result), options)
        .thenApply(Answer::result);
  }

  // ── Approvals ─────────────────────────────────────────────────────────────

  /** Approvals waiting for a person. */
  public List<Approval> pendingApprovals() {
    return approvals(send("GET", "v1/approvals", encode(null)));
  }

  public CompletableFuture<List<Approval>> pendingApprovalsAsync() {
    return sendAsync("GET", "v1/approvals", null).thenApply(OpenScriptClient::approvals);
  }

  /**
   * Approve or deny a pending approval.
   *
   * @param note the decider's reason, returned to whoever asked
   * @throws OpenScriptException 404 for an unknown id, 409 for one already decided or expired
   */
  public Approval decideApproval(
      String approvalId, boolean approved, String decidedBy, String note) {
    return approval(
        asMap(send("POST", decidePath(approvalId), encode(decision(approved, decidedBy, note)))));
  }

  public CompletableFuture<Approval> decideApprovalAsync(
      String approvalId, boolean approved, String decidedBy, String note) {
    return sendAsync("POST", decidePath(approvalId), decision(approved, decidedBy, note))
        .thenApply(body -> approval(asMap(body)));
  }

  // ── Streaming (used by SecureStreamingAgent) ──────────────────────────────

  /** The input phase of a stream: the result, and the guards' names and window. */
  Answer checkStreamInput(Map<String, ?> input, CheckOptions options) {
    return guard("input", "stream", input, null, options);
  }

  GuardResult checkStreamOutput(
      Map<String, ?> input, Map<String, ?> output, CheckOptions options) {
    return guard("output", "stream", input, output, options).result();
  }

  /** One pass of the stream guards over the text being held back. */
  StreamScan scanStream(
      Map<String, ?> input, String text, boolean last, CheckOptions options) {
    Map<String, Object> request = new LinkedHashMap<>();
    request.put("session_id", options.sessionId());
    request.put("agent_id", options.agentId());
    request.put("input", input);
    request.put("text", text);
    request.put("final", last);
    long start = System.nanoTime();
    try {
      Map<String, Object> body = asMap(send("POST", "v1/guard/stream", encode(request)));
      StreamScan scan = StreamScan.from(body, System.nanoTime() - start);
      observe(scan.observation());
      return scan;
    } catch (OpenScriptException ex) {
      observe(failure("stream", "scan", ex, System.nanoTime() - start));
      throw ex;
    }
  }

  // ── Internals ─────────────────────────────────────────────────────────────

  /** A guard result and the body it came from, for the fields only streaming reads. */
  record Answer(GuardResult result, Map<String, Object> body) {}

  Executor executor() {
    return executor;
  }

  static Map<String, Object> wrapOutput(Object result) {
    if (result instanceof Map<?, ?> map) {
      Map<String, Object> copy = new LinkedHashMap<>();
      map.forEach((key, value) -> copy.put(String.valueOf(key), value));
      return copy;
    }
    return wrap(result);
  }

  private static Map<String, Object> wrap(Object result) {
    Map<String, Object> wrapped = new LinkedHashMap<>();
    wrapped.put("output", result);
    return wrapped;
  }

  private static Map<String, Object> toolInput(String name, Map<String, ?> args) {
    Map<String, Object> input = new LinkedHashMap<>();
    input.put("name", Objects.requireNonNull(name, "name"));
    input.put("args", args == null ? Map.of() : args);
    return input;
  }

  private static String decidePath(String approvalId) {
    return "v1/approvals/" + Objects.requireNonNull(approvalId, "approvalId") + "/decide";
  }

  private static Map<String, Object> decision(boolean approved, String decidedBy, String note) {
    Map<String, Object> request = new LinkedHashMap<>();
    request.put("approved", approved);
    request.put("decided_by", decidedBy == null ? "" : decidedBy);
    request.put("note", note == null ? "" : note);
    return request;
  }

  private static Map<String, Object> guardRequest(
      String phase,
      String action,
      Map<String, ?> input,
      Map<String, ?> output,
      CheckOptions options) {
    Objects.requireNonNull(input, "input");
    Objects.requireNonNull(options, "options");
    Map<String, Object> request = new LinkedHashMap<>();
    request.put("phase", phase);
    request.put("action", action);
    request.put("session_id", options.sessionId());
    request.put("agent_id", options.agentId());
    request.put("input", input);
    if (output != null) request.put("output", output);
    if (options.role() != null) request.put("role", options.role());
    request.put("approval_id", options.approvalId());
    return request;
  }

  private Answer guard(
      String phase,
      String action,
      Map<String, ?> input,
      Map<String, ?> output,
      CheckOptions options) {
    Map<String, Object> request = guardRequest(phase, action, input, output, options);
    long start = System.nanoTime();
    try {
      Map<String, Object> body = asMap(send("POST", "v1/guard", encode(request)));
      Answer answer = new Answer(guardResult(body, System.nanoTime() - start), body);
      observe(observation(action, phase, answer.result()));
      return answer;
    } catch (OpenScriptException ex) {
      observe(failure(action, phase, ex, System.nanoTime() - start));
      throw ex;
    }
  }

  private CompletableFuture<Answer> guardAsync(
      String phase,
      String action,
      Map<String, ?> input,
      Map<String, ?> output,
      CheckOptions options) {
    Map<String, Object> request;
    try {
      request = guardRequest(phase, action, input, output, options);
    } catch (RuntimeException ex) {
      return CompletableFuture.failedFuture(ex);
    }
    long start = System.nanoTime();
    return sendAsync("POST", "v1/guard", request)
        .thenApply(
            body -> {
              Map<String, Object> map = asMap(body);
              return new Answer(guardResult(map, System.nanoTime() - start), map);
            })
        .whenComplete(
            (answer, error) -> {
              if (answer != null) {
                observe(observation(action, phase, answer.result()));
              } else if (unwrap(error) instanceof OpenScriptException ex) {
                observe(failure(action, phase, ex, System.nanoTime() - start));
              }
            });
  }

  private static String encode(Object body) {
    if (body == null) return null;
    try {
      return Json.write(body);
    } catch (IllegalArgumentException ex) {
      throw new OpenScriptException("cannot send this as JSON: " + ex.getMessage(), 0, ex);
    }
  }

  private HttpRequest request(String method, String path, String json) {
    HttpRequest.Builder request =
        HttpRequest.newBuilder(baseUrl.resolve(path))
            .timeout(timeout)
            .header("X-API-KEY", apiKey)
            .header("Accept", "application/json");
    if (json == null) {
      request.method(method, HttpRequest.BodyPublishers.noBody());
    } else {
      request
          .header("Content-Type", "application/json")
          .method(method, HttpRequest.BodyPublishers.ofString(json));
    }
    return request.build();
  }

  private Object send(String method, String path, String json) {
    HttpResponse<String> response;
    try {
      response = http.send(request(method, path, json), HttpResponse.BodyHandlers.ofString());
    } catch (IOException ex) {
      throw unreachable(ex);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new OpenScriptException("interrupted waiting for " + baseUrl, 0, ex);
    }
    return read(method, path, response);
  }

  private CompletableFuture<Object> sendAsync(String method, String path, Object body) {
    String json;
    try {
      json = encode(body);
    } catch (OpenScriptException ex) {
      return CompletableFuture.failedFuture(ex);
    }
    return http.sendAsync(request(method, path, json), HttpResponse.BodyHandlers.ofString())
        .handle(
            (response, error) -> {
              if (error != null) {
                Throwable cause = unwrap(error);
                throw cause instanceof IOException io
                    ? unreachable(io)
                    : new OpenScriptException("request to " + baseUrl + " failed", 0, cause);
              }
              return read(method, path, response);
            });
  }

  private OpenScriptException unreachable(IOException ex) {
    return new OpenScriptException("cannot reach " + baseUrl + ": " + ex, 0, ex);
  }

  private static Object read(String method, String path, HttpResponse<String> response) {
    if (response.statusCode() != 200) {
      throw new OpenScriptException(
          method + " /" + path + " answered " + response.statusCode() + ": "
              + detail(response.body()),
          response.statusCode(),
          null);
    }
    try {
      return Json.parse(response.body());
    } catch (IllegalArgumentException ex) {
      throw new OpenScriptException("unreadable answer from /" + path, 200, ex);
    }
  }

  static Throwable unwrap(Throwable error) {
    while ((error instanceof CompletionException || error instanceof ExecutionException)
        && error.getCause() != null) {
      error = error.getCause();
    }
    return error;
  }

  private static String detail(String body) {
    try {
      Object parsed = Json.parse(body);
      if (parsed instanceof Map<?, ?> map && map.get("detail") != null) {
        return String.valueOf(map.get("detail"));
      }
    } catch (IllegalArgumentException ignored) {
      // not JSON; show it as it came
    }
    return body;
  }

  private void observe(Observation observation) {
    if (metrics == null) return;
    try {
      metrics.record(observation);
    } catch (RuntimeException ex) {
      LOG.log(System.Logger.Level.WARNING, "metrics recorder failed; the call goes on", ex);
    }
  }

  private static Observation observation(String action, String phase, GuardResult r) {
    return new Observation(
        action,
        phase,
        200,
        r.decision(),
        r.blockedBy(),
        r.riskScore(),
        r.riskCategories(),
        r.findings(),
        r.pipelineMillis(),
        r.roundTripNanos());
  }

  private static Observation failure(
      String action, String phase, OpenScriptException ex, long nanos) {
    // An unreadable 200 is still no decision.
    int status = ex.status() == 200 ? 0 : ex.status();
    return new Observation(action, phase, status, null, "", 0, Map.of(), Map.of(), 0, nanos);
  }

  private static GuardResult guardResult(Map<String, Object> body, long nanos) {
    Map<String, Double> categories = new LinkedHashMap<>();
    asMap(body.getOrDefault("risk_categories", Map.of()))
        .forEach((key, value) -> categories.put(key, number(value)));
    Object output = body.get("output");
    return new GuardResult(
        Decision.fromWire(string(body, "decision")),
        string(body, "reason"),
        string(body, "blocked_by"),
        string(body, "approval_id"),
        asMap(body.get("input")),
        output == null ? null : asMap(output),
        number(body.getOrDefault("risk_score", 0.0)),
        categories,
        asMap(body.getOrDefault("findings", Map.of())),
        number(body.getOrDefault("pipeline_ms", 0.0)),
        nanos);
  }

  private static List<Approval> approvals(Object body) {
    List<Approval> approvals = new ArrayList<>();
    for (Object record : asList(asMap(body).get("approvals"))) {
      approvals.add(approval(asMap(record)));
    }
    return approvals;
  }

  private static Approval approval(Map<String, Object> record) {
    return new Approval(
        string(record, "approval_id"),
        string(record, "session_id"),
        string(record, "agent_id"),
        string(record, "action"),
        string(record, "reason"),
        string(record, "status"),
        string(record, "created_at"),
        string(record, "expires_at"),
        string(record, "decided_by"),
        string(record, "decision_note"));
  }

  static double number(Object value) {
    if (!(value instanceof Number n)) {
      throw new OpenScriptException("expected a number from the server, got " + value);
    }
    return n.doubleValue();
  }

  static String string(Map<String, Object> body, String key) {
    Object value = body.get(key);
    return value == null ? "" : value.toString();
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> asMap(Object value) {
    if (!(value instanceof Map)) {
      throw new OpenScriptException("expected a JSON object from the server, got " + value);
    }
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  static List<Object> asList(Object value) {
    if (!(value instanceof List)) {
      throw new OpenScriptException("expected a JSON array from the server, got " + value);
    }
    return (List<Object>) value;
  }

  public static final class Builder {
    private String baseUrl;
    private String apiKey;
    private Duration timeout = Duration.ofSeconds(10);
    private HttpClient http;
    private Executor executor;
    private MetricsRecorder metrics;

    private Builder() {}

    /** Where the server is, e.g. {@code http://localhost:8000}. */
    public Builder baseUrl(String baseUrl) {
      this.baseUrl = baseUrl;
      return this;
    }

    /** The server's {@code OPENSCRIPT_API_KEY}, sent as {@code X-API-KEY}. */
    public Builder apiKey(String apiKey) {
      this.apiKey = apiKey;
      return this;
    }

    /** Per request, and for connecting. Default 10 seconds. */
    public Builder timeout(Duration timeout) {
      this.timeout = Objects.requireNonNull(timeout, "timeout");
      return this;
    }

    /** A preconfigured JDK client (proxy, TLS, executor). */
    public Builder httpClient(HttpClient http) {
      this.http = http;
      return this;
    }

    /**
     * Where the async forms run a blocking {@link Agent} or {@link Tool}, and, unless {@link
     * #httpClient} is given, the HTTP client's executor. Default: the common fork-join pool.
     */
    public Builder executor(Executor executor) {
      this.executor = executor;
      return this;
    }

    /** Told about every request; see {@link InMemoryMetrics}. Default: none. */
    public Builder metrics(MetricsRecorder metrics) {
      this.metrics = metrics;
      return this;
    }

    public OpenScriptClient build() {
      return new OpenScriptClient(this);
    }
  }
}
