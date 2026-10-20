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
 * <p>It fails closed: every way of not getting a decision (no server, a wrong key, a policy that
 * raised) is an {@link OpenScriptException}, and the wrappers run nothing without an allow.
 *
 * <p>Thread-safe; build one and share it.
 */
public final class OpenScriptClient {
  private final URI baseUrl;
  private final String apiKey;
  private final Duration timeout;
  private final HttpClient http;

  private OpenScriptClient(Builder builder) {
    String base = Objects.requireNonNull(builder.baseUrl, "baseUrl");
    this.baseUrl = URI.create(base.endsWith("/") ? base : base + "/");
    this.apiKey = Objects.requireNonNull(builder.apiKey, "apiKey");
    this.timeout = builder.timeout;
    this.http =
        builder.http != null
            ? builder.http
            : HttpClient.newBuilder().connectTimeout(builder.timeout).build();
  }

  public static Builder builder() {
    return new Builder();
  }

  /** An agent behind the {@code agent} policies, with default options. */
  public SecureAgent secureAgent(Agent agent) {
    return secureAgent(agent, CheckOptions.defaults());
  }

  /** An agent behind the {@code agent} policies; {@code options} apply to every invoke. */
  public SecureAgent secureAgent(Agent agent, CheckOptions options) {
    return new SecureAgent(this, Objects.requireNonNull(agent, "agent"), options);
  }

  /** A tool behind the {@code tool} policies, with default options. */
  public SecureTool secureTool(String name, Tool tool) {
    return secureTool(name, tool, CheckOptions.defaults());
  }

  /** A tool behind the {@code tool} policies; {@code options} apply to every call. */
  public SecureTool secureTool(String name, Tool tool, CheckOptions options) {
    return new SecureTool(this, name, Objects.requireNonNull(tool, "tool"), options);
  }

  /** The input phase for an agent: what it is about to be given. */
  public GuardResult checkInput(Map<String, ?> input, CheckOptions options) {
    return guard("input", "invoke", input, null, options);
  }

  /** The output phase for an agent: what it was given (as checked) and what it returned. */
  public GuardResult checkOutput(
      Map<String, ?> input, Map<String, ?> output, CheckOptions options) {
    return guard("output", "invoke", input, Objects.requireNonNull(output, "output"), options);
  }

  /** The input phase for a tool: its name and the arguments it is about to be called with. */
  public GuardResult checkToolCall(String name, Map<String, ?> args, CheckOptions options) {
    return guard("input", "tool_call", toolInput(name, args), null, options);
  }

  /** The output phase for a tool: the call (as checked) and what it returned. */
  public GuardResult checkToolResult(
      String name, Map<String, ?> args, Object result, CheckOptions options) {
    Map<String, Object> output = new LinkedHashMap<>();
    output.put("output", result);
    return guard("output", "tool_call", toolInput(name, args), output, options);
  }

  /** Approvals waiting for a person. */
  public List<Approval> pendingApprovals() {
    Map<String, Object> body = asMap(send("GET", "v1/approvals", null));
    List<Approval> approvals = new ArrayList<>();
    for (Object record : asList(body.get("approvals"))) {
      approvals.add(approval(asMap(record)));
    }
    return approvals;
  }

  /**
   * Approve or deny a pending approval.
   *
   * @param note the decider's reason, returned to whoever asked
   * @throws OpenScriptException 404 for an unknown id, 409 for one already decided or expired
   */
  public Approval decideApproval(
      String approvalId, boolean approved, String decidedBy, String note) {
    Map<String, Object> request = new LinkedHashMap<>();
    request.put("approved", approved);
    request.put("decided_by", decidedBy == null ? "" : decidedBy);
    request.put("note", note == null ? "" : note);
    return approval(asMap(send("POST", "v1/approvals/" + approvalId + "/decide", request)));
  }

  static Map<String, ?> wrapOutput(Object result) {
    if (result instanceof Map<?, ?> map) {
      Map<String, Object> copy = new LinkedHashMap<>();
      map.forEach((key, value) -> copy.put(String.valueOf(key), value));
      return copy;
    }
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

  private GuardResult guard(
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
    return guardResult(asMap(send("POST", "v1/guard", request)));
  }

  private Object send(String method, String path, Object body) {
    String json;
    try {
      json = body == null ? null : Json.write(body);
    } catch (IllegalArgumentException ex) {
      throw new OpenScriptException("cannot send this as JSON: " + ex.getMessage(), 0, ex);
    }
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

    HttpResponse<String> response;
    try {
      response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    } catch (IOException ex) {
      throw new OpenScriptException("cannot reach " + baseUrl + ": " + ex, 0, ex);
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw new OpenScriptException("interrupted waiting for " + baseUrl, 0, ex);
    }

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

  private static GuardResult guardResult(Map<String, Object> body) {
    Map<String, Double> categories = new LinkedHashMap<>();
    asMap(body.getOrDefault("risk_categories", Map.of()))
        .forEach((key, value) -> categories.put(key, ((Number) value).doubleValue()));
    Object output = body.get("output");
    return new GuardResult(
        Decision.fromWire(string(body, "decision")),
        string(body, "reason"),
        string(body, "blocked_by"),
        string(body, "approval_id"),
        asMap(body.get("input")),
        output == null ? null : asMap(output),
        ((Number) body.getOrDefault("risk_score", 0.0)).doubleValue(),
        categories,
        asMap(body.getOrDefault("findings", Map.of())));
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

  private static String string(Map<String, Object> body, String key) {
    Object value = body.get(key);
    return value == null ? "" : value.toString();
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> asMap(Object value) {
    if (!(value instanceof Map)) {
      throw new OpenScriptException("expected a JSON object from the server, got " + value);
    }
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  private static List<Object> asList(Object value) {
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

    public OpenScriptClient build() {
      return new OpenScriptClient(this);
    }
  }
}
