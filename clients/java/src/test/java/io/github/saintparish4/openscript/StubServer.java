package io.github.saintparish4.openscript;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/** A local HTTP server that answers each request with what the test's handler returns. */
final class StubServer implements AutoCloseable {

  record Request(String method, String path, Map<String, Object> body) {}

  record Reply(int status, Object body) {
    static Reply ok(Object body) {
      return new Reply(200, body);
    }
  }

  private final HttpServer server;
  private final List<Request> requests = new ArrayList<>();
  private volatile Function<Request, Reply> handler =
      r -> new Reply(500, Map.of("detail", "unscripted"));

  @SuppressWarnings("unchecked")
  StubServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          String raw = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          Request request =
              new Request(
                  exchange.getRequestMethod(),
                  exchange.getRequestURI().getPath(),
                  raw.isEmpty() ? null : (Map<String, Object>) Json.parse(raw));
          synchronized (requests) {
            requests.add(request);
          }
          Reply reply;
          try {
            reply = handler.apply(request);
          } catch (RuntimeException ex) {
            reply = new Reply(500, Map.of("detail", String.valueOf(ex)));
          }
          byte[] bytes = Json.write(reply.body()).getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(reply.status(), bytes.length);
          try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
          }
        });
    server.start();
  }

  void handle(Function<Request, Reply> handler) {
    this.handler = handler;
  }

  List<Request> requests() {
    synchronized (requests) {
      return new ArrayList<>(requests);
    }
  }

  List<Request> requests(String path) {
    return requests().stream().filter(r -> r.path().equals(path)).toList();
  }

  String url() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  OpenScriptClient.Builder client() {
    return OpenScriptClient.builder().baseUrl(url()).apiKey("k").timeout(Duration.ofSeconds(5));
  }

  @Override
  public void close() {
    server.stop(0);
  }

  /** A /v1/guard answer: the decision, with the input and output echoed as given. */
  static Map<String, Object> answer(String decision, Object input, Object output) {
    Map<String, Object> body = new LinkedHashMap<>();
    body.put("decision", decision);
    body.put("reason", decision.equals("allow") ? "" : "because");
    body.put("blocked_by", decision.equals("allow") ? "" : "SomePolicy");
    body.put("approval_id", decision.equals("require_approval") ? "ap-1" : "");
    body.put("input", input);
    body.put("output", decision.equals("allow") ? output : null);
    body.put("risk_score", decision.equals("allow") ? 0.0 : 0.9);
    body.put("risk_categories", Map.of());
    body.put("findings", Map.of());
    body.put("pipeline_ms", 0.25);
    return body;
  }

  /** Allow everything, echoing what was sent. */
  static Reply echo(Request r) {
    return Reply.ok(answer("allow", r.body().get("input"), r.body().get("output")));
  }
}
