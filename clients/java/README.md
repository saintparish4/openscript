# OpenScript Java client

A Java agent and its tools, behind the same policies a Python agent gets. The policies are not reimplemented here: they are the Python ones, run by the OpenScript server's `/v1/guard` endpoint. A Java agent is held to exactly what a Python agent with the same config is held to, and a fix to a policy reaches both at once.

Java 17. No dependencies beyond the JDK. Not published to Maven Central: build it from source.

```bash
cd clients/java && mvn install        # io.github.saintparish4:openscript-client:0.1.0 in ~/.m2
```

## How it works

In Python, `SecureAgent` runs the policies' before phase, the agent, then the after phase, in one process. Java cannot hand the server its agent, so the two phases are two requests:

1. `POST /v1/guard` with `phase: "input"`: the policies check (and may redact) the input.
2. The client runs the agent or tool on the input **as the server returned it**, so a masked secret never reaches the model.
3. `POST /v1/guard` with `phase: "output"`: the policies check (and may redact) what came back.

The server holds two lists, as a Python program builds two: `agent` (what `SecureAgent` would run, action `invoke`) and `tool` (what each `SecureTool` would run, action `tool_call`). See [`server/guard_example.yaml`](../../server/guard_example.yaml). Start the server with it:

```bash
docker compose up -d && alembic upgrade head
export OPENSCRIPT_API_KEY=change-me
OPENSCRIPT_GUARD_CONFIG=server/guard_example.yaml uvicorn server.app:app
```

## Use

```java
import io.github.saintparish4.openscript.*;

OpenScriptClient client = OpenScriptClient.builder()
    .baseUrl("http://localhost:8000")
    .apiKey(System.getenv("OPENSCRIPT_API_KEY"))
    .build();

// An agent: input policies, the agent on what they left, output policies.
SecureAgent agent = client.secureAgent(
    input -> model.complete((String) input.get("prompt")),
    CheckOptions.defaults().withSessionId(sessionId));
String answer = (String) agent.invoke(Map.of("prompt", userText));

// A tool: the firewall, the session rule and approvals, per call.
SecureTool send = client.secureTool("send_email", args -> mailer.send(args),
    CheckOptions.defaults().withSessionId(sessionId));
send.call(Map.of("to", "ops@example.com", "body", "done"));
```

An agent returns a `Map` (checked and returned as an object) or one JSON value (checked as `{"output": value}` and returned unwrapped), the two shapes the Python `SecureAgent` handles.

A tool receives its arguments as the policies left them, read back from the server, so they arrive as JSON values: integers as `Long`, decimals as `Double`, objects as `Map`, arrays as `List`. Its result has to be a JSON value too.

### Refusals and approvals

A refusal throws `ActionBlockedException`, carrying the reason, the policy (`blockedBy()`, by its Python class name), the risk score and the phase. After a refusal in the `"output"` phase a tool has already run: what is withheld is its result, not its side effects.

A held call throws the same exception with `requiresApproval()` true and an `approvalId()`. A person decides it, and the same call is retried with the id:

```java
try {
  wire.call(call);
} catch (ActionBlockedException e) {
  if (!e.requiresApproval()) throw e;
  // A person decides, here or through the dashboard or POST /v1/approvals/{id}/decide:
  client.decideApproval(e.approvalId(), true, "ops@example.com", "amount checked");
  wire.call(call, options.withApprovalId(e.approvalId()));
}
```

The approval is single-use, expires after an hour, and is bound to the tool's name and exact arguments, including their types: `10` and `10.0` are two different calls. `client.pendingApprovals()` lists what is waiting.

### Async

Every check has an `...Async` form returning a `CompletableFuture`, and so do the wrappers: `invokeAsync`, `callAsync`, `pendingApprovalsAsync`, `decideApprovalAsync`. A failed future's cause is the exception the blocking form would throw.

```java
// An agent that answers with a future: nothing blocks on the model or the server.
SecureAgent agent = client.secureAsyncAgent(input -> asyncModel.complete(input));
agent.invokeAsync(Map.of("prompt", userText))
    .thenAccept(answer -> reply(answer))
    .exceptionally(error -> refuse(error.getCause()));
```

Either kind of agent or tool can be called either way. A blocking `Agent` or `Tool` called through `invokeAsync`/`callAsync` runs on the client's executor (`builder().executor(...)`, the common fork-join pool by default); an `AsyncAgent` called through `invoke` is waited for.

### Streaming

`secureStreamingAgent` takes an agent that returns a `java.util.stream.Stream` of chunks and gives back a stream of what the policies let through, with Python's three modes:

```java
SecureStreamingAgent agent = client.secureStreamingAgent(
    input -> model.streamText((String) input.get("prompt")),
    CheckOptions.defaults(), StreamMode.GUARDED);

try (Stream<Object> answer = agent.stream(Map.of("prompt", userText))) {
  answer.forEach(System.out::print);
}
```

- `BUFFER` (the default): every chunk is collected and the whole answer checked before any of it is delivered. Text arrives as one chunk.
- `GUARDED`: text arrives as it streams, minus a held-back tail as long as the longest match a stream guard can make (512 characters with the example config, from the secrets guard). The server scans what is held before anything is released, so a secret or an email split across chunks is redacted, and a private key refuses the stream before any of it goes out. The policies without a guard run over the whole answer at the end.
- `PASSTHROUGH`: chunks are delivered unscanned; the output policies run afterwards for the record, and a refusal throws after the caller has everything.

The input is checked when `stream()` is called, so a refused prompt throws there and the agent never starts. Refusals of the output throw from the stream as it is consumed. Close the stream to close the agent's.

In `GUARDED` mode each release is a request to the server: once the window is full, that is one per chunk. `withMinRelease(n)` holds back `n` characters more before each scan: fewer requests, larger and later pieces, the same guarantee. Measured below: 130 requests and 196 ms for a 1,020-character answer by default, 4 requests and 9.3 ms with `withMinRelease(256)`.

Streaming is pull-based and blocks the consuming thread while the server is asked; there is no async form of it.

### Metrics

Pass a `MetricsRecorder` to the builder and it is told about every request: action, phase, decision or HTTP status, risk, findings, the server's pipeline time and the client's round trip. `InMemoryMetrics` counts them and writes Prometheus text, with the families of Python's `MetricsRecorder` under an `openscript_client_` prefix (`checks_total`, `errors_total`, `check_risk_score`, `policy_violations_total`, `injections_flagged_total`, `tool_calls_denied_total`, `pii_redacted_total`) plus `round_trip_seconds` and `pipeline_seconds`:

```java
InMemoryMetrics metrics = new InMemoryMetrics();
OpenScriptClient client = OpenScriptClient.builder()
    .baseUrl(url).apiKey(key).metrics(metrics).build();
// serve metrics.toPrometheus() from your own /metrics endpoint
```

Each `GuardResult` also carries `pipelineMillis()` (the policies, timed by the server) and `roundTripNanos()` (the whole request, timed here). A recorder that throws is logged and ignored: it cannot change an answer.

### Without the wrappers

`checkInput`, `checkOutput`, `checkToolCall` and `checkToolResult` each make one request and return a `GuardResult` (decision, reason, the input and output as the policies left them, risk, and every policy's findings). `result.orThrow(phase)` turns a refusal into the exception. Use them when the agent is not one call, but run the output phase for every tool that ran: that is how the session rule learns a source was read.

## What to know

- **It fails closed.** No server, a wrong key, nothing configured (503), a policy that failed closed (500), an unknown decision, or an argument that is not JSON: each is an `OpenScriptException`, thrown before the agent or tool runs.
- **Two round trips per guarded call**, one per phase: 4.7 ms p50 for an agent call on the local box, measured below.
- **The session rule's memory is in the server process.** What a session has read is remembered per session id by the one `SessionTaintPolicy` the server built. Run one worker, or sessions will forget.
- **Approvals live in the server's store**, shared with `/v1/approvals`: in memory unless the server has `REDIS_URL`.
- **It sees each call, not the agent's reasoning.** Like the Python wrappers, it sees an agent's input and final output, and each tool call you wrap. A tool you do not wrap is not guarded.
- **The approval used on the input is spent there.** The output phase is checked on its own. None of the built-in policies asks for approval on the way out.

## Speed

`make java-latency` times guarded calls against the real server with `guard_example.yaml`. On 2026-10-20, with the server (one worker), its Postgres and the client all on one WSL box (AMD Ryzen 5 5625U), 2,000 runs after 300 warm-up:

| Call | Requests | p50 | p95 |
|---|---|---|---|
| `checkInput` (1.3 ms of it in the policies) | 1 | 3.4 ms | 5.2 ms |
| `SecureAgent.invoke` | 2 | 4.7 ms | 6.6 ms |
| `SecureTool.call`, allowed | 2 | 3.3 ms | 4.4 ms |
| Guarded stream, 1,020 characters in 4-character chunks | 130 | 196 ms | 235 ms |
| The same with `withMinRelease(256)` | 4 | 9.3 ms | 12.1 ms |

Over a network, add the network's round trip per request. The method and the full table are in [`docs/metrics.md`](../../docs/metrics.md#the-java-client-per-call).

## Tests

```bash
make java-test     # the client against a stub server
make java-live     # against the real policies: starts the server with guard_example.yaml (needs Postgres)
make java-latency  # the timings above (needs Postgres; RUNS=2000 WARMUP=300)
```

`make java-live` fails if the live tests were skipped. CI runs it with a Postgres service.
