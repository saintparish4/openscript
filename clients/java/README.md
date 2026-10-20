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

### Without the wrappers

`checkInput`, `checkOutput`, `checkToolCall` and `checkToolResult` each make one request and return a `GuardResult` (decision, reason, the input and output as the policies left them, risk, and every policy's findings). `result.orThrow(phase)` turns a refusal into the exception. Use them when the agent is not one call, but run the output phase for every tool that ran: that is how the session rule learns a source was read.

## What to know

- **It fails closed.** No server, a wrong key, nothing configured (503), a policy that failed closed (500), an unknown decision, or an argument that is not JSON: each is an `OpenScriptException`, thrown before the agent or tool runs.
- **Two round trips per guarded call**, one per phase.
- **The session rule's memory is in the server process.** What a session has read is remembered per session id by the one `SessionTaintPolicy` the server built. Run one worker, or sessions will forget.
- **Approvals live in the server's store**, shared with `/v1/approvals`: in memory unless the server has `REDIS_URL`.
- **It sees each call, not the agent's reasoning.** Like the Python wrappers, it sees an agent's input and final output, and each tool call you wrap. A tool you do not wrap is not guarded.
- **The approval used on the input is spent there.** The output phase is checked on its own. None of the built-in policies asks for approval on the way out.

## Tests

```bash
make java-test     # the client against a stub server
make java-live     # against the real policies: starts the server with guard_example.yaml (needs Postgres)
```

`make java-live` fails if the live tests were skipped. CI runs it with a Postgres service.
