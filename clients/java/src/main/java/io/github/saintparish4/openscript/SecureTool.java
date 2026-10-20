package io.github.saintparish4.openscript;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * One tool behind the server's {@code tool} policies, as Python's {@code SecureTool}: the
 * firewall, the session rule and approvals sit where the action is.
 *
 * <pre>{@code
 * SecureTool send = client.secureTool("send_email", args -> mailer.send(args));
 * send.call(Map.of("to", "ops@example.com", "body", "done"));
 * send.callAsync(Map.of("to", "ops@example.com", "body", "done")).thenAccept(...);
 * }</pre>
 *
 * <p>A call the policies hold throws {@link ActionBlockedException} with an approval id. Once a
 * person approves it, retry with {@code call(args, options.withApprovalId(id))}; the approval is
 * bound to this tool's name and these exact arguments.
 *
 * <p>An output refusal comes after the tool has run. What is withheld is its result, which is how
 * a tool's output is kept from the model, not how its side effects are undone.
 *
 * <p>Built from a blocking {@link Tool} or an {@link AsyncTool}; either can be called either way.
 */
public final class SecureTool {
  private final OpenScriptClient client;
  private final String name;
  private final Tool tool;
  private final AsyncTool asyncTool;
  private final CheckOptions options;

  SecureTool(
      OpenScriptClient client, String name, Tool tool, AsyncTool asyncTool, CheckOptions options) {
    if (name == null || name.isEmpty()) {
      throw new IllegalArgumentException("a tool needs a name: the rules are written against it");
    }
    this.client = client;
    this.name = name;
    this.tool = tool;
    this.asyncTool = asyncTool;
    this.options = options;
  }

  public String name() {
    return name;
  }

  public Object call(Map<String, ?> args) throws Exception {
    return call(args, options);
  }

  public Object call(Map<String, ?> args, CheckOptions options) throws Exception {
    if (tool == null) {
      return SecureAgent.await(callAsync(args, options));
    }
    GuardResult checked = client.checkToolCall(name, args, options).orThrow("input");
    // The call that runs is the call that was checked, and approved.
    Map<String, Object> runWith = checkedArgs(checked);
    Object result = tool.call(runWith);

    // Reported even when nothing in it will be refused: this is how the
    // session rule learns that a source has been read.
    GuardResult answered =
        client
            .checkToolResult(name, runWith, result, options.withApprovalId(""))
            .orThrow("output");
    return answered.output().get("output");
  }

  public CompletableFuture<Object> callAsync(Map<String, ?> args) {
    return callAsync(args, options);
  }

  /** The same steps without blocking; the future fails with what {@link #call} would throw. */
  public CompletableFuture<Object> callAsync(Map<String, ?> args, CheckOptions options) {
    return client
        .checkToolCallAsync(name, args, options)
        .thenCompose(
            checked -> {
              checked.orThrow("input");
              Map<String, Object> runWith = checkedArgs(checked);
              return run(runWith)
                  .thenCompose(
                      result ->
                          client.checkToolResultAsync(
                              name, runWith, result, options.withApprovalId("")))
                  .thenApply(answered -> answered.orThrow("output").output().get("output"));
            });
  }

  private CompletableFuture<?> run(Map<String, Object> args) {
    if (asyncTool != null) {
      CompletableFuture<?> future = asyncTool.call(args);
      return future != null
          ? future
          : CompletableFuture.failedFuture(new IllegalStateException("the tool returned no future"));
    }
    return CompletableFuture.supplyAsync(
        () -> {
          try {
            return tool.call(args);
          } catch (RuntimeException ex) {
            throw ex;
          } catch (Exception ex) {
            throw new CompletionException(ex);
          }
        },
        client.executor());
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> checkedArgs(GuardResult checked) {
    Object args = checked.input().get("args");
    if (!(args instanceof Map)) {
      throw new OpenScriptException("the server returned no arguments for " + name);
    }
    return (Map<String, Object>) args;
  }
}
