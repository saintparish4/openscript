package io.github.saintparish4.openscript;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/**
 * An agent behind the server's {@code agent} policies, called the way Python's {@code
 * SecureAgent} calls one: input policies, then the agent on what they left, then output policies.
 *
 * <pre>{@code
 * SecureAgent agent = client.secureAgent(input -> model.complete((String) input.get("prompt")));
 * String answer = (String) agent.invoke(Map.of("prompt", "Summarise the ticket"));
 *
 * agent.invokeAsync(Map.of("prompt", "Summarise the ticket"))
 *     .thenAccept(answer -> ...);
 * }</pre>
 *
 * <p>Built from a blocking {@link Agent} or an {@link AsyncAgent}; either can be called either
 * way. A blocking agent called through {@link #invokeAsync} runs on the client's executor; an
 * async agent called through {@link #invoke} is waited for.
 *
 * <p>Like the Python one, it sees the input and the final output and nothing between: the tools
 * the agent calls are guarded by wrapping each in a {@link SecureTool}.
 */
public final class SecureAgent {
  private final OpenScriptClient client;
  private final Agent agent;
  private final AsyncAgent asyncAgent;
  private final CheckOptions options;

  SecureAgent(OpenScriptClient client, Agent agent, AsyncAgent asyncAgent, CheckOptions options) {
    this.client = client;
    this.agent = agent;
    this.asyncAgent = asyncAgent;
    this.options = options;
  }

  public Object invoke(Map<String, ?> input) throws Exception {
    return invoke(input, options);
  }

  /**
   * @throws ActionBlockedException a policy refused the input (the agent did not run) or the
   *     output (the agent ran; its answer is withheld), or one is holding the input for approval
   * @throws OpenScriptException the server could not be asked; the agent did not run, or its
   *     answer is withheld
   */
  public Object invoke(Map<String, ?> input, CheckOptions options) throws Exception {
    if (agent == null) {
      return await(invokeAsync(input, options));
    }
    GuardResult checked = client.checkInput(input, options).orThrow("input");
    // What the policies left, not what the caller sent: a redacted secret
    // never reaches the model.
    Object result = agent.invoke(checked.input());

    // The approval was spent on the input. The output is checked on its own.
    GuardResult answered =
        client
            .checkOutput(checked.input(), OpenScriptClient.wrapOutput(result),
                options.withApprovalId(""))
            .orThrow("output");
    return unwrapAnswer(result, answered);
  }

  public CompletableFuture<Object> invokeAsync(Map<String, ?> input) {
    return invokeAsync(input, options);
  }

  /**
   * The same three steps, without blocking a thread on the server or on an async agent. The
   * future fails with what {@link #invoke} would throw, as its cause.
   */
  public CompletableFuture<Object> invokeAsync(Map<String, ?> input, CheckOptions options) {
    return client
        .checkInputAsync(input, options)
        .thenCompose(
            checked -> {
              checked.orThrow("input");
              return run(checked.input())
                  .thenCompose(
                      result ->
                          client
                              .checkOutputAsync(
                                  checked.input(),
                                  OpenScriptClient.wrapOutput(result),
                                  options.withApprovalId(""))
                              .thenApply(answered -> unwrapAnswer(result, answered.orThrow("output"))));
            });
  }

  private CompletableFuture<?> run(Map<String, Object> input) {
    if (asyncAgent != null) {
      CompletableFuture<?> future = asyncAgent.invoke(input);
      return future != null
          ? future
          : CompletableFuture.failedFuture(new IllegalStateException("the agent returned no future"));
    }
    return CompletableFuture.supplyAsync(
        () -> {
          try {
            return agent.invoke(input);
          } catch (RuntimeException ex) {
            throw ex;
          } catch (Exception ex) {
            throw new CompletionException(ex);
          }
        },
        client.executor());
  }

  private static Object unwrapAnswer(Object result, GuardResult answered) {
    return result instanceof Map ? answered.output() : answered.output().get("output");
  }

  /** The future's value, or what made it fail, thrown as itself. */
  static Object await(CompletableFuture<?> future) throws Exception {
    try {
      return future.get();
    } catch (InterruptedException ex) {
      Thread.currentThread().interrupt();
      throw ex;
    } catch (ExecutionException ex) {
      Throwable cause = OpenScriptClient.unwrap(ex);
      if (cause instanceof Exception e) throw e;
      if (cause instanceof Error e) throw e;
      throw ex;
    }
  }
}
