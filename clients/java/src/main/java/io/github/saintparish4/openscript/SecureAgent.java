package io.github.saintparish4.openscript;

import java.util.Map;

/**
 * An agent behind the server's {@code agent} policies, called the way Python's {@code
 * SecureAgent} calls one: input policies, then the agent on what they left, then output policies.
 *
 * <pre>{@code
 * SecureAgent agent = client.secureAgent(input -> model.complete((String) input.get("prompt")));
 * String answer = (String) agent.invoke(Map.of("prompt", "Summarise the ticket"));
 * }</pre>
 *
 * <p>Like the Python one, it sees the input and the final output and nothing between: the tools
 * the agent calls are guarded by wrapping each in a {@link SecureTool}.
 */
public final class SecureAgent {
  private final OpenScriptClient client;
  private final Agent agent;
  private final CheckOptions options;

  SecureAgent(OpenScriptClient client, Agent agent, CheckOptions options) {
    this.client = client;
    this.agent = agent;
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
    GuardResult checked = client.checkInput(input, options).orThrow("input");
    // What the policies left, not what the caller sent: a redacted secret
    // never reaches the model.
    Object result = agent.invoke(checked.input());

    Map<String, ?> output = OpenScriptClient.wrapOutput(result);
    // The approval was spent on the input. The output is checked on its own.
    GuardResult answered =
        client.checkOutput(checked.input(), output, options.withApprovalId("")).orThrow("output");
    return result instanceof Map ? answered.output() : answered.output().get("output");
  }
}
