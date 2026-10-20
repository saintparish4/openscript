package io.github.saintparish4.openscript;

import java.util.Map;

/**
 * One tool behind the server's {@code tool} policies, as Python's {@code SecureTool}: the
 * firewall, the session rule and approvals sit where the action is.
 *
 * <pre>{@code
 * SecureTool send = client.secureTool("send_email", args -> mailer.send(args));
 * send.call(Map.of("to", "ops@example.com", "body", "done"));
 * }</pre>
 *
 * <p>A call the policies hold throws {@link ActionBlockedException} with an approval id. Once a
 * person approves it, retry with {@code call(args, options.withApprovalId(id))}; the approval is
 * bound to this tool's name and these exact arguments.
 *
 * <p>An output refusal comes after the tool has run. What is withheld is its result, which is how
 * a tool's output is kept from the model, not how its side effects are undone.
 */
public final class SecureTool {
  private final OpenScriptClient client;
  private final String name;
  private final Tool tool;
  private final CheckOptions options;

  SecureTool(OpenScriptClient client, String name, Tool tool, CheckOptions options) {
    if (name == null || name.isEmpty()) {
      throw new IllegalArgumentException("a tool needs a name: the rules are written against it");
    }
    this.client = client;
    this.name = name;
    this.tool = tool;
    this.options = options;
  }

  public String name() {
    return name;
  }

  public Object call(Map<String, ?> args) throws Exception {
    return call(args, options);
  }

  @SuppressWarnings("unchecked")
  public Object call(Map<String, ?> args, CheckOptions options) throws Exception {
    GuardResult checked = client.checkToolCall(name, args, options).orThrow("input");
    // The call that runs is the call that was checked, and approved.
    Object checkedArgs = checked.input().get("args");
    if (!(checkedArgs instanceof Map)) {
      throw new OpenScriptException("the server returned no arguments for " + name);
    }
    Map<String, Object> runWith = (Map<String, Object>) checkedArgs;
    Object result = tool.call(runWith);

    // Reported even when nothing in it will be refused: this is how the
    // session rule learns that a source has been read.
    GuardResult answered =
        client
            .checkToolResult(name, runWith, result, options.withApprovalId(""))
            .orThrow("output");
    return answered.output().get("output");
  }
}
