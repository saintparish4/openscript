package io.github.saintparish4.openscript;

/**
 * The server could not be asked, or did not answer with a decision: it was unreachable, the API
 * key was wrong, nothing is configured (503), or a policy that fails closed raised (500).
 *
 * <p>Thrown in place of a decision, so {@link SecureAgent} and {@link SecureTool} never run the
 * agent or tool when they see it. A guard that cannot be reached refuses.
 */
public class OpenScriptException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  private final int status;

  public OpenScriptException(String message) {
    this(message, 0, null);
  }

  public OpenScriptException(String message, int status, Throwable cause) {
    super(message, cause);
    this.status = status;
  }

  /** The HTTP status the server answered with, or 0 when there was no answer. */
  public int status() {
    return status;
  }
}
