package io.github.saintparish4.openscript;

/** How a streamed answer is checked. Python's {@code StreamOutputMode}, with the same meanings. */
public enum StreamMode {
  /**
   * Collect every chunk, check the whole answer, then deliver it: nothing reaches the caller
   * unscanned. Text arrives as one chunk; structured chunks arrive as the policies left them.
   */
  BUFFER,

  /**
   * Text only. Deliver as it comes, holding back a tail as long as the longest match a stream
   * guard (secrets, PII) can make, so a match is redacted, or the stream refused, before any of it
   * is released. Policies without a guard run over the whole answer at the end, where a refusal
   * still throws. Each release is one request to the server.
   */
  GUARDED,

  /**
   * Deliver every chunk at once, unscanned. The output policies run afterwards over the whole
   * answer, for the record; a refusal throws at the end, after the caller has everything.
   */
  PASSTHROUGH
}
