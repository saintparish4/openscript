package io.github.saintparish4.openscript;

import java.util.Map;
import java.util.stream.Stream;

/**
 * An agent that answers in chunks: a streaming model call. Text chunks are {@code String}s;
 * anything else is a structured chunk and has to be a JSON value. The stream is closed when the
 * caller closes the stream it was given.
 */
@FunctionalInterface
public interface StreamingAgent {
  Stream<?> stream(Map<String, Object> input) throws Exception;
}
