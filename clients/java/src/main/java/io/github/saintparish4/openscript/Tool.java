package io.github.saintparish4.openscript;

import java.util.Map;

/**
 * One tool an agent can call, taking its arguments by name.
 *
 * <p>The arguments it receives are the ones the policies checked, read back from the server, so
 * they arrive as JSON values: integers as {@code Long}, decimals as {@code Double}, objects as
 * {@code Map}, arrays as {@code List}. Its result has to be a JSON value too.
 */
@FunctionalInterface
public interface Tool {
  Object call(Map<String, Object> args) throws Exception;
}
