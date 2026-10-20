package io.github.saintparish4.openscript;

import java.util.Map;

/**
 * Anything that answers an input: a model call, a framework's agent, a chain.
 *
 * <p>It returns a {@code Map} (checked and returned as an object) or a single JSON value (a
 * {@code String}, number, boolean or list, checked as {@code {"output": value}} and returned
 * unwrapped), the same two shapes Python's {@code SecureAgent} handles.
 */
@FunctionalInterface
public interface Agent {
  Object invoke(Map<String, Object> input) throws Exception;
}
