package io.github.saintparish4.openscript;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * An {@link Agent} that answers with a future: an async model client, a reactive chain. Its
 * answer takes the same two shapes, a {@code Map} or one JSON value.
 */
@FunctionalInterface
public interface AsyncAgent {
  CompletableFuture<?> invoke(Map<String, Object> input);
}
