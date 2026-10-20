package io.github.saintparish4.openscript;

import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** A {@link Tool} that answers with a future. Its arguments and result are JSON values. */
@FunctionalInterface
public interface AsyncTool {
  CompletableFuture<?> call(Map<String, Object> args);
}
