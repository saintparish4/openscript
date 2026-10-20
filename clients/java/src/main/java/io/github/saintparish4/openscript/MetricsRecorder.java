package io.github.saintparish4.openscript;

/**
 * Told about every request the client makes to {@code /v1/guard}, answered or not.
 *
 * <p>{@link InMemoryMetrics} counts them and writes Prometheus text; implement this to send them
 * somewhere else (Micrometer, OpenTelemetry, logs). It is called on the thread that finished the
 * request, so it has to be thread-safe and quick. If it throws, the throw is logged and the call
 * goes on: a recorder cannot turn an answer into a different one.
 */
@FunctionalInterface
public interface MetricsRecorder {
  void record(Observation observation);
}
