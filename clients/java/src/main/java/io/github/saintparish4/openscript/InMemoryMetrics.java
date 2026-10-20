package io.github.saintparish4.openscript;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.concurrent.atomic.DoubleAdder;
import java.util.concurrent.atomic.LongAdder;

/**
 * Counters and histograms over every request the client makes, kept in memory and written as
 * Prometheus text. The Java side of Python's {@code MetricsRecorder}, with the same families
 * under an {@code openscript_client_} prefix, plus what only a client can see: the round trip.
 *
 * <pre>{@code
 * InMemoryMetrics metrics = new InMemoryMetrics();
 * OpenScriptClient client = OpenScriptClient.builder()...metrics(metrics).build();
 * // serve metrics.toPrometheus() from your /metrics endpoint
 * }</pre>
 *
 * <p>Families:
 *
 * <ul>
 *   <li>{@code openscript_client_checks_total{action,phase,decision}}: every answered request
 *   <li>{@code openscript_client_errors_total{action,phase,status}}: every request with no answer
 *   <li>{@code openscript_client_check_risk_score}: the risk score of each answered check
 *   <li>{@code openscript_client_policy_violations_total{policy}}: one per category with risk > 0
 *   <li>{@code openscript_client_injections_flagged_total}: the injection scorer flagged the input
 *   <li>{@code openscript_client_tool_calls_denied_total}: the tool firewall refused a call
 *   <li>{@code openscript_client_pii_redacted_total}: PII was redacted from an output
 *   <li>{@code openscript_client_round_trip_seconds{action,phase}}: the whole request, client side
 *   <li>{@code openscript_client_pipeline_seconds{action,phase}}: the policies, server side
 * </ul>
 *
 * <p>Thread-safe. Counts only grow; there is no reset.
 */
public final class InMemoryMetrics implements MetricsRecorder {

  /** Seconds. From half a millisecond, a local check, to ten seconds, a timeout. */
  static final double[] LATENCY_BUCKETS = {
    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
  };

  /** Python's {@code _RISK_BUCKETS}. */
  static final double[] RISK_BUCKETS = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0};

  private final ConcurrentMap<List<String>, LongAdder> checks = new ConcurrentHashMap<>();
  private final ConcurrentMap<List<String>, LongAdder> errors = new ConcurrentHashMap<>();
  private final ConcurrentMap<String, LongAdder> violations = new ConcurrentHashMap<>();
  private final LongAdder injectionsFlagged = new LongAdder();
  private final LongAdder toolCallsDenied = new LongAdder();
  private final LongAdder piiRedacted = new LongAdder();
  private final Histogram risk = new Histogram(RISK_BUCKETS);
  private final ConcurrentMap<List<String>, Histogram> roundTrip = new ConcurrentHashMap<>();
  private final ConcurrentMap<List<String>, Histogram> pipeline = new ConcurrentHashMap<>();

  @Override
  public void record(Observation o) {
    List<String> where = List.of(o.action(), o.phase());
    histogram(roundTrip, where).observe(o.roundTripNanos() / 1e9);
    if (!o.answered()) {
      counter(errors, List.of(o.action(), o.phase(), Integer.toString(o.status()))).increment();
      return;
    }
    counter(checks, List.of(o.action(), o.phase(), wire(o.decision()))).increment();
    histogram(pipeline, where).observe(o.pipelineMillis() / 1000);
    risk.observe(o.riskScore());
    o.riskCategories()
        .forEach(
            (category, value) -> {
              if (value != null && value > 0) {
                violations.computeIfAbsent(category, k -> new LongAdder()).increment();
              }
            });
    if (Boolean.TRUE.equals(field(o.findings(), "threat", "flagged"))) {
      injectionsFlagged.increment();
    }
    if (Boolean.FALSE.equals(field(o.findings(), "tool_firewall", "allowed"))) {
      toolCallsDenied.increment();
    }
    if (Boolean.TRUE.equals(field(o.findings(), "pii", "redacted"))) {
      piiRedacted.increment();
    }
  }

  /** Answered requests with this action, phase and decision. */
  public long checks(String action, String phase, Decision decision) {
    LongAdder count = checks.get(List.of(action, phase, wire(decision)));
    return count == null ? 0 : count.sum();
  }

  /** Requests with this action and phase that got no decision, whatever the status. */
  public long errors(String action, String phase) {
    return errors.entrySet().stream()
        .filter(e -> e.getKey().get(0).equals(action) && e.getKey().get(1).equals(phase))
        .mapToLong(e -> e.getValue().sum())
        .sum();
  }

  public long policyViolations(String category) {
    LongAdder count = violations.get(category);
    return count == null ? 0 : count.sum();
  }

  public long injectionsFlagged() {
    return injectionsFlagged.sum();
  }

  public long toolCallsDenied() {
    return toolCallsDenied.sum();
  }

  public long piiRedacted() {
    return piiRedacted.sum();
  }

  /** The round trips of requests with this action and phase, answered or not. */
  public HistogramSnapshot roundTrip(String action, String phase) {
    Histogram h = roundTrip.get(List.of(action, phase));
    return h == null ? HistogramSnapshot.empty(LATENCY_BUCKETS) : h.snapshot();
  }

  /** The server's pipeline time for answered requests with this action and phase. */
  public HistogramSnapshot pipeline(String action, String phase) {
    Histogram h = pipeline.get(List.of(action, phase));
    return h == null ? HistogramSnapshot.empty(LATENCY_BUCKETS) : h.snapshot();
  }

  /** Everything, in the Prometheus text exposition format (version 0.0.4). */
  public String toPrometheus() {
    StringBuilder out = new StringBuilder();
    writePrometheus(out);
    return out.toString();
  }

  public void writePrometheus(Appendable out) {
    try {
      counters(out, "openscript_client_checks_total", "Requests answered with a decision",
          List.of("action", "phase", "decision"), checks);
      counters(out, "openscript_client_errors_total", "Requests that got no decision",
          List.of("action", "phase", "status"), errors);
      Map<List<String>, LongAdder> byPolicy = new TreeMap<>(InMemoryMetrics::compare);
      violations.forEach((k, v) -> byPolicy.put(List.of(k), v));
      counters(out, "openscript_client_policy_violations_total",
          "Checks where a policy category found something (risk > 0)", List.of("policy"),
          byPolicy);
      single(out, "openscript_client_injections_flagged_total",
          "Checks where the prompt-injection scorer flagged the input", injectionsFlagged);
      single(out, "openscript_client_tool_calls_denied_total",
          "Tool calls the tool firewall refused", toolCallsDenied);
      single(out, "openscript_client_pii_redacted_total",
          "Outputs that had PII redacted", piiRedacted);
      histograms(out, "openscript_client_check_risk_score",
          "Aggregated risk score per answered check", List.of(), Map.of(List.of(), risk));
      histograms(out, "openscript_client_round_trip_seconds",
          "Whole request, measured by the client", List.of("action", "phase"), roundTrip);
      histograms(out, "openscript_client_pipeline_seconds",
          "Time in the policies, measured by the server", List.of("action", "phase"), pipeline);
    } catch (IOException ex) {
      throw new UncheckedIOException(ex);
    }
  }

  private static void counters(
      Appendable out,
      String name,
      String help,
      List<String> labels,
      Map<List<String>, LongAdder> values)
      throws IOException {
    header(out, name, help, "counter");
    Map<List<String>, LongAdder> sorted = new TreeMap<>(InMemoryMetrics::compare);
    sorted.putAll(values);
    for (Map.Entry<List<String>, LongAdder> e : sorted.entrySet()) {
      out.append(name).append(labelSet(labels, e.getKey(), null, null)).append(' ')
          .append(Long.toString(e.getValue().sum())).append('\n');
    }
  }

  private static void single(Appendable out, String name, String help, LongAdder value)
      throws IOException {
    header(out, name, help, "counter");
    out.append(name).append(' ').append(Long.toString(value.sum())).append('\n');
  }

  private static void histograms(
      Appendable out,
      String name,
      String help,
      List<String> labels,
      Map<List<String>, Histogram> values)
      throws IOException {
    header(out, name, help, "histogram");
    Map<List<String>, Histogram> sorted = new TreeMap<>(InMemoryMetrics::compare);
    sorted.putAll(values);
    for (Map.Entry<List<String>, Histogram> e : sorted.entrySet()) {
      HistogramSnapshot s = e.getValue().snapshot();
      for (int i = 0; i <= s.bounds().length; i++) {
        String le = i < s.bounds().length ? number(s.bounds()[i]) : "+Inf";
        out.append(name).append("_bucket").append(labelSet(labels, e.getKey(), "le", le))
            .append(' ').append(Long.toString(s.cumulative()[i])).append('\n');
      }
      out.append(name).append("_sum").append(labelSet(labels, e.getKey(), null, null))
          .append(' ').append(number(s.sum())).append('\n');
      out.append(name).append("_count").append(labelSet(labels, e.getKey(), null, null))
          .append(' ').append(Long.toString(s.count())).append('\n');
    }
  }

  private static void header(Appendable out, String name, String help, String type)
      throws IOException {
    out.append("# HELP ").append(name).append(' ').append(help).append('\n');
    out.append("# TYPE ").append(name).append(' ').append(type).append('\n');
  }

  private static String labelSet(
      List<String> names, List<String> values, String extraName, String extraValue) {
    if (names.isEmpty() && extraName == null) return "";
    StringBuilder s = new StringBuilder("{");
    for (int i = 0; i < names.size(); i++) {
      if (i > 0) s.append(',');
      s.append(names.get(i)).append("=\"").append(escape(values.get(i))).append('"');
    }
    if (extraName != null) {
      if (!names.isEmpty()) s.append(',');
      s.append(extraName).append("=\"").append(extraValue).append('"');
    }
    return s.append('}').toString();
  }

  private static String escape(String value) {
    return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
  }

  private static String number(double value) {
    if (value == Math.rint(value) && !Double.isInfinite(value) && Math.abs(value) < 1e15) {
      return Long.toString((long) value) + ".0";
    }
    return Double.toString(value);
  }

  private static int compare(List<String> a, List<String> b) {
    for (int i = 0; i < Math.min(a.size(), b.size()); i++) {
      int c = a.get(i).compareTo(b.get(i));
      if (c != 0) return c;
    }
    return Integer.compare(a.size(), b.size());
  }

  private static String wire(Decision decision) {
    return decision.name().toLowerCase(java.util.Locale.ROOT);
  }

  private static Object field(Map<String, Object> findings, String category, String key) {
    return findings.get(category) instanceof Map<?, ?> entry ? entry.get(key) : null;
  }

  private static LongAdder counter(ConcurrentMap<List<String>, LongAdder> map, List<String> key) {
    return map.computeIfAbsent(key, k -> new LongAdder());
  }

  private static Histogram histogram(
      ConcurrentMap<List<String>, Histogram> map, List<String> key) {
    return map.computeIfAbsent(key, k -> new Histogram(LATENCY_BUCKETS));
  }

  /** A fixed-bucket histogram: counts per bucket, a sum and a count. */
  static final class Histogram {
    private final double[] bounds;
    private final AtomicLongArray buckets;
    private final DoubleAdder sum = new DoubleAdder();

    Histogram(double[] bounds) {
      this.bounds = bounds;
      this.buckets = new AtomicLongArray(bounds.length + 1);
    }

    void observe(double value) {
      int i = 0;
      while (i < bounds.length && value > bounds[i]) i++;
      buckets.incrementAndGet(i);
      sum.add(value);
    }

    HistogramSnapshot snapshot() {
      long[] cumulative = new long[bounds.length + 1];
      long running = 0;
      for (int i = 0; i < cumulative.length; i++) {
        running += buckets.get(i);
        cumulative[i] = running;
      }
      return new HistogramSnapshot(bounds.clone(), cumulative, sum.sum());
    }
  }

  /**
   * A histogram at one moment.
   *
   * @param bounds upper bounds of the buckets, without +Inf
   * @param cumulative observations at or under each bound; the last entry is +Inf, the count
   */
  public record HistogramSnapshot(double[] bounds, long[] cumulative, double sum) {

    static HistogramSnapshot empty(double[] bounds) {
      return new HistogramSnapshot(bounds.clone(), new long[bounds.length + 1], 0);
    }

    public long count() {
      return cumulative[cumulative.length - 1];
    }

    public double mean() {
      return count() == 0 ? 0 : sum / count();
    }

    /**
     * The smallest bucket bound under which at least {@code q} of the observations fall: an upper
     * bound on the quantile, as precise as the buckets. +Inf past the last bound; 0 when empty.
     */
    public double quantileUpperBound(double q) {
      if (count() == 0) return 0;
      long needed = (long) Math.ceil(q * count());
      for (int i = 0; i < bounds.length; i++) {
        if (cumulative[i] >= needed) return bounds[i];
      }
      return Double.POSITIVE_INFINITY;
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof HistogramSnapshot s
          && Arrays.equals(bounds, s.bounds)
          && Arrays.equals(cumulative, s.cumulative)
          && sum == s.sum;
    }

    @Override
    public int hashCode() {
      return 31 * Arrays.hashCode(cumulative) + Double.hashCode(sum);
    }

    @Override
    public String toString() {
      return "HistogramSnapshot[count=" + count() + ", sum=" + sum + "]";
    }
  }
}
