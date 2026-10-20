package io.github.saintparish4.openscript;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The JSON this client sends and reads, so that it needs nothing beyond the JDK.
 *
 * <p>Reading gives {@code Map<String, Object>} (insertion-ordered), {@code List<Object>},
 * {@code String}, {@code Long} (or {@code BigInteger} past its range), {@code Double},
 * {@code Boolean} and {@code null}. Writing accepts those, any other {@code Number}, any
 * {@code Collection} and any array of objects, and refuses everything else rather than
 * guessing at a representation.
 *
 * <p>Integers stay integers on the way out: the server binds an approval to the exact types of a
 * tool's arguments, so {@code 10} and {@code 10.0} are two different calls.
 */
final class Json {
  private Json() {}

  static String write(Object value) {
    StringBuilder out = new StringBuilder();
    write(value, out);
    return out.toString();
  }

  private static void write(Object value, StringBuilder out) {
    if (value == null) {
      out.append("null");
    } else if (value instanceof String s) {
      writeString(s, out);
    } else if (value instanceof Boolean b) {
      out.append(b);
    } else if (value instanceof Double || value instanceof Float) {
      double d = ((Number) value).doubleValue();
      if (Double.isNaN(d) || Double.isInfinite(d)) {
        throw new IllegalArgumentException("JSON has no " + d);
      }
      out.append(d);
    } else if (value instanceof Integer
        || value instanceof Long
        || value instanceof Short
        || value instanceof Byte
        || value instanceof BigInteger
        || value instanceof BigDecimal) {
      out.append(value);
    } else if (value instanceof Map<?, ?> map) {
      out.append('{');
      boolean first = true;
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (!(entry.getKey() instanceof String key)) {
          throw new IllegalArgumentException("JSON object keys are strings, got " + entry.getKey());
        }
        if (!first) out.append(',');
        first = false;
        writeString(key, out);
        out.append(':');
        write(entry.getValue(), out);
      }
      out.append('}');
    } else if (value instanceof Collection<?> items) {
      writeArray(items, out);
    } else if (value instanceof Object[] items) {
      writeArray(List.of(items), out);
    } else {
      throw new IllegalArgumentException(
          "cannot send a " + value.getClass().getName() + " as JSON; use maps, lists and scalars");
    }
  }

  private static void writeArray(Collection<?> items, StringBuilder out) {
    out.append('[');
    boolean first = true;
    for (Object item : items) {
      if (!first) out.append(',');
      first = false;
      write(item, out);
    }
    out.append(']');
  }

  private static void writeString(String s, StringBuilder out) {
    out.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }

  static Object parse(String text) {
    Parser parser = new Parser(text);
    parser.skipSpace();
    Object value = parser.value();
    parser.skipSpace();
    if (parser.pos != text.length()) {
      throw parser.error("trailing characters");
    }
    return value;
  }

  private static final class Parser {
    private final String text;
    private int pos;

    Parser(String text) {
      this.text = text;
    }

    IllegalArgumentException error(String message) {
      return new IllegalArgumentException("invalid JSON at offset " + pos + ": " + message);
    }

    void skipSpace() {
      while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0) pos++;
    }

    char peek() {
      if (pos >= text.length()) throw error("unexpected end");
      return text.charAt(pos);
    }

    void expect(String literal) {
      if (!text.startsWith(literal, pos)) throw error("expected " + literal);
      pos += literal.length();
    }

    Object value() {
      char c = peek();
      switch (c) {
        case '{':
          return object();
        case '[':
          return array();
        case '"':
          return string();
        case 't':
          expect("true");
          return Boolean.TRUE;
        case 'f':
          expect("false");
          return Boolean.FALSE;
        case 'n':
          expect("null");
          return null;
        default:
          if (c == '-' || (c >= '0' && c <= '9')) return number();
          throw error("unexpected '" + c + "'");
      }
    }

    Map<String, Object> object() {
      Map<String, Object> map = new LinkedHashMap<>();
      pos++;
      skipSpace();
      if (peek() == '}') {
        pos++;
        return map;
      }
      while (true) {
        skipSpace();
        if (peek() != '"') throw error("expected a string key");
        String key = string();
        skipSpace();
        expect(":");
        skipSpace();
        map.put(key, value());
        skipSpace();
        char c = peek();
        pos++;
        if (c == '}') return map;
        if (c != ',') throw error("expected ',' or '}'");
      }
    }

    List<Object> array() {
      List<Object> list = new ArrayList<>();
      pos++;
      skipSpace();
      if (peek() == ']') {
        pos++;
        return list;
      }
      while (true) {
        skipSpace();
        list.add(value());
        skipSpace();
        char c = peek();
        pos++;
        if (c == ']') return list;
        if (c != ',') throw error("expected ',' or ']'");
      }
    }

    String string() {
      StringBuilder out = new StringBuilder();
      pos++;
      while (true) {
        char c = peek();
        pos++;
        if (c == '"') return out.toString();
        if (c < 0x20) throw error("control character in string");
        if (c != '\\') {
          out.append(c);
          continue;
        }
        char e = peek();
        pos++;
        switch (e) {
          case '"', '\\', '/' -> out.append(e);
          case 'n' -> out.append('\n');
          case 'r' -> out.append('\r');
          case 't' -> out.append('\t');
          case 'b' -> out.append('\b');
          case 'f' -> out.append('\f');
          case 'u' -> {
            if (pos + 4 > text.length()) throw error("short \\u escape");
            try {
              out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
            } catch (NumberFormatException ex) {
              throw error("bad \\u escape");
            }
            pos += 4;
          }
          default -> throw error("bad escape \\" + e);
        }
      }
    }

    Number number() {
      int start = pos;
      if (peek() == '-') pos++;
      boolean integral = true;
      while (pos < text.length()) {
        char c = text.charAt(pos);
        if (c >= '0' && c <= '9') {
          pos++;
        } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
          integral = false;
          pos++;
        } else {
          break;
        }
      }
      String literal = text.substring(start, pos);
      try {
        if (integral) {
          BigInteger big = new BigInteger(literal);
          return big.bitLength() < 64 ? (Number) big.longValue() : big;
        }
        return Double.parseDouble(literal);
      } catch (NumberFormatException ex) {
        throw error("bad number " + literal);
      }
    }
  }
}
