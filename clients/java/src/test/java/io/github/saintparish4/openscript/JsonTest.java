package io.github.saintparish4.openscript;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class JsonTest {

  @Test
  void roundTripsNestedValues() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("s", "a \"quoted\"\\ line\n\ttab \u0001 é 😀");
    value.put("n", 10L);
    value.put("d", 2.5);
    value.put("b", true);
    value.put("z", null);
    value.put("list", List.of(1L, "two", List.of()));
    value.put("map", Map.of("k", false));
    assertEquals(value, Json.parse(Json.write(value)));
  }

  @Test
  void integersStayIntegers() {
    // The server's approval hash tells 10 from 10.0.
    assertEquals("[10,10.0,10]", Json.write(List.of(10, 10.0, 10L)));
    assertEquals(10L, Json.parse("10"));
    assertEquals(10.0, Json.parse("10.0"));
    assertEquals(1e3, Json.parse("1e3"));
    assertEquals(-7L, Json.parse("-7"));
  }

  @Test
  void bigIntegersSurvive() {
    BigInteger big = new BigInteger("123456789012345678901234567890");
    assertEquals(big, Json.parse(Json.write(big)));
    assertEquals(Long.MAX_VALUE, Json.parse(Long.toString(Long.MAX_VALUE)));
  }

  @Test
  void writesArraysAndEscapesControlCharacters() {
    assertEquals("[\"a\",1]", Json.write(new Object[] {"a", 1}));
    assertEquals("\"\\u001f\"", Json.write("\u001f"));
  }

  @Test
  void readsUnicodeEscapes() {
    assertEquals("é😀", Json.parse("\"\\u00e9\\ud83d\\ude00\""));
  }

  @Test
  void refusesWhatJsonCannotSay() {
    assertThrows(IllegalArgumentException.class, () -> Json.write(Double.NaN));
    assertThrows(IllegalArgumentException.class, () -> Json.write(Double.POSITIVE_INFINITY));
    assertThrows(IllegalArgumentException.class, () -> Json.write(Map.of(1, "x")));
    assertThrows(IllegalArgumentException.class, () -> Json.write(new Object()));
  }

  @Test
  void refusesMalformedInput() {
    for (String bad :
        Arrays.asList("", "{", "[1,]", "{\"a\" 1}", "tru", "\"open", "1 2", "{1:2}", "\"\\x\"")) {
      assertThrows(IllegalArgumentException.class, () -> Json.parse(bad), bad);
    }
  }
}
