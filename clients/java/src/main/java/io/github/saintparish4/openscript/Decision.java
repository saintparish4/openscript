package io.github.saintparish4.openscript;

/** What the policies decided about one phase of one action. */
public enum Decision {
  ALLOW,
  DENY,
  REQUIRE_APPROVAL;

  static Decision fromWire(String value) {
    return switch (value) {
      case "allow" -> ALLOW;
      case "deny" -> DENY;
      case "require_approval" -> REQUIRE_APPROVAL;
      // A decision this client does not know is not an allow.
      default -> throw new OpenScriptException("unknown decision '" + value + "'");
    };
  }
}
