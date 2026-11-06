"""Text canonicalization shared by the input-side pattern banks.

A pattern bank sees exactly the bytes it is handed. "Ignore all previous
instructions" is blocked at 0.85; the same sentence with a zero-width space
inside one word, or with the Cyrillic о instead of the Latin one, or written
1gn0re, scored 0.00 — the regex engine is looking at different characters and
is entirely correct to say so. That gap is not a missing pattern, it is a
missing step, and every pattern added without it is one substitution away from
being bypassed.

So the policies do not scan a string. They scan a small set of *views* of it:

  raw            what arrived, untouched
  normalized     NFKD, invisible characters dropped, combining marks dropped,
                 look-alike letters folded to ASCII, letter-spacing collapsed
  deobfuscated   the above, plus leetspeak undone and separator punctuation
                 treated as spaces
  decoded        whatever a base64, hex or percent-encoded run in the text
                 turned out to be, normalized in turn

Only views that differ from one already in the list are produced, so plain
English text costs exactly one scan, the same as before. The cost is paid by
text that has been fiddled with, which is the text worth paying for.

Two deliberate limits, because a reader should know what this does not do:
translation is not one of the transforms (an attack written in French is still
invisible to an English pattern bank), and de-leeting is confined to tokens
that already mix letters with digits, so "refund 9999" is never read as
"refund gggg".

Pure stdlib on purpose: this runs inside the browser demo, where the only
Python available is what Pyodide ships. Percent-decoding is done by hand rather
than with urllib.parse, because tools/policy_audit.py counts any reference to
urllib as a module that could reach the network, and that check is worth more
than the four lines it costs here.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial

__all__ = ["Prepared", "Scan", "View", "canonical", "prepare", "scan"]

# Format characters (Cf) cover zero-width spaces, joiners, the bidi overrides
# and the BOM. Soft hyphen is Cf too. Listed rather than category-tested where
# the category would also catch something worth keeping.
_INVISIBLE = re.compile(r"[­͏؜ᅟᅠ឴឵᠎⠀ㅤﾠ]")

# Look-alikes that survive NFKD: NFKD decomposes mathematical, fullwidth and
# circled Latin, but Cyrillic and Greek letters are not Latin with decorations,
# they are separate letters that happen to be drawn the same.
_CONFUSABLES = str.maketrans(
    {
        # Cyrillic lowercase
        "а": "a",
        "б": "b",
        "в": "b",
        "г": "r",
        "е": "e",
        "ѐ": "e",
        "ё": "e",
        "з": "3",
        "и": "u",
        "й": "u",
        "к": "k",
        "м": "m",
        "н": "h",
        "о": "o",
        "п": "n",
        "р": "p",
        "с": "c",
        "т": "t",
        "у": "y",
        "х": "x",
        "ч": "4",
        "ѕ": "s",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "һ": "h",
        "ӏ": "l",
        "ԛ": "q",
        "ԝ": "w",
        "ь": "b",
        "я": "r",
        # Cyrillic uppercase
        "А": "A",
        "В": "B",
        "Е": "E",
        "З": "3",
        "К": "K",
        "М": "M",
        "Н": "H",
        "О": "O",
        "Р": "P",
        "С": "C",
        "Т": "T",
        "У": "Y",
        "Х": "X",
        "Ѕ": "S",
        "І": "I",
        "Ј": "J",
        "Ԁ": "D",
        "Һ": "H",
        "Ԛ": "Q",
        "Ԝ": "W",
        # Greek
        "α": "a",
        "β": "b",
        "γ": "y",
        "ε": "e",
        "ζ": "z",
        "η": "n",
        "ι": "i",
        "κ": "k",
        "μ": "u",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "σ": "o",
        "τ": "t",
        "υ": "u",
        "χ": "x",
        "ω": "w",
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Ζ": "Z",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Υ": "Y",
        "Χ": "X",
        # Latin letters that are not the usual ones
        "ı": "i",
        "ł": "l",
        "ø": "o",
        "œ": "oe",
        "æ": "ae",
        "ſ": "s",
        # Armenian and Georgian shapes that get used for this
        "օ": "o",
        "ո": "n",
        "ս": "s",
        "զ": "q",
        "ա": "w",
        # Punctuation look-alikes that matter to the patterns
        "‚": ",",
        "„": ",",
        "‘": "'",
        "’": "'",
        "‛": "'",
        "“": '"',
        "”": '"',
        "‟": '"',
        "‐": "-",
        "‑": "-",
        "‒": "-",
        "–": "-",
        "—": "-",
        "―": "-",
        "․": ".",
        "‥": "..",
        "…": "...",
        "⁄": "/",
        "∕": "/",
        "︰": ":",
    }
)

# Four or more single letters in a row, each followed by a separator: the
# "I g n o r e" and "i-g-n-o-r-e" shapes. Anchored on both sides so it cannot
# eat the first letter of a real word.
_PAD_PUNCT = r"\-._*|~·•‧"
_SEPARATORS = r" \t" + _PAD_PUNCT
_SPACED_OUT = re.compile(
    rf"(?<![^\W\d_])(?:[^\W\d_][{_SEPARATORS}]{{1,3}}){{3,}}[^\W\d_](?![^\W\d_])"
)
_SEP_RUN = re.compile(rf"[{_SEPARATORS}]{{2,}}")
_SEP_ONE = re.compile(rf"[{_SEPARATORS}]")
_PUNCT_PAD = re.compile(rf"[{_PAD_PUNCT}]")

_LEET_BASE = {
    "4": "a",
    "3": "e",
    "0": "o",
    "5": "s",
    "7": "t",
    "8": "b",
    "9": "g",
    "$": "s",
    "@": "a",
    "+": "t",
    "(": "c",
    "€": "e",
    "£": "l",
}
# 1, ! and | are drawn like both i and l, so each token gets read both ways and
# the more word-like reading wins: "1gn0re" is ignore rather than lgnore, and
# "a11" is all rather than aii. Guessing one way for the whole string gets one
# of those two wrong every time.
_LEET_I = str.maketrans({**_LEET_BASE, "1": "i", "!": "i", "|": "i"})
_LEET_L = str.maketrans({**_LEET_BASE, "1": "l", "!": "l", "|": "l"})
# Sequences English essentially does not produce. Used only to choose between
# two readings of the same token, never to reject text.
# Word-initial l before a consonant ("lgnore"), a doubled i ("aii"), and an i
# wedged between two vowels ("keyiogger") are the three shapes that separate a
# wrong reading from a right one often enough to be worth testing for. The
# middle vowel rule is written to leave "previous" alone, where the i follows a
# consonant.
_UNLIKELY = re.compile(r"ii|\bl(?=[bcdfgjklmnpqrstvwxz])|\bi(?=[lr])|[aeouy]i[aeouy]")
_LONE_ONE = re.compile(r"\b[1|]\b")
# A token is a de-leeting candidate only if it already contains a letter. That
# is what keeps "$9999", "order 4471" and "E11.9" out of it — numbers that are
# only numbers stay numbers.
_LEET_TOKEN = re.compile(r"\b(?=[\w$@!|+]*[a-zA-Z])[\w$@!|+]*[0134578$@!|+][\w$@!|+]*\b")
# Punctuation wedged between letters, as in "ignore.all.previous".
_WEDGED = re.compile(r"(?<=[^\W\d_])[._\-*|/~+](?=[^\W\d_])")

_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-fA-F]{2}[\s:-]?){12,}")
_PERCENT_RUN = re.compile(r"(?:%[0-9a-fA-F]{2}){6,}")

MAX_DECODED_PAYLOADS = 3
MAX_DECODED_CHARS = 4096


@dataclass(frozen=True)
class View:
    """One rendering of the input, and the name the metadata reports it under."""

    name: str
    text: str


@dataclass(frozen=True)
class Prepared:
    """Every view worth scanning, plus what was done to produce them.

    `markers` is the honest part of the report: it names the obfuscation that
    was actually present, so a policy can say "caught after folding look-alike
    characters" instead of leaving a reader to guess why a score appeared.
    """

    views: list[View]
    markers: list[str]


def _strip_invisibles(text: str) -> tuple[str, bool]:
    out = _INVISIBLE.sub("", text)
    kept = []
    removed = out != text
    for ch in out:
        category = unicodedata.category(ch)
        if category in ("Cf", "Mn", "Me"):  # format characters and combining marks
            removed = True
            continue
        kept.append(ch)
    return "".join(kept), removed


def _collapse_spacing(text: str) -> tuple[str, bool]:
    """Join "I g n o r e" back into a word, keeping the gaps between words.

    Which character was the padding depends on what else is in the run. When
    the padding is punctuation ("i-g-n-o-r-e a-l-l"), whitespace is still doing
    its usual job and survives as one space. When the padding is whitespace
    itself ("i g n o r e   a l l"), a single space is padding and a run of two
    or more is the word boundary. Collapsing every separator either way would
    produce "ignoreallprevious", which matches nothing either.
    """
    changed = False

    def _join(match: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        chunk = match.group(0)
        if _PUNCT_PAD.search(chunk):
            return re.sub(r"\s+", " ", _PUNCT_PAD.sub("", chunk))
        return _SEP_ONE.sub("", _SEP_RUN.sub("\x00", chunk)).replace("\x00", " ")

    return _SPACED_OUT.sub(_join, text), changed


def canonical(text: str) -> str:
    """The view every pattern bank should have been looking at all along."""
    return _canonical(text)[0]


def _canonical(text: str) -> tuple[str, list[str]]:
    markers: list[str] = []
    out = unicodedata.normalize("NFKD", text)
    if out != text:
        markers.append("compatibility_forms")

    out, stripped = _strip_invisibles(out)
    if stripped:
        markers.append("invisible_characters")

    folded = out.translate(_CONFUSABLES)
    if folded != out:
        markers.append("look_alike_letters")
    out = folded

    out, spaced = _collapse_spacing(out)
    if spaced:
        markers.append("letter_spacing")

    return out, markers


def _rank(word: str) -> int:
    """How many sequences English essentially does not produce this word has."""
    return len(_UNLIKELY.findall(word.lower()))


def _read_token(match: re.Match[str], prefer_likely: bool = True) -> str:
    """One of a token's two leet readings: the more word-like one, or the other.

    "a11" is all, not aii, and "1gn0re" is ignore, not lgnore — a single global
    guess gets one of those wrong whichever way it is made. The losing reading
    is not thrown away either: "key10gger" looks equally plausible both ways,
    and the one that matters is keylogger.
    """
    token = match.group(0)
    as_i = token.translate(_LEET_I)
    as_l = token.translate(_LEET_L)
    if as_i == as_l:
        return as_i
    # Ties go to i, the commoner substitution, so the runner-up is well defined.
    ranked = sorted((as_i, as_l), key=lambda word: (_rank(word), word == as_l))
    return ranked[0] if prefer_likely else ranked[1]


def _deobfuscate(text: str) -> tuple[list[str], list[str]]:
    """Undo leetspeak and punctuation wedged between letters.

    Returns one reading for text with no ambiguous characters in it, and two
    when the ambiguity is real. Scanning both costs one extra pass over text
    that has already announced itself as obfuscated.
    """
    markers: list[str] = []
    readings: list[str] = []

    for prefer_likely in (True, False):
        out = _LEET_TOKEN.sub(partial(_read_token, prefer_likely=prefer_likely), text)
        if out != text:
            if "leetspeak" not in markers:
                markers.append("leetspeak")
            # A lone "1" is a number in ordinary text and a letter in
            # leetspeak, so it is only re-read once some other token has given
            # the text away. Without this, "h0w d0 1 bu1ld" keeps its pronoun
            # as a digit.
            out = _LONE_ONE.sub("i", out)

        unwedged = _WEDGED.sub(" ", out)
        if unwedged != out and "wedged_punctuation" not in markers:
            markers.append("wedged_punctuation")
        if unwedged not in readings:
            readings.append(unwedged)

    return readings, markers


def _readable(raw: bytes) -> str | None:
    """Decoded bytes are only interesting if they came out as prose."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if len(text) < 12:
        return None
    if sum(ch.isprintable() or ch in "\n\t" for ch in text) / len(text) < 0.95:
        return None
    if sum(ch.isalpha() for ch in text) / len(text) < 0.5:
        return None
    return text[:MAX_DECODED_CHARS]


def _decode_payloads(text: str) -> list[str]:
    """Anything encoded in the prompt, decoded, so it gets scanned as well.

    A prompt that says "decode this and do what it says" is carrying its
    payload in plain sight. Runs that decode to bytes rather than to prose are
    dropped, which is what keeps an API key or a hash from being read as an
    instruction.
    """
    found: list[str] = []

    for match in _B64_RUN.finditer(text):
        run = match.group(0).rstrip("=")
        try:
            decoded = base64.b64decode(run + "=" * (-len(run) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        readable = _readable(decoded)
        if readable:
            found.append(readable)

    for match in _HEX_RUN.finditer(text):
        digits = re.sub(r"[\s:-]", "", match.group(0))
        if len(digits) % 2:
            digits = digits[:-1]
        try:
            readable = _readable(bytes.fromhex(digits))
        except ValueError:
            continue
        if readable:
            found.append(readable)

    for match in _PERCENT_RUN.finditer(text):
        raw = bytes(int(pair, 16) for pair in match.group(0).split("%") if pair)
        readable = _readable(raw)
        if readable:
            found.append(readable)

    return found[:MAX_DECODED_PAYLOADS]


def prepare(text: str) -> Prepared:
    """Build the views a pattern bank should scan, cheapest first.

    Views that came out identical to one already in the list are dropped, so
    ordinary text produces exactly one view and costs exactly one pass.
    """
    views = [View("raw", text)]
    seen = {text}
    markers: list[str] = []

    normalized, canon_markers = _canonical(text)
    markers.extend(canon_markers)
    if normalized not in seen:
        views.append(View("normalized", normalized))
        seen.add(normalized)

    readings, deob_markers = _deobfuscate(normalized)
    markers.extend(deob_markers)
    for reading in readings:
        if reading not in seen:
            views.append(View("deobfuscated", reading))
            seen.add(reading)

    for payload in _decode_payloads(normalized):
        decoded, _ = _canonical(payload)
        if decoded not in seen:
            views.append(View("decoded", decoded))
            seen.add(decoded)
            if "encoded_payload" not in markers:
                markers.append("encoded_payload")

    return Prepared(views=views, markers=markers)


@dataclass(frozen=True)
class Scan:
    """What a pattern bank found, and which view of the text it found it in."""

    risk: float
    signals: dict[str, float] = field(default_factory=dict)
    #: "raw" unless an obfuscated view scored higher than the text as it arrived.
    view: str = "raw"
    #: Obfuscation present in the input, whether or not it changed the score.
    markers: list[str] = field(default_factory=list)


def scan(text: str, scorer: Callable[[str], tuple[float, dict[str, float]]]) -> Scan:
    """Run *scorer* over every view of *text* and keep the strongest result.

    Ties go to the earliest view, so a prompt that scores the same before and
    after normalization is reported as what it plainly is.
    """
    prepared = prepare(text)
    best = Scan(risk=0.0, signals={}, view="raw", markers=prepared.markers)
    for view in prepared.views:
        risk, signals = scorer(view.text)
        if risk > best.risk:
            best = Scan(risk=risk, signals=signals, view=view.name, markers=prepared.markers)
    return best
