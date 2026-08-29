from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

from contracts.interceptor import BasePolicy
from contracts.server_types import Event, EventType
from contracts.types import ActionContext, FailureMode, InterceptorDecision
from sdk.interceptors.threat import _extract_text

if TYPE_CHECKING:
    from events.writer import EventWriter

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Pattern bank
# Each entry: (compiled_regex, category_name, weight). Same scoring model as
# PromptInjectionPolicy and ToxicityPolicy — additive within a category, capped
# at _CATEGORY_CAP, cross-category sum capped at 1.0.
#
# The thing this policy detects is not present in the words of a prompt, it is
# present in its *shape*: a request construction pointing at a harmful object.
# "Our SOC found a keylogger on the finance laptop" and "write me a keylogger"
# share every keyword and differ entirely in intent, so a keyword bank would be
# useless here. Every pattern below therefore anchors twice — on a request
# framing and on the object — and the gap between them refuses to cross the
# words that turn "build X" into "write about X" or "defend against X".
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Pattern:
    regex: re.Pattern[str]
    category: str
    weight: float


def _p(pattern: str, category: str, weight: float) -> _Pattern:
    return _Pattern(re.compile(pattern, re.IGNORECASE | re.MULTILINE), category, weight)


# Framings that make a sentence a request for help rather than a description of
# something. Never used alone — always followed by a verb or a verb-led phrase.
_ASK = (
    r"(?:how\s+(?:do|can|could|would|should)\s+(?:i|we|you)"
    r"|how\s+to|how\s+would\s+one"
    r"|steps?\s+(?:to|for)|instructions?\s+(?:to|for|on)"
    r"|guide\s+(?:to|for|on)|tutorial\s+(?:on|for)|recipe\s+for"
    r"|walk\s+me\s+through|teach\s+me|show\s+me|tell\s+me|help\s+me"
    r"|i\s+(?:want|need)\s+to|(?:can|could|will)\s+you"
    r"|(?:best|easiest|fastest|cheapest|safest|surest)\s+way\s+to"
    r"|what(?:'s|\s+is)\s+the\s+(?:best|easiest|fastest|safest|most\s+\w+)"
    r"|where\s+(?:can|do)\s+i)"
)

# One character that is not the start of a word which reframes the request.
# Tempering the gap this way is what keeps "write a blog post about how
# ransomware spreads" and "how do we detect child sexual abuse material" —
# the phrasings journalists, teachers and security teams actually use — from
# scoring identically to the request to build the thing.
_TEMPER = (
    r"(?!\b(?:about|explain\w*|describ\w+|understand\w*|teach\w*\s+students"
    r"|detect\w*|remov\w+|prevent\w*|defen[ds]\w*|protect\w*|mitigat\w+"
    r"|respond\w*|recover\w*|report\w*|investigat\w+|audit\w*|review\w*"
    r"|blog|article|essay|post|paper|thesis|book|course|lesson|lecture"
    r"|training|awareness|curriculum|policy|presentation|talk|deck"
    r"|signature|scanner|detector|honeypot|simulation|exercise|drill"
    r"|bath|photo)\b)."
)
_GAP = rf"(?:{_TEMPER}){{0,40}}?"
_LEAD = rf"(?:{_TEMPER}){{0,20}}?"

# Sentence-initial imperative, or one of the framings above. Whatever follows a
# _REQ has to begin with a verb — that is the whole reason this does not match
# every line of every document.
_REQ = rf"(?:^\s*(?:please[,\s]+)?|(?<=[.!?]\s)|{_ASK}{_LEAD})"

# Verbs that ask for the thing to be produced or handed over.
_PRODUCE = (
    r"(?:writ\w+|build\w*|mak\w+|creat\w+|construct\w*|assembl\w+|cod\w+"
    r"|program\w*|develop\w*|generat\w+|design\w*|synthesi[sz]\w+"
    r"|manufactur\w+|cook\w*|brew\w*|3d[\s-]?print\w*|print\w*|forge\w*"
    r"|convert\w*|modif\w+|craft\w*|set\s+up|put\s+together"
    r"|giv\w+|provid\w+|send|hand)"
)
# Verbs that ask for the thing to be obtained.
_OBTAIN = (
    r"(?:buy\w*|purchas\w+|acquir\w+|obtain\w*|order|get|find|source"
    r"|smuggl\w+|import\w*|steal|hire|pay\s+someone)"
)


def _produce(obj: str, category: str, weight: float) -> _Pattern:
    """A request to build, write or hand over *obj*."""
    return _p(rf"{_REQ}{_PRODUCE}(?:\s+me)?\b{_GAP}\b(?:{obj})", category, weight)


def _obtain(obj: str, category: str, weight: float) -> _Pattern:
    """A request to acquire *obj*."""
    return _p(rf"{_REQ}{_OBTAIN}(?:\s+me)?\b{_GAP}\b(?:{obj})", category, weight)


def _act(phrase: str, category: str, weight: float) -> _Pattern:
    """A request for a harmful act. *phrase* must begin with its own verb."""
    return _p(rf"{_REQ}(?:{phrase})", category, weight)


# --- objects -----------------------------------------------------------------

_FIREARM = (
    r"ghost\s+guns?|untraceable\s+(?:guns?|firearms?|weapons?|receivers?)"
    r"|unserialized\s+(?:receivers?|firearms?|lowers?)"
    r"|(?:80|eighty)\s*%\s*(?:lower|receiver)"
    r"|auto\s+sear|drop[\s-]?in\s+auto"
    r"|semi[\s-]?auto\w*\s+(?:in)?to\s+(?:a\s+)?full[\s-]?auto"
    r"|(?:gun|firearm|rifle|pistol|silencer|suppressor)\s+at\s+home"
)
_EXPLOSIVE = (
    r"(?:pipe|car|nail|letter|dirty|fertilizer|pressure\s+cooker)\s+bombs?"
    r"|(?<!bath )(?<!photo )bombs?\b|explosive\s+devices?|detonators?"
    r"|napalm|thermite|c-?4\b|tatp|improvised\s+explosives?"
)
_CBRN = (
    r"weapons?\s+of\s+mass\s+destruction|wmds?\b"
    r"|(?:nuclear|atomic|nerve|chemical|biological|radiological)\s+"
    r"(?:bombs?|weapons?|agents?|devices?)"
    r"|bio[\s-]?weapons?|sarin|vx\s+(?:gas|nerve)|mustard\s+gas|phosgene"
    r"|ricin|anthrax|botulinum"
    r"|weaponi[sz]\w+\s+(?:a\s+)?(?:virus|pathogen|anthrax|strain)"
)

_MALWARE = (
    r"key\s?logger\w*|ransomware|rootkits?|botnets?|trojans?|cryptolocker"
    r"|(?:computer\s+)?virus\s+(?:to|that|which)\b|worms?\s+(?:that|to)\b"
    r"|malware\s+(?:that|to)\b|c2\s+servers?|command\s+and\s+control\s+server"
    r"|reverse\s+shell|wiper\s+malware"
)
_OFFENSIVE = (
    r"phishing\s+(?:pages?|sites?|kits?|emails?|campaigns?|links?)"
    r"|credential\s+stuffing|password\s+crackers?"
    r"|ddos|denial[\s-]of[\s-]service"
    r"|sql\s+injection\s+(?:payloads?|attacks?|strings?)"
    r"|zero[\s-]?day\s+exploits?|exploit\s+for\s+cve"
    r"|backdoors?\s+(?:into|in|on)\b"
)

_ID_GOV = (
    r"social\s+security\s+(?:number|#)|ssn\b|tax\s+id|passport\s+numbers?"
    r"|driver'?s?\s+licen[cs]e\s+numbers?|medical\s+records?|health\s+records?"
    r"|bank\s+account\s+(?:number|details)|credit\s+card\s+numbers?|credit\s+score"
)
_ID_LOC = (
    r"home\s+address(?:es)?|house\s+address(?:es)?|home\s+phone"
    r"|personal\s+(?:phone|email|cell|number|address)"
    r"|private\s+(?:phone|email|number|address)"
    r"|phone\s+numbers?|cell\s+(?:phone\s+)?numbers?|whereabouts|maiden\s+name"
)
_THIRD = (
    r"(?:his|her|their|(?:some|any)(?:one|body)(?:'s|s')?"
    r"|my\s+(?:boss|supervisor|manager|coworkers?|co-workers?|colleagues?"
    r"|neighbou?rs?|ex|ex-\w+|teachers?|professors?|landlords?|tenants?"
    r"|clients?|patients?|students?|wife|husband|girlfriend|boyfriend"
    r"|partner|roommates?)(?:'s|s')?"
    r"|the\s+(?:ceo|cfo|cto|coo|president|chairman|founder|journalists?"
    r"|reporters?|woman|man|guy|girl|person|employees?|customers?|patients?"
    r"|students?|teachers?|witness|victim|plaintiff|defendant)(?:'s|s')?"
    r"|(?:mr|ms|mrs|dr)\.?\s+\w+(?:'s|s')?)"
)
_LOOKUP = (
    r"(?:what(?:'s|\s+is|\s+are)|find|get|look\s*up|locate|track\s+down"
    r"|dig\s+up|tell\s+me|giv\w+\s+me|show\s+me|pull\s+up|i\s+need|search\s+for"
    r"|how\s+(?:do|can)\s+i\s+(?:find|get|look\s*up|locate))"
)
_NEAR = rf"(?:{_TEMPER}){{0,25}}?"
_ASK_PII = rf"(?:^\s*|(?<=[.!?]\s)|{_ASK}{_LEAD}){_LOOKUP}"

_DRUG_STREET = (
    r"fentanyl|heroin|cocaine|crack\s+cocaine|methamphetamine|meth\b"
    r"|crystal\s+meth|mdma|ecstasy|lsd\b|ghb\b|rohypnol|roofies"
)
_DRUG_RX = (
    r"oxycodone|oxycontin|percocet|vicodin|adderall|xanax|valium" r"|ketamine|codeine|opioids?"
)


_PATTERNS: list[_Pattern] = [
    # Weapons — manufacture, conversion, and CBRN
    _produce(_FIREARM, "weapons", 0.65),
    _produce(_EXPLOSIVE, "weapons", 0.65),
    _produce(_CBRN, "weapons", 0.70),
    _obtain(_CBRN, "weapons", 0.65),
    _act(r"convert\w*\s+(?:a\s+)?semi[\s-]?auto\w*", "weapons", 0.60),
    # Malware and offensive tooling
    _produce(_MALWARE, "malware", 0.60),
    _produce(_OFFENSIVE, "malware", 0.60),
    _act(
        r"brute[\s-]?forc\w+\s+(?:\w+\s+){0,3}?(?:passwords?|wifi|logins?|accounts?|hashes?)",
        "malware",
        0.60,
    ),
    _act(
        r"hack\s+(?:in)?to\s+(?:\w+\s+){0,3}?"
        r"(?:accounts?|phones?|emails?|instagram|facebook|snapchat|wifi|network)",
        "malware",
        0.55,
    ),
    # Soliciting a third party's identifiers or records
    _p(rf"{_ASK_PII}{_NEAR}\b{_THIRD}{_NEAR}\b(?:{_ID_GOV})", "pii_solicitation", 0.65),
    _p(
        rf"{_ASK_PII}{_NEAR}\b(?:{_ID_GOV}){_NEAR}\b(?:of|for|belonging\s+to)\s+{_THIRD}",
        "pii_solicitation",
        0.65,
    ),
    _p(rf"{_ASK_PII}{_NEAR}\b{_THIRD}{_NEAR}\b(?:{_ID_LOC})", "pii_solicitation", 0.55),
    _p(
        rf"{_ASK_PII}{_NEAR}\b(?:{_ID_LOC}){_NEAR}\b(?:of|for|belonging\s+to)\s+{_THIRD}",
        "pii_solicitation",
        0.55,
    ),
    _act(
        r"(?:find|figur\w+)\s+out\s+(?:where|who)\s+(?:\w+\s+){0,3}?"
        r"(?:lives?|works?|really\s+is|is\s+staying)",
        "pii_solicitation",
        0.55,
    ),
    # Acquiring controlled goods or criminal services
    _obtain(_DRUG_STREET, "illicit_acquisition", 0.55),
    _produce(_DRUG_STREET, "illicit_acquisition", 0.60),
    _act(
        rf"(?:get|buy|obtain|order)\s+(?:{_DRUG_RX})\b{_GAP}"
        r"\bwithout\s+a\s+(?:prescription|script|doctor)",
        "illicit_acquisition",
        0.55,
    ),
    _obtain(
        r"(?:an?\s+)?(?:guns?|firearms?|pistols?|rifles?)\b.{0,25}?"
        r"\bwithout\s+a\s+(?:background\s+check|permit|licen[cs]e|ffl)",
        "illicit_acquisition",
        0.60,
    ),
    _obtain(
        r"stolen\s+(?:credit\s+cards?|cards?|accounts?|credentials?|data|logins?|identit\w+)"
        r"|dumps\s+with\s+pins?|fullz\b",
        "illicit_acquisition",
        0.60,
    ),
    _obtain(
        r"(?:an?\s+)?(?:fake|forged|counterfeit)\s+"
        r"(?:ids?|passports?|driver'?s?\s+licen[cs]es?|documents?)",
        "illicit_acquisition",
        0.60,
    ),
    _act(
        r"(?:hire|find|pay)\s+(?:someone|a\s+(?:hacker|hitman|hit\s+man))\s+to\s+"
        r"(?:hack|kill|hurt|beat|break|steal)",
        "illicit_acquisition",
        0.65,
    ),
    # Financial crime
    _act(r"launder\w*\s+(?:the\s+)?(?:money|cash|funds|proceeds)", "fraud", 0.60),
    _produce(
        r"counterfeit\s+(?:\w+\s+){0,2}?(?:bills?|money|currency|banknotes?|notes?)"
        r"|fake\s+(?:\w+\s+){0,2}?(?:bills?|currency|banknotes?)",
        "fraud",
        0.60,
    ),
    _act(
        r"steal\s+(?:someone'?s?|somebody'?s?|his|her|their|a\s+person'?s?|my\s+\w+'?s?)\s+"
        r"identity|commit\s+identity\s+theft",
        "fraud",
        0.60,
    ),
    _act(
        r"(?:kite|kiting)\s+checks?|check\s+kiting"
        r"|writ\w+\s+(?:a\s+)?(?:bad|rubber|fraudulent|hot)\s+che(?:ck|que)"
        r"|writ\w+\s+(?:a\s+)?che(?:ck|que)\s+that\s+(?:wo|do)n'?t\s+(?:bounce|clear)",
        "fraud",
        0.55,
    ),
    _act(
        r"(?:evade|dodge)\s+(?:paying\s+)?(?:taxes|the\s+irs)|tax\s+evasion\s+scheme", "fraud", 0.50
    ),
    # Planning harm to a person
    _act(
        r"poison\s+(?:someone|somebody|a\s+person|him|her|them|my\s+\w+)"
        r"|(?:best|undetectable|untraceable)\s+poison"
        r"|poisons?\s+to\s+(?:use\s+)?on\b",
        "violence_planning",
        0.65,
    ),
    _act(
        r"(?:hurt|harm|injur\w+|beat|attack)\s+"
        r"(?:someone|somebody|him|her|them|a\s+person|my\s+\w+)\b.{0,40}?"
        r"\bwithout\s+(?:leaving|getting|being|anyone)",
        "violence_planning",
        0.60,
    ),
    _act(
        r"get\s+away\s+with\s+(?:murder|killing|a\s+crime|assault|arson)", "violence_planning", 0.65
    ),
    _act(
        r"(?:plan|carry\s+out|commit|stage)\s+(?:an?\s+)?"
        r"(?:attack|shooting|massacre|bombing|ambush)\s+(?:on|at|against)\s+",
        "violence_planning",
        0.70,
    ),
    _act(
        r"mak\w+\s+it\s+look\s+like\s+(?:an?\s+)?(?:accident|suicide|self[\s-]defen[cs]e)",
        "violence_planning",
        0.60,
    ),
    _act(
        r"(?:kill|murder|stab|shoot)\s+(?:someone|somebody|a\s+person|him|her|them)\b"
        r".{0,30}?\b(?:without|and\s+not|and\s+never)\s+(?:getting|being|leaving)",
        "violence_planning",
        0.65,
    ),
    # Covert surveillance of a person, and evading the consequences
    _act(
        r"(?:track|monitor|follow|spy\s+on|geolocate|read)\s+"
        r"(?:my|his|her|their|someone'?s?)\s+(?:\w+\s+){0,2}?"
        r"(?:location|phone|cell|car|movements?|whereabouts|messages?|texts?|dms?)\b"
        r".{0,40}?\bwithout\s+(?:\w+\s+){0,2}?"
        r"(?:knowing|know|consent|permission|noticing|finding\s+out)",
        "surveillance_evasion",
        0.65,
    ),
    _act(
        r"(?:spy\s+on|track|monitor|stalk)\s+my\s+"
        r"(?:wife|husband|girlfriend|boyfriend|ex|partner|gf|bf|spouse)\b",
        "surveillance_evasion",
        0.55,
    ),
    _act(
        r"install\s+(?:spyware|stalkerware|a\s+keylogger|a\s+tracker"
        r"|monitoring\s+(?:app|software))\b.{0,40}?\bwithout\b",
        "surveillance_evasion",
        0.60,
    ),
    _act(
        r"(?:avoid|evade|escape|beat)\s+(?:the\s+)?"
        r"(?:police|law\s+enforcement|cops|arrest|prosecution)\b"
        r"|avoid\s+(?:police\s+)?detection\s+after",
        "surveillance_evasion",
        0.55,
    ),
    _act(
        r"(?:delete|destroy|wipe|erase|scrub|shred)\s+(?:the\s+|all\s+)?evidence\b",
        "surveillance_evasion",
        0.60,
    ),
    # Exploitation of people
    _act(
        r"groom\w*\s+(?:an?\s+)?(?:child|children|kid|minor|teen\w*"
        r"|young\s+(?:girl|boy)|underage)",
        "exploitation",
        0.70,
    ),
    _act(
        r"(?:smuggl\w+|traffic\w*)\s+(?:people|persons|humans|women|children|migrants)"
        r"|human\s+traffick\w+\s+(?:operation|route|ring)",
        "exploitation",
        0.65,
    ),
    _act(
        r"(?:meet|contact|find)\s+(?:a\s+)?(?:minor|underage)\b.{0,30}?\b(?:sex|alone|without)",
        "exploitation",
        0.70,
    ),
    _act(
        r"(?:child|minor|underage)\s+(?:porn\w*|sexual\s+(?:images?|content|material))",
        "exploitation",
        0.70,
    ),
    # Requests for a self-harm method, as opposed to the expressions of intent
    # that ToxicityPolicy scores. Modelled as a deny here because that is what
    # this pipeline can express; a product built on it should route these to
    # crisis resources rather than return a bare refusal.
    _act(
        r"(?:best|painless|quickest|fastest|easiest|surest|reliable|effective"
        r"|most\s+\w+)?\s*(?:ways?|methods?)\s+to\s+"
        r"(?:die|kill\s+myself|end\s+(?:it\s+all|my\s+life))",
        "self_harm_method",
        0.60,
    ),
    _act(
        r"how\s+(?:many|much)\s+(?:\w+\s+){0,3}?(?:pills?|tablets?|mg|milligrams?|units?)\s+"
        r"(?:\w+\s+){0,4}?(?:to\s+)?(?:overdose|od\b|die|kill|be\s+lethal|be\s+fatal)",
        "self_harm_method",
        0.55,
    ),
    _act(r"lethal\s+doses?\s+of|fatal\s+(?:dose|amount)\s+of", "self_harm_method", 0.55),
    _act(r"(?:suicide|self[\s-]harm)\s+methods?\b", "self_harm_method", 0.55),
]


_CATEGORY_CAP = 0.7  # max a single category can contribute to the total score


def score_harmful_request(text: str) -> tuple[float, dict[str, float]]:
    """Return (total_score, signals) for the given text.

    signals maps category -> capped contribution (weapons, malware,
    pii_solicitation, illicit_acquisition, fraud, violence_planning,
    surveillance_evasion, exploitation, self_harm_method).
    """
    category_totals: dict[str, float] = {}
    for pat in _PATTERNS:
        if pat.regex.search(text):
            current = category_totals.get(pat.category, 0.0)
            category_totals[pat.category] = min(_CATEGORY_CAP, current + pat.weight)

    total = min(1.0, sum(category_totals.values()))
    return total, category_totals


class HarmfulRequestPolicy(BasePolicy):
    """Scores input text for requests for harmful capability and blocks on breach.

    The gap this fills is the one the other input policies leave open by
    construction. PromptInjectionPolicy scores attacks on the *system*,
    ToxicityPolicy scores abusive *expression*, and PIIPolicy and SecretsPolicy
    score sensitive data *present in the text*. A grammatical, polite,
    slur-free, injection-free request to build a keylogger trips none of them.
    This one scores the request itself.

    Detection is structural: a request framing (interrogative, imperative or
    first-person intent) paired with a harmful object, with a tempered gap
    between them so reporting, teaching and defensive phrasings do not score.
    That keeps false positives manageable and makes paraphrase the obvious
    bypass — this is a heuristic layer, not a substitute for a model-side
    refusal. A local classifier backend arrives with the [ml] extra.

    Results land in context.metadata["harmful_request"] using the standardized
    shape:
      {"risk": float, "category": "harmful_request", "signals": {...},
       "flagged": bool, "threshold": float}
    """

    failure_mode: FailureMode = FailureMode.FAIL_CLOSED

    def __init__(
        self,
        threshold: float = 0.5,
        writer: EventWriter | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(f"threshold must be in [0, 1], got {threshold}")
        self._threshold = threshold
        self._writer = writer
        self._sequence_counters: dict[str, int] = {}

    async def before_action(self, context: ActionContext) -> ActionContext:
        text = _extract_text(context.input_data)
        score, signals = score_harmful_request(text)
        flagged = score >= self._threshold

        context.metadata["harmful_request"] = {
            "risk": round(score, 4),
            "category": "harmful_request",
            "signals": {k: round(v, 4) for k, v in signals.items()},
            "flagged": flagged,
            "threshold": self._threshold,
        }

        if flagged:
            top_signal = max(signals, key=lambda k: signals[k]) if signals else "unknown"
            reason = (
                f"harmful request score {score:.2f} >= threshold {self._threshold} "
                f"(top signal: {top_signal})"
            )
            context.decision = InterceptorDecision.DENY
            context.decision_reason = reason
            logger.warning(
                "harmful_request_detected",
                session_id=context.session_id,
                agent_id=context.agent_id,
                score=round(score, 4),
                signals=list(signals.keys()),
            )
            if self._writer is not None:
                await self._emit_harmful_request_event(context, score, signals, reason)

        return context

    async def _emit_harmful_request_event(
        self,
        context: ActionContext,
        score: float,
        signals: dict[str, float],
        reason: str,
    ) -> None:
        seq = self._next_sequence(context.session_id)
        event = Event(
            session_id=context.session_id,
            agent_id=context.agent_id,
            event_type=EventType.POLICY_EVALUATED,
            payload={
                "policy": "harmful_request_check",
                "score": round(score, 4),
                "signals": signals,
                "reason": reason,
                "action": context.action,
                "threshold": self._threshold,
            },
            sequence_num=seq,
        )
        await self._writer.write(event)  # type: ignore[union-attr]

    def _next_sequence(self, session_id: str) -> int:
        count = self._sequence_counters.get(session_id, 0) + 1
        self._sequence_counters[session_id] = count
        return count
