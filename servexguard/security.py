"""
Security module — PII detection (Presidio) + prompt injection scanning.

Global-first by design: no country-specific logic lives here. PII fallback
patterns are universal (ISO IBAN, E.164 phone, RFC-ish email, credit card,
IP, generic alphanumeric IDs). Locale-specific entities (e.g. Moroccan CIN,
French CNSS) are user-supplied via ``custom_entities`` in ``servexguard.yaml``.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Iterable
from functools import lru_cache

from servexguard import presets as pii_presets_module

logger = logging.getLogger(__name__)

# Soft limit for context-window stuffing detection (tokens). Warn, don't fail.
CONTEXT_STUFFING_TOKENS = 8000

# Hard cap on characters fed to any regex — prevents ReDoS (catastrophic
# backtracking) on adversarially crafted long inputs.
MAX_SCAN_CHARS = 10_000
# Injection scans walk long fields in windows of the size above, up to this much.
MAX_INJECTION_CHARS = 200_000
_WINDOW_OVERLAP = 500


def _safe_scan(text: str) -> str:
    """Truncate input to :data:`MAX_SCAN_CHARS` before regex matching.

    Guards against ReDoS: even a pathological input can only ever drive the
    regex engine over a bounded prefix.

    Args:
        text: Raw input string.

    Returns:
        The original string, or its first ``MAX_SCAN_CHARS`` chars.
    """
    if len(text) > MAX_SCAN_CHARS:
        logger.warning(
            "Input (%d chars) truncated to %d for safe regex scan",
            len(text), MAX_SCAN_CHARS,
        )
        return text[:MAX_SCAN_CHARS]
    return text

# ── Prompt injection patterns ────────────────────────────────────
# Written against normalized text (see _normalize_for_match): lower case, no
# accents, no Arabic diacritics, one form of alif, ya and ta marbuta.
#
# This is a first filter for known phrasings, in the languages this tool serves.
# It cannot catch a reworded attack, and Darija has no fixed spelling, so a clean
# result means "no known pattern", never "not injectable".
_OVERRIDE_EN = r"(?:instructions?|prompts?|rules?|directions?|guidelines?|guidance|context)"
_OVERRIDE_FR = r"(?:instructions?|consignes?|regles?|directives?|prompts?|invites?)"
_OVERRIDE_AR = r"(?:التعليمات|الاوامر|القواعد|التوجيهات|تعليماتك|توجيهاتك|اوامرك|قواعدك|البرومبت)"
_OVERRIDE_LATN = r"(?:instructions?|directives?|ta3limat|t3limat|l9awa3id|qawa3id|prompt)"
_REVEAL_FR = r"(?:montre|montrez|affiche|affichez|revele|revelez|donne|donnez|repete|repetez|imprime|imprimez|ecris|ecrivez|dis|dites)"  # noqa: E501
_REVEAL_AR = r"(?:اظهر|اظهري|اعرض|اعرضي|اكشف|اكشفي|اعطني|اعطيني|كرر|اطبع|اكتب|قل)"
_REVEAL_ARY = r"(?:ورني|وريني|وري|بين|بينلي|عطيني|عطني|قول|كتب|طبع)"
_REVEAL_LATN = r"(?:werri|wri|wrini|wriyni|werrini|3tini|3tiny|3tih|bayen|gol|goul|9ol|kteb)"
_PEOPLE_FR = r"(?:clients?|utilisateurs?|usagers?)"
_PEOPLE_AR = r"(?:العملاء|الزبناء|الزبائن|المستخدمين)"
_PEOPLE_ARY = r"(?:الكليان|الناس|الزبناء|العملاء)"
_PEOPLE_LATN = r"(?:clients?|klyan|lklyan|nass|ness|zbon|zbayen)"

_EVERY_PERSON_FR = r"(?:chaque|tous\s+les|toutes\s+les)\s+(?:clients?|utilisateurs?)"

INJECTION_PATTERNS = [
    # Intent, in any wording these families can reach: stop obeying, role-play
    # without limits, recite the prompt, everyone's data. English:
    r"\b(?:stop|quit)\s+following\s+(?:\w+\s+){0,3}?(?:rules|instructions|guidelines|guidance)\b",
    r"\bpretend\s+(?:that\s+)?you\s+(?:have\s+no|are\s+not|aren't|don't\s+have|do\s+not\s+have)\b",
    r"\b(?:act|behave|respond|answer)\s+(?:\w+\s+){0,5}?(?:without|with\s+no)\s+(?:\w+\s+){0,2}?(?:rules|restrictions|filters?|limits|limitations)\b",
    r"\bfrom\s+now\s+on,?\s+(?:you\s+(?:will|must|should|shall|are\s+to)\s+)?(?:act|behave|respond|answer|ignore|obey)\b",
    r"\b(?:instructions?|rules|prompt)\s+(?:that\s+)?you\s+(?:received|were\s+given|got)\b",
    r"\b(?:disregard|ignore|forget|bypass)\s+(?:\w+\s+){0,2}?system\s+message\b",
    r"\b(?:copy|repeat|recite|quote)\b.{0,40}\bword\s+for\s+word\b",
    r"\b(?:written|text|everything|said)\s+(?:above|before)\s+this\s+message\b",
    r"\b(?:balances?|accounts?|data|details|records)\s+of\s+(?:every|each|all|other)\s+(?:customers?|clients?|users?)\b",
    # French
    r"\b(?:arrete|arretez|cesse|cessez)\s+de\s+(?:suivre|respecter|appliquer)\b",
    r"\bfais\s+comme\s+si\s+tu\s+(?:n'avais|n'as|etais)\b|\bfaites\s+comme\s+si\s+vous\s+(?:n'aviez|etiez)\b",
    r"\b(?:agis|agissez|reponds|repondez)\s+(?:\w+\s+){0,5}?sans\s+(?:\w+\s+){0,2}?(?:regles?|restrictions?|filtres?|limites?)\b",
    r"\ba\s+partir\s+de\s+maintenant,?\s+(?:tu|vous)\s+(?:agis|agissez|reponds|repondez|ignores|ignorez|obeis|obeissez)\b",
    r"\b(?:instructions?|consignes?|regles?)\s+(?:que\s+(?:tu\s+as|vous\s+avez)|qu'on\s+t'a|qu'on\s+vous\s+a)\b",
    r"\b(?:oublie|oubliez)\s+tout\s+ce\s+qu",
    r"\bmot\s+pour\s+mot\b.{0,60}\b(?:avant|au[\s-]dessus)\b|\b(?:avant|au[\s-]dessus\s+de)\s+ce\s+message\b",
    rf"\b(?:soldes?|comptes?|donnees|informations|coordonnees)\s+(?:de|des|d')\s*{_EVERY_PERSON_FR}\b",
    # Arabic
    r"توقف\s+عن\s+(?:اتباع|الالتزام)",
    r"(?:تصرف|تصرفي|اجب|اجيبي)\s+(?:\S+\s+){0,3}?(?:كانك|كما\s+لو|بدون|بلا)\s+(?:\S+\s+){0,2}?(?:قيود|قواعد|فلتر|حدود)",
    r"من\s+الان\s+(?:فصاعدا\s+)?(?:ستعمل|ستتصرف|تصرف|اجب|ستجيب|ستتجاهل)",
    r"(?:لخص|كرر|انسخ|ترجم)\s+(?:\S+\s+){0,2}?(?:التعليمات|القواعد|الاوامر)\s+(?:التي|اللي)",
    r"(?:قبل|فوق)\s+هذه\s+الرساله",
    r"انس\s+كل\s+ما",
    r"(?:رصيد|حساب|بيانات|معلومات)\s+كل\s+(?:عميل|زبون|مستخدم)",
    # Darija, Arabic script
    r"(?:ما\s*تبقاش|ماتبقاش)\s+(?:تتبع|تحترم)",
    r"دير\s+راسك\s+ما\s*عندك",
    r"من\s+دابا\s+غادي\s+(?:تخدم|تجاوب|تدير)",
    r"(?:لخص|عاود|نقل)(?:\s+ليا)?\s+(?:\S+\s+){0,2}?(?:التعليمات|القواعد)\s+اللي",
    r"نسا\s+كلشي",
    r"(?:قبل|فوق)\s+هاد\s+الميساج",
    r"(?:الصولد|الحساب|الكونط|الفلوس)\s+ديال\s+(?:كل|كاع)\s+(?:كليان|زبون|الكليان)",
    # Darija, Latin script
    r"\bma\s*tb9ach\s+(?:tbe3|t7tarem|tebe3)\b",
    r"\bdir\s+rassek\s+ma\s*3endek\b",
    r"\bmn\s+daba\s+ghadi\s+(?:tkhdem|tjaweb|dir)\b",
    r"\b(?:lekhes|lkhes|3awed|ne9el)(?:\s+liya)?\s+(?:\w+\s+){0,2}?(?:t3limat|ta3limat|instructions?)\s+li\b",
    r"\bnsa\s+kolchi\b",
    r"\b(?:9bel|fo9)\s+had\s+(?:l)?message\b",
    r"\b(?:solde|compte|hsab|lhsab)\s+dyal\s+(?:kol|ga3)\s+(?:clients?|zbon|klyan|lklyan)\b",
    # English: override
    rf"\b(?:ignore|disregard|forget|skip|override|bypass)\s+(?:\w+\s+){{0,4}}?(?:previous|prior|above|earlier|preceding|system|original)\s+(?:\w+\s+){{0,2}}?{_OVERRIDE_EN}\b",
    rf"\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|your\s+)+{_OVERRIDE_EN}\b",
    r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?above\b",
    r"\bdisregard\s+(?:all\s+)?previous\b",
    r"\bforget\s+(?:all\s+)?previous\b",
    r"\byou\s+are\s+now\s+(?:dan\b|unrestricted|unfiltered|jailbroken|evil|free\s+of|in\s+\w+\s+mode|an?\s+(?:unrestricted|unfiltered|different|new)\b)",
    r"\b(?:developer|debug|admin|god|jailbreak)\s+mode\b",
    r"\bnew\s+instructions?\s*:",
    r"\bsystem\s*:\s*you\s+are\b",
    r"</?(?:system|user|assistant)\s*>",
    # English: reveal the prompt
    r"\b(?:repeat|reveal|print|show|display|output|leak)\s+(?:me\s+)?(?:\w+\s+){0,2}?(?:system\s+prompt|prompt|(?:system|hidden|initial|original)\s+instructions?|your\s+instructions?)\b",
    r"\bwhat\s+(?:are|were)\s+your\s+(?:\w+\s+)?instructions\b",
    # English: other people's data
    r"\btell\s+me\s+about\s+other\s+(?:users|customers|clients)\b",
    r"\bwhat\s+data\s+do\s+you\s+have\s+(?:on|about)\s+(?:him|her|them|other|another|every|all)\b",
    r"\b(?:show|dump|give)\s+(?:me\s+)?(?:the|your|whole|entire|full)\s+(?:\w+\s+)?database\b",
    r"\blist\s+all\s+(?:users|customers|clients|accounts|entries)\b",
    r"\baccess\s+(?:other|all)\s+(?:users|records|customers|clients|accounts)\b",
    # French
    rf"\b(?:ignore|ignorez|ignorer|oublie|oubliez|oublier|outrepasse|contourne|contournez)\s+(?:\w+\s+){{0,4}}?{_OVERRIDE_FR}\b",
    rf"\bne\s+(?:tiens|tenez|tient)\s+(?:pas|plus)\s+compte\s+(?:\w+\s+){{0,4}}?{_OVERRIDE_FR}\b",
    rf"\bfais\s+abstraction\s+(?:\w+\s+){{0,4}}?{_OVERRIDE_FR}\b",
    rf"\b{_REVEAL_FR}(?:[\s-]+moi)?\s+(?:\w+\s+){{0,3}}?(?:prompt|invite\s+systeme|instructions?\s+(?:systeme|initiales|cachees)|tes\s+(?:instructions|consignes)|vos\s+(?:instructions|consignes))\b",
    r"\b(?:quelles?\s+sont|quels?\s+sont)\s+(?:tes|vos)\s+(?:instructions|consignes|regles)\b",
    r"\b(?:tu\s+es|vous\s+etes)\s+(?:maintenant|desormais)\s+(?:dan\b|sans\s+(?:restriction|filtre|limite)|en\s+mode\b|libre\b)",
    r"\bmode\s+(?:developpeur|administrateur|debogage|admin)\b",
    rf"\b(?:liste|listez|lister|affiche|affichez|montre|montrez|donne|donnez)(?:[\s-]+moi)?\s+(?:\w+\s+){{0,3}}?(?:de\s+)?(?:tous\s+les|toutes\s+les|les\s+autres|d'autres|des\s+autres)\s+{_PEOPLE_FR}\b",
    rf"\b(?:des|de|aux)\s+(?:autres|tous\s+les)\s+{_PEOPLE_FR}\b.{{0,40}}\b(?:donnees|comptes|soldes|informations|coordonnees)\b",
    rf"\b(?:donnees|comptes|soldes|informations|coordonnees)\s+(?:\w+\s+){{0,2}}?(?:des\s+autres|de\s+tous\s+les|d'autres)\s+{_PEOPLE_FR}\b",
    r"\b(?:montre|montrez|affiche|affichez|donne|donnez)(?:[\s-]+moi)?\s+(?:\w+\s+){0,2}?base\s+de\s+donnees\b",
    # Arabic
    rf"(?:تجاهل|تجاهلي|تجاهلوا|انس|انسي|اهمل|اهملي|تخط|لا\s+تلتزم|لا\s+تتبع)\s+(?:\S+\s+){{0,3}}?{_OVERRIDE_AR}",
    rf"(?:^|\s){_REVEAL_AR}\s+(?:\S+\s+){{0,2}}?(?:موجه|البرومبت|برومبت|تعليماتك|اوامرك|التعليمات\s+(?:السريه|الاصليه|السابقه))",
    r"(?:انت|اصبحت)\s+(?:الان\s+)?(?:بدون|بلا)\s+(?:قيود|حدود|فلتر)",
    rf"(?:بيانات|معلومات|حسابات|ارصده)\s+(?:\S+\s+){{0,2}}?(?:جميع|كل|باقي|بقيه|سائر)\s+{_PEOPLE_AR}",
    r"(?:اعرض|اظهر|اعطني)\s+(?:\S+\s+){0,2}?قاعده\s+البيانات",
    # Darija, Arabic script
    rf"(?:نسا|نساي|ننسا|تنسا|خلي\s+عليك|ماتبعش|ما\s+تبعش)\s+(?:\S+\s+){{0,3}}?{_OVERRIDE_AR}",
    rf"(?:^|\s){_REVEAL_ARY}(?:\s+ليا|\s+لي)?\s+(?:\S+\s+){{0,2}}?(?:البرومبت|برومبت|سيستم|تعليماتك|التعليمات\s+ديالك|التعليمات\s+ديال)",
    rf"(?:معلومات|بيانات|حسابات|الحسابات|فلوس)\s+(?:\S+\s+){{0,1}}?ديال\s+(?:كاع|جميع|كل|باقي)?\s*{_PEOPLE_ARY}",
    rf"{_REVEAL_ARY}(?:\s+ليا|\s+لي)?\s+(?:\S+\s+){{0,2}}?(?:كاع|جميع)\s+{_PEOPLE_ARY}",
    # Darija, Latin script
    rf"\b(?:nsa|nssa|ensa|nsay|tjahel|tjahl|khelli\s+3lik|ma\s*tb3ch|matbe3ch|skhi\s+b)\s+(?:\w+\s+){{0,3}}?{_OVERRIDE_LATN}\b",
    rf"\b{_REVEAL_LATN}(?:\s+liya|\s+lia|\s+li|\s+lya)?\s+(?:\w+\s+){{0,2}}?(?:prompt|ta3limat|t3limat|instructions?)\b",
    rf"\b(?:ma3lomat|m3lomat|donnees|lhisabat|hisabat|7isabat|comptes?|flouss)\s+(?:\w+\s+){{0,1}}?dyal\s+(?:ga3\s+|kolchi\s+|kamlin\s+|les\s+)?{_PEOPLE_LATN}\b",
]

# ── Compiled regex for performance ───────────────────────────────
_compiled_patterns = [re.compile(p) for p in INJECTION_PATTERNS]

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­ـ"))
_ARABIC_FORMS = str.maketrans(
    {"أ": "ا", "إ": "ا", "آ": "ا", "ى": "ي", "ة": "ه", "ؤ": "و", "ئ": "ي"}
)
# "i.g.n.o.r.e" or "i g n o r e": at least three lone letters joined by a separator.
_SPACED_LETTERS = re.compile(r"(?<!\w)(?:\w[.\-_*\s]){3,}\w(?!\w)")
_SEPARATORS = re.compile(r"[.\-_*\s]")


def _normalize_for_match(text: str) -> str:
    """Remove what hides a known phrase: case, accents, invisible characters, spacing."""
    text = unicodedata.normalize("NFKD", text.translate(_ZERO_WIDTH))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = text.casefold().translate(_ARABIC_FORMS)
    text = _SPACED_LETTERS.sub(lambda m: _SEPARATORS.sub("", m.group()), text)
    return text.replace("’", "'")


def _windows(text: str) -> Iterable[str]:
    """Split long text into overlapping windows, up to :data:`MAX_INJECTION_CHARS`.

    A plain cut at the regex limit would let an attacker pad a retrieved document
    and put the payload past it. Windows keep each regex run bounded and cover it.
    """
    text = text[:MAX_INJECTION_CHARS]
    step = MAX_SCAN_CHARS - _WINDOW_OVERLAP
    for start in range(0, max(len(text) - _WINDOW_OVERLAP, 1), step):
        yield text[start : start + MAX_SCAN_CHARS]


# spaCy model families Presidio can use. Arabic has none, so it stays on regex.
SPACY_MODEL_PREFIX = {
    "en": "en_core_web",
    "fr": "fr_core_news",
    "es": "es_core_news",
    "de": "de_core_news",
}

# ── Universal PII fallback patterns ──────────────────────────────
# Order matters only for readability; each is scanned independently.
UNIVERSAL_PII_PATTERNS: dict[str, str] = {
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    # E.164: "+" country code then national number, optional separators.
    "PHONE": r"\+[1-9]\d{0,3}(?:[\s.-]?\d{2,4}){2,4}",
    # ISO 13616 IBAN: 2-letter country, 2 check digits, up to 30 BBAN chars.
    "IBAN": r"\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}",
    "CREDIT_CARD": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    "IP_ADDRESS": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    # Generic ID: 6-12 char uppercase/digit token containing BOTH a letter
    # and a digit (avoids matching ordinary words or plain numbers).
    "ID_NUMBER": r"\b(?=[A-Z0-9]*[A-Z])(?=[A-Z0-9]*\d)[A-Z0-9]{6,12}\b",
}


def _compile_custom_entities(
    custom_entities: list[dict] | None,
) -> list[tuple[str, re.Pattern]]:
    """Compile user-defined ``custom_entities`` into ``(label, regex)`` pairs.

    Args:
        custom_entities: List of dicts with ``pattern`` and ``label`` keys.

    Returns:
        List of ``(label, compiled_pattern)`` tuples. Invalid regexes are
        logged and skipped (never crash the scan).
    """
    compiled: list[tuple[str, re.Pattern]] = []
    for ent in custom_entities or []:
        pattern = ent.get("pattern")
        label = ent.get("label", "CUSTOM_ENTITY")
        if not pattern:
            continue
        try:
            compiled.append((label, re.compile(pattern)))
        except re.error as exc:
            logger.warning("Skipping invalid custom entity %r: %s", label, exc)
    return compiled


@lru_cache(maxsize=8)
def _build_analyzer(language: str):
    """Build a Presidio analyzer from spaCy models that are already installed.

    Presidio's default engine downloads a 400 MB English model at runtime, and
    would analyse French or Arabic text with it. Neither is acceptable in a tool
    that promises to run offline, so a missing model means the regex patterns,
    with a warning that says how to get the better detector.

    Args:
        language: Language code to analyse.

    Returns:
        A ready analyzer, or ``None`` when Presidio or its model is unavailable.
    """
    try:
        import spacy
        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider
    except ImportError:
        logger.warning(
            "Presidio not installed, using regex patterns. Run: pip install servex-guard[pii]"
        )
        return None

    prefix = SPACY_MODEL_PREFIX.get(language)
    candidates = [f"{prefix}_{size}" for size in ("lg", "md", "sm")] if prefix else []
    model = next((name for name in candidates if spacy.util.is_package(name)), None)
    if model is None:
        hint = f" Run: python -m spacy download {candidates[-1]}" if candidates else ""
        logger.warning(
            "No spaCy model installed for language %r, using regex patterns.%s", language, hint
        )
        return None

    engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": model}],
        }
    ).create_engine()
    return AnalyzerEngine(nlp_engine=engine, supported_languages=[language])


def pii_detector(language: str) -> str:
    """Name the detector a scan in ``language`` uses, for the report.

    A reader has to know whether person names were even looked for.
    """
    if _build_analyzer(language) is None:
        return "regex (cannot detect person names)"
    return "presidio"


def scan_pii(
    data: list[dict],
    language: str = "en",
    custom_entities: list[dict] | None = None,
    presets: list[str] | None = None,
) -> list[dict]:
    """Scan RAG answers for PII leaks.

    Uses Microsoft Presidio when available (any supported language), otherwise
    falls back to universal regex patterns. User-defined ``custom_entities``
    are always applied on top of the built-in detection.

    Args:
        data: List of dicts with an ``answer`` field.
        language: Presidio analysis language ("en", "fr", "ar", "de", ...).
            Falls back to "en" if the language model is not installed.
        custom_entities: Optional user regex entities (``pattern``, ``label``).
        presets: Locale presets to apply on top, e.g. ``["ma"]``.

    Returns:
        List of detected PII leaks with location and type. Overlapping findings
        are merged, keeping the longest, so one number is one leak.
    """
    presets = presets or []
    pii_presets_module.validate(presets)

    analyzer = _build_analyzer(language)
    if analyzer is None:
        return _scan_pii_fallback(data, custom_entities=custom_entities, presets=presets)

    try:
        entities = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "IBAN_CODE",
            "CREDIT_CARD",
            "PERSON",
            "LOCATION",
            "IP_ADDRESS",
            "URL",
        ]
        leaks: list[dict] = []
        custom = _compile_custom_entities(custom_entities)

        for i, row in enumerate(data):
            answer = _safe_scan(row.get("answer", ""))
            if not answer:
                continue

            results = analyzer.analyze(
                text=answer, entities=entities, language=language
            )

            for result in results:
                if result.score >= 0.7:
                    leaks.append(
                        _make_leak(
                            i, row, result.entity_type,
                            round(result.score, 2), result.start, result.end,
                        )
                    )

            leaks.extend(_scan_custom(i, row, answer, custom))
            leaks.extend(_scan_presets(i, row, answer, presets))

        leaks = _merge_overlaps(leaks)
        logger.info("PII scan: %d leaks in %d answers", len(leaks), len(data))
        return leaks

    except Exception as exc:  # a scan that dies must not take the gate down with it
        logger.warning("Presidio scan failed (%s); using regex patterns", exc)
        return _scan_pii_fallback(data, custom_entities=custom_entities, presets=presets)


def _scan_pii_fallback(
    data: list[dict],
    custom_entities: list[dict] | None = None,
    presets: list[str] | None = None,
) -> list[dict]:
    """Universal regex-based PII detection (fallback when Presidio absent).

    Args:
        data: List of dicts with an ``answer`` field.
        custom_entities: Optional user regex entities (``pattern``, ``label``).
        presets: Locale presets to apply on top, e.g. ``["ma"]``.

    Returns:
        List of detected PII leaks.
    """
    leaks: list[dict] = []
    custom = _compile_custom_entities(custom_entities)

    for i, row in enumerate(data):
        answer = _safe_scan(row.get("answer", ""))
        if not answer:
            continue
        for entity_type, pattern in UNIVERSAL_PII_PATTERNS.items():
            for match in re.finditer(pattern, answer):
                if entity_type == "CREDIT_CARD" and not _passes_luhn(match.group()):
                    continue
                leaks.append(
                    _make_leak(
                        i, row, entity_type, 0.9, match.start(), match.end()
                    )
                )
        leaks.extend(_scan_custom(i, row, answer, custom))
        leaks.extend(_scan_presets(i, row, answer, presets or []))

    return _merge_overlaps(leaks)


def _scan_custom(
    i: int, row: dict, answer: str, custom: list[tuple[str, re.Pattern]]
) -> list[dict]:
    """Apply compiled custom-entity patterns to a single answer."""
    found: list[dict] = []
    for label, pattern in custom:
        for match in pattern.finditer(answer):
            found.append(_make_leak(i, row, label, 0.95, match.start(), match.end()))
    return found


def _scan_presets(i: int, row: dict, answer: str, presets: list[str]) -> list[dict]:
    """Apply locale presets to a single answer."""
    return [
        _make_leak(i, row, label, score, start, end)
        for label, score, start, end in pii_presets_module.scan_presets(answer, presets)
    ]


def _passes_luhn(number: str) -> bool:
    """Card numbers carry a check digit. Random 16-digit strings mostly fail it."""
    digits = [int(ch) for ch in number if ch.isdigit()]
    total = 0
    for position, digit in enumerate(reversed(digits)):
        if position % 2:
            digit = digit * 2 - 9 if digit > 4 else digit * 2
        total += digit
    return total % 10 == 0


_NER_ENTITIES = {"PERSON", "LOCATION"}


def _merge_overlaps(leaks: list[dict]) -> list[dict]:
    """Keep one finding per overlapping span.

    Exact formats beat statistical guesses: spaCy has read "CIN BK123456" as a
    place, which would otherwise hide the identifier inside a longer span. After
    that, the longest and then the most confident wins.
    """
    ranked = sorted(
        leaks,
        key=lambda x: (x["entity_type"] in _NER_ENTITIES, x["start"] - x["end"], -x["score"]),
    )
    kept: list[dict] = []
    for leak in ranked:
        if not any(
            k["row"] == leak["row"] and k["start"] < leak["end"] and leak["start"] < k["end"]
            for k in kept
        ):
            kept.append(leak)
    return sorted(kept, key=lambda x: (x["row"], x["start"]))


def _make_leak(
    i: int, row: dict, entity_type: str, score: float, start: int, end: int
) -> dict:
    """Build a structured PII leak record."""
    answer = row.get("answer", "")
    return {
        "row": i,
        "entity_type": entity_type,
        "score": score,
        "start": start,
        "end": end,
        "text_snippet": answer[max(0, start - 10) : end + 10],
        "question": row.get("question", "")[:80],
    }


def _count_tokens(text: str) -> int:
    """Estimate tokens at four characters each, the usual rule of thumb.

    Only feeds a warning. tiktoken would fetch its encoding from the internet on
    first use, which is a poor trade for a slightly better estimate.
    """
    return max(len(text.split()), len(text) // 4)


def _fields_to_scan(row: dict) -> Iterable[tuple[str, str]]:
    """Yield every text a row carries, including the retrieved contexts.

    Contexts are where indirect injection lives: a poisoned document does its work
    without the user ever typing anything suspicious.
    """
    for field_name in ("question", "answer"):
        text = row.get(field_name)
        if isinstance(text, str) and text:
            yield field_name, text
    contexts = row.get("contexts")
    if isinstance(contexts, list):
        for index, text in enumerate(contexts):
            if isinstance(text, str) and text:
                yield f"contexts[{index}]", text


def scan_injection(data: list[dict]) -> list[dict]:
    """Scan questions, answers and retrieved contexts for known injection phrasings.

    Covers English, French, Arabic and Darija in both scripts. Also emits a
    (non-failing) warning when an input exceeds :data:`CONTEXT_STUFFING_TOKENS`.

    Args:
        data: Dicts with ``question``, ``answer`` and optionally ``contexts``.

    Returns:
        One finding per pattern per field (context stuffing is warned, not listed).
        ``text_snippet`` is taken from the normalized text.
    """
    vulnerabilities: list[dict] = []

    for i, row in enumerate(data):
        for field_name, text in _fields_to_scan(row):
            tokens = _count_tokens(text)
            if tokens > CONTEXT_STUFFING_TOKENS:
                logger.warning(
                    "Row %d %s has %d tokens (> %d) — possible context stuffing",
                    i, field_name, tokens, CONTEXT_STUFFING_TOKENS,
                )

            matched: set[int] = set()
            for window in _windows(text):
                normalized = _normalize_for_match(window)
                for number, pattern in enumerate(_compiled_patterns):
                    if number in matched:
                        continue
                    match = pattern.search(normalized)
                    if match:
                        matched.add(number)
                        vulnerabilities.append({
                            "row": i,
                            "field": field_name,
                            "pattern": match.group(),
                            "start": match.start(),
                            "end": match.end(),
                            "text_snippet": normalized[
                                max(0, match.start() - 20) : match.end() + 20
                            ],
                            "question": str(row.get("question", ""))[:80],
                        })

    logger.info(
        "Injection scan: %d risks in %d samples", len(vulnerabilities), len(data)
    )
    return vulnerabilities
