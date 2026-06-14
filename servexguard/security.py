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

logger = logging.getLogger(__name__)

# Soft limit for context-window stuffing detection (tokens). Warn, don't fail.
CONTEXT_STUFFING_TOKENS = 8000

# Hard cap on characters fed to any regex — prevents ReDoS (catastrophic
# backtracking) on adversarially crafted long inputs.
MAX_SCAN_CHARS = 10_000


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

# ── Prompt injection patterns (universal attack vectors) ─────────
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"ignore\s+(all\s+)?above",
    r"disregard\s+(all\s+)?previous",
    r"forget\s+(all\s+)?previous",
    r"you\s+are\s+now\s+",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*you\s+are",
    r"</?(system|user|assistant)\s*>",
    r"repeat\s+the\s+(system\s+)?prompt",
    r"reveal\s+(your\s+)?(system\s+)?prompt",
    r"what\s+are\s+your\s+instructions",
    r"print\s+your\s+(system\s+)?prompt",
    # RAG-specific data-exfiltration attempts
    r"tell\s+me\s+about\s+other\s+(users|customers|clients)",
    r"what\s+data\s+do\s+you\s+have\s+(on|about)",
    r"show\s+me\s+the\s+(database|documents|data)",
    r"list\s+all\s+(users|documents|entries)",
    r"what\s+(other|else)\s+do\s+you\s+know",
    r"access\s+(other|all)\s+(users|records)",
]

# ── Compiled regex for performance ───────────────────────────────
_compiled_patterns = [
    re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS
]

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


def scan_pii(
    data: list[dict],
    language: str = "en",
    custom_entities: list[dict] | None = None,
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

    Returns:
        List of detected PII leaks with location and type.
    """
    try:
        from presidio_analyzer import AnalyzerEngine

        analyzer = AnalyzerEngine()
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

            try:
                results = analyzer.analyze(
                    text=answer, entities=entities, language=language
                )
            except Exception as exc:  # unsupported/missing language model
                logger.warning(
                    "Presidio language %r unavailable (%s); falling back to 'en'",
                    language,
                    exc,
                )
                results = analyzer.analyze(
                    text=answer, entities=entities, language="en"
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

        logger.info("PII scan: %d leaks in %d answers", len(leaks), len(data))
        return leaks

    except ImportError:
        logger.warning("Presidio not installed. Run: pip install presidio-analyzer")
        return _scan_pii_fallback(data, custom_entities=custom_entities)


def _scan_pii_fallback(
    data: list[dict],
    custom_entities: list[dict] | None = None,
) -> list[dict]:
    """Universal regex-based PII detection (fallback when Presidio absent).

    Args:
        data: List of dicts with an ``answer`` field.
        custom_entities: Optional user regex entities (``pattern``, ``label``).

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
                leaks.append(
                    _make_leak(
                        i, row, entity_type, 0.9, match.start(), match.end()
                    )
                )
        leaks.extend(_scan_custom(i, row, answer, custom))

    return leaks


def _scan_custom(
    i: int, row: dict, answer: str, custom: list[tuple[str, re.Pattern]]
) -> list[dict]:
    """Apply compiled custom-entity patterns to a single answer."""
    found: list[dict] = []
    for label, pattern in custom:
        for match in pattern.finditer(answer):
            found.append(_make_leak(i, row, label, 0.95, match.start(), match.end()))
    return found


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
    """Count tokens with tiktoken if available, else a whitespace estimate."""
    try:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return len(text.split())


def scan_injection(data: list[dict]) -> list[dict]:
    """Scan questions and answers for prompt injection attempts.

    Detects common injection patterns that could leak system prompts, override
    instructions, or exfiltrate other users' data. Also emits a (non-failing)
    warning when an input exceeds :data:`CONTEXT_STUFFING_TOKENS` tokens.

    Args:
        data: List of dicts with ``question`` and ``answer`` fields.

    Returns:
        List of detected injection risks (context stuffing is warned, not listed).
    """
    vulnerabilities: list[dict] = []

    for i, row in enumerate(data):
        for field_name in ["question", "answer"]:
            text = row.get(field_name, "")
            if not text:
                continue

            # Context-window stuffing — warn only, never hard-fail.
            tokens = _count_tokens(text)
            if tokens > CONTEXT_STUFFING_TOKENS:
                logger.warning(
                    "Row %d %s has %d tokens (> %d) — possible context stuffing",
                    i, field_name, tokens, CONTEXT_STUFFING_TOKENS,
                )

            scan_text = _safe_scan(text)
            for pattern in _compiled_patterns:
                match = pattern.search(scan_text)
                if match:
                    vulnerabilities.append({
                        "row": i,
                        "field": field_name,
                        "pattern": match.group(),
                        "start": match.start(),
                        "end": match.end(),
                        "text_snippet": text[
                            max(0, match.start() - 20) : match.end() + 20
                        ],
                        "question": row.get("question", "")[:80],
                    })

    logger.info(
        "Injection scan: %d risks in %d samples", len(vulnerabilities), len(data)
    )
    return vulnerabilities
