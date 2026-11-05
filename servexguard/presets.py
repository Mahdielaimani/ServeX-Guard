"""
Locale PII presets: identifiers no universal pattern can know.

Opt-in by name (``security.pii_presets`` or ``--pii-preset``). Each detector
returns ``(label, score, start, end)`` spans. Where a format carries a check
digit it sets the score, but a failed check is still reported: a number an LLM
garbled by one digit has still leaked.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

Span = tuple[str, float, int, int]

# Eastern Arabic and Arabic-Indic digits, one character each, so spans still
# point at the right place in the original text.
ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")

_MA_RIB = re.compile(r"(?<![\w-])\d(?:[ -]?\d){23}(?![\w-])")
_MA_PHONE = re.compile(
    r"(?<![\d+])(?:\+212|00212|0)[ .-]?(?:\(0\)[ .-]?)?[5-7](?:[ .-]?\d){8}(?!\d)"
)
_MA_CIN = re.compile(r"\b[A-Z]{1,2}[ -]?\d{5,6}\b")
_MA_ICE = re.compile(r"(?i:\bICE\b)\D{0,12}(\d{15})\b")
_MA_CNSS = re.compile(r"(?i:\bCNSS\b)\D{0,12}(\d{9})\b")


def _rib_key_is_valid(digits: str) -> bool:
    """A Moroccan RIB ends in a key: 97 - (first 22 digits x 100 mod 97)."""
    return 97 - (int(digits[:22]) * 100 % 97) == int(digits[22:])


def _scan_ma(text: str) -> Iterable[Span]:
    for match in _MA_RIB.finditer(text):
        digits = re.sub(r"\D", "", match.group())
        score = 0.99 if _rib_key_is_valid(digits) else 0.7
        yield ("MA_RIB", score, match.start(), match.end())
    for match in _MA_PHONE.finditer(text):
        yield ("MA_PHONE", 0.9, match.start(), match.end())
    for match in _MA_CIN.finditer(text):
        yield ("MA_CIN", 0.85, match.start(), match.end())
    for match in _MA_ICE.finditer(text):
        yield ("MA_ICE", 0.9, match.start(1), match.end(1))
    for match in _MA_CNSS.finditer(text):
        yield ("MA_CNSS", 0.9, match.start(1), match.end(1))


PRESETS: dict[str, Callable[[str], Iterable[Span]]] = {"ma": _scan_ma}


def scan_presets(text: str, names: list[str]) -> list[Span]:
    """Run the named presets over ``text``.

    Args:
        text: Text to scan.
        names: Preset names. Validated by :func:`validate`.

    Returns:
        All spans found.
    """
    normalized = text.translate(ARABIC_DIGITS)
    return [span for name in names for span in PRESETS[name](normalized)]


def validate(names: list[str]) -> None:
    """Reject unknown names, so a typo cannot quietly switch detection off.

    Raises:
        ValueError: A name is not a known preset.
    """
    unknown = sorted(set(names) - set(PRESETS))
    if unknown:
        raise ValueError(
            f"Unknown PII preset: {', '.join(unknown)} (available: {', '.join(sorted(PRESETS))})"
        )
