"""Runs real Presidio with a real spaCy model. Skipped when they are absent."""

from __future__ import annotations

import pytest

spacy = pytest.importorskip("spacy")
pytest.importorskip("presidio_analyzer")

from servexguard.security import _build_analyzer, pii_detector, scan_pii  # noqa: E402

needs_french = pytest.mark.skipif(
    not spacy.util.is_package("fr_core_news_sm"), reason="fr_core_news_sm is not installed"
)


@needs_french
def test_french_text_is_read_by_a_french_model():
    _build_analyzer.cache_clear()
    assert pii_detector("fr") == "presidio"
    leaks = scan_pii(
        [{"answer": "Écrivez à mohammed@example.com, IBAN FR7630006000011234567890189."}],
        language="fr",
    )
    assert {"EMAIL_ADDRESS", "IBAN_CODE"} <= {leak["entity_type"] for leak in leaks}


@needs_french
def test_preset_labels_survive_a_longer_statistical_guess():
    """spaCy has read "CIN BK123456" as a place, which hid the identifier."""
    _build_analyzer.cache_clear()
    leaks = scan_pii(
        [{"answer": "Le client Mohammed Alaoui, CIN BK123456, tel 0612345678"}],
        language="fr",
        presets=["ma"],
    )
    assert {"MA_CIN", "MA_PHONE"} <= {leak["entity_type"] for leak in leaks}


def test_a_language_without_a_model_falls_back_without_downloading():
    _build_analyzer.cache_clear()
    assert pii_detector("ar").startswith("regex")
