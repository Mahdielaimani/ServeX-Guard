"""Tests for query drift detection."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from servexguard.core import CheckStatus, ServeXGuard
from servexguard.drift import (
    VECTOR_DIM,
    DriftNotMeasuredError,
    compute_drift,
    detect_drift,
    embed,
)

BANKING = [
    "Quels sont les frais pour ouvrir un compte bancaire ?",
    "Comment obtenir un credit immobilier ?",
    "Quel est le plafond de retrait de ma carte bancaire ?",
    "Comment faire un virement vers un compte a l'etranger ?",
    "Quels documents faut-il pour ouvrir un compte courant ?",
    "Quel est le taux d'interet d'un credit a la consommation ?",
    "Comment opposer ma carte bancaire en cas de vol ?",
    "Quels sont les frais de tenue de compte par mois ?",
]
MORE_BANKING = [
    "Quels sont les frais d'un virement bancaire ?",
    "Comment demander un credit a la consommation ?",
    "Quel est le plafond de ma carte de retrait ?",
    "Quels documents pour un credit immobilier ?",
]
COOKING = [
    "Quelle recette de tajine au poulet et aux olives ?",
    "Combien de temps pour cuire un couscous aux legumes ?",
    "Comment preparer une harira pour le ramadan ?",
    "Quelles epices dans une pastilla au pigeon ?",
]


def _rows(texts: list[str]) -> list[dict]:
    return [{"question": text, "answer": "", "contexts": []} for text in texts]


@pytest.fixture(autouse=True)
def _in_cwd(tmp_path, monkeypatch):
    """Run each drift test inside a temp cwd (path-traversal guard)."""
    monkeypatch.chdir(tmp_path)


def test_the_same_questions_do_not_drift():
    baseline = embed(BANKING)
    assert compute_drift(baseline, baseline) == 0.0


def test_one_extra_word_is_not_a_drift_alarm():
    """In 0.2.1 this scored 0.8, the same as a completely different topic."""
    edited = [BANKING[0] + " aujourd'hui"] + BANKING[1:]
    assert compute_drift(embed(BANKING), embed(edited)) < 0.05


def test_another_topic_drifts_more_than_the_same_topic():
    baseline = embed(BANKING)
    same = compute_drift(baseline, embed(MORE_BANKING))
    other = compute_drift(baseline, embed(COOKING))
    assert other > same
    assert other > 0.25


@pytest.mark.parametrize(
    "baseline,edited",
    [
        (["هل توجد رسوم لفتح حساب بنكي؟", "كيف أحصل على قرض سكني؟"],
         ["هل تُوجد رسوم لفتح حساب بنكي؟", "كيف أحصل على قرض سكني؟"]),
        (["wach kaynin chi masarif bach nhel hsab?", "kifach ndir virement?"],
         ["WACH kaynin chi masarif bach nhel hsab?", "kifach ndir virement?"]),
    ],
    ids=["arabic-diacritic", "darija-latin-case"],
)
def test_spelling_noise_is_not_drift(baseline, edited):
    assert compute_drift(embed(baseline), embed(edited)) == 0.0


def test_vectors_do_not_depend_on_the_rest_of_the_batch():
    """The 0.2.1 flaw: a vocabulary rebuilt per run made baselines incomparable."""
    alone = embed([BANKING[0]])[0]
    in_batch = embed(BANKING)[0]
    assert np.array_equal(alone, in_batch)
    assert alone.shape == (VECTOR_DIM,)


def test_the_baseline_stores_no_text(tmp_path):
    detect_drift(_rows(BANKING), "baseline.npy", save_baseline=True)
    raw = Path("baseline.npy").read_bytes()
    assert b"bancaire" not in raw
    assert "bancaire".encode("utf-16-le") not in raw
    assert "bancaire".encode("utf-32-le") not in raw


def test_missing_baseline_is_not_measured_and_not_silently_created():
    """A first run used to score 0.0, pass, and bake in whatever it saw."""
    with pytest.raises(DriftNotMeasuredError, match="no baseline exists"):
        detect_drift(_rows(BANKING), "baseline.npy")
    assert not Path("baseline.npy").exists()


def test_no_baseline_path_is_not_measured():
    with pytest.raises(DriftNotMeasuredError, match="no baseline file"):
        detect_drift(_rows(BANKING))


def test_no_questions_is_not_measured():
    with pytest.raises(DriftNotMeasuredError, match="no questions"):
        detect_drift([{"question": ""}], "baseline.npy")


def test_an_old_baseline_is_not_compared():
    np.save("baseline.npy", np.zeros((3, 256), dtype=np.float32))
    with pytest.raises(DriftNotMeasuredError, match="older version"):
        detect_drift(_rows(BANKING), "baseline.npy")


def test_save_baseline_replaces_without_comparing():
    assert detect_drift(_rows(COOKING), "baseline.npy", save_baseline=True) is None
    assert detect_drift(_rows(BANKING), "baseline.npy", save_baseline=True) is None
    assert detect_drift(_rows(BANKING), "baseline.npy") == 0.0


def test_baseline_path_must_stay_in_the_working_directory():
    with pytest.raises(ValueError, match="escapes"):
        detect_drift(_rows(BANKING), "../baseline.npy")


def _guard(**kwargs) -> ServeXGuard:
    return ServeXGuard(
        min_faithfulness=0.0,
        min_relevancy=0.0,
        min_context_recall=0.0,
        check_drift=True,
        baseline_path="baseline.npy",
        **kwargs,
    )


def test_gate_blocks_on_a_missing_baseline():
    check = _guard()._run_drift_detection(_rows(BANKING))
    assert check.status == CheckStatus.NOT_MEASURED
    assert "--save-baseline" in check.details["fix"]


def test_gate_does_not_report_a_saved_baseline_as_a_comparison():
    check = _guard(save_baseline=True)._run_drift_detection(_rows(BANKING))
    assert check.status == CheckStatus.SKIPPED
    assert check.score is None


def test_gate_scores_against_a_saved_baseline():
    _guard(save_baseline=True)._run_drift_detection(_rows(BANKING))
    guard = _guard()
    assert guard._run_drift_detection(_rows(BANKING)).status == CheckStatus.PASSED
    assert guard._run_drift_detection(_rows(COOKING)).status == CheckStatus.FAILED
