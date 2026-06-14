"""Tests for query drift detection."""

from __future__ import annotations

import pytest

from servexguard.drift import detect_drift


def _q(text: str) -> dict:
    return {"question": text, "answer": "", "contexts": []}


@pytest.fixture(autouse=True)
def _in_cwd(tmp_path, monkeypatch):
    """Run each drift test inside a temp cwd (path-traversal guard)."""
    monkeypatch.chdir(tmp_path)


def test_no_baseline_returns_zero():
    """No baseline file → drift = 0.0 (baseline gets seeded)."""
    data = [_q("What is the deductible?"), _q("How do I file a claim?")]
    score = detect_drift(data, "baseline.npy")
    assert score == 0.0
    from pathlib import Path

    assert Path("baseline.npy").exists()  # seeded for next run


def test_same_data_low_drift():
    """Identical questions vs baseline → drift < 0.1."""
    data = [_q("What is the deductible?"), _q("How do I file a claim?")]
    detect_drift(data, "baseline.npy")  # seed baseline
    score = detect_drift(data, "baseline.npy")  # compare against itself
    assert score < 0.1


def test_empty_questions():
    """Empty data → returns 0.0 without crashing."""
    assert detect_drift([]) == 0.0
    assert detect_drift([{"question": ""}]) == 0.0


def test_save_baseline_refreshes():
    """--save-baseline overwrites the baseline with current embeddings."""
    from pathlib import Path

    detect_drift([_q("alpha beta")], "baseline.npy")
    before = Path("baseline.npy").stat().st_mtime_ns
    detect_drift([_q("gamma delta epsilon")], "baseline.npy", save_baseline=True)
    assert Path("baseline.npy").stat().st_mtime_ns >= before
