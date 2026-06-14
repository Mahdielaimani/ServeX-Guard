"""Tests for the RAGAS quality evaluator (no API calls).

The RAGAS/datasets stack is an optional extra and is not installed in the
base test environment. To cover the success path we inject lightweight fake
`ragas`, `ragas.metrics`, and `datasets` modules into ``sys.modules`` so the
lazy imports inside ``evaluate_quality`` resolve to our stubs.
"""

from __future__ import annotations

import builtins
import sys
import types

import pandas as pd
import pytest

from servexguard.evaluator import evaluate_quality

SAMPLE = [
    {"question": "q", "answer": "a", "contexts": ["c"], "ground_truth": "g"},
]


def _install_fake_ragas(monkeypatch, df: pd.DataFrame) -> None:
    """Register stub ragas/datasets modules whose evaluate() returns ``df``."""
    datasets_mod = types.ModuleType("datasets")

    class FakeDataset:
        @staticmethod
        def from_list(data):
            return {"_data": data}

    datasets_mod.Dataset = FakeDataset

    class FakeResult:
        def to_pandas(self):
            return df

    ragas_mod = types.ModuleType("ragas")
    ragas_mod.evaluate = lambda dataset, metrics: FakeResult()

    metrics_mod = types.ModuleType("ragas.metrics")
    metrics_mod.faithfulness = "faithfulness"
    metrics_mod.answer_relevancy = "answer_relevancy"
    metrics_mod.context_recall = "context_recall"
    metrics_mod.context_precision = "context_precision"

    monkeypatch.setitem(sys.modules, "datasets", datasets_mod)
    monkeypatch.setitem(sys.modules, "ragas", ragas_mod)
    monkeypatch.setitem(sys.modules, "ragas.metrics", metrics_mod)


def test_fallback_when_ragas_missing(monkeypatch):
    """If RAGAS/datasets import fails, return a zeroed score dict."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name in {"ragas", "datasets"} or name.startswith("ragas."):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    scores = evaluate_quality(SAMPLE)
    assert scores == {
        "faithfulness": 0.0,
        "answer_relevancy": 0.0,
        "context_recall": 0.0,
        "context_precision": 0.0,
    }


def test_returns_all_metric_keys():
    """The result always exposes the four expected metric keys."""
    scores = evaluate_quality(SAMPLE)
    assert set(scores) == {
        "faithfulness",
        "answer_relevancy",
        "context_recall",
        "context_precision",
    }
    assert all(isinstance(v, float) for v in scores.values())


def test_success_path_aggregates_mean(monkeypatch):
    """With RAGAS present, scores are the per-metric mean across rows."""
    df = pd.DataFrame(
        {
            "faithfulness": [0.9, 0.7],
            "answer_relevancy": [0.8, 0.6],
            "context_recall": [0.5, 0.5],
            "context_precision": [1.0, 0.0],
        }
    )
    _install_fake_ragas(monkeypatch, df)

    data = [
        {"question": "q1", "answer": "a1", "contexts": ["c1"]},
        {"question": "q2", "answer": "a2", "contexts": ["c2"]},
    ]
    scores = evaluate_quality(data)
    assert scores["faithfulness"] == pytest.approx(0.8)
    assert scores["answer_relevancy"] == pytest.approx(0.7)
    assert scores["context_recall"] == pytest.approx(0.5)
    assert scores["context_precision"] == pytest.approx(0.5)
    assert all(isinstance(v, float) for v in scores.values())


def test_success_path_missing_required_field_raises(monkeypatch):
    """A row missing a required field raises ValueError (not silently zeroed)."""
    df = pd.DataFrame(
        {
            "faithfulness": [1.0],
            "answer_relevancy": [1.0],
            "context_recall": [1.0],
            "context_precision": [1.0],
        }
    )
    _install_fake_ragas(monkeypatch, df)

    bad = [{"question": "q", "answer": "a"}]  # missing "contexts"
    with pytest.raises(ValueError, match="contexts"):
        evaluate_quality(bad)
