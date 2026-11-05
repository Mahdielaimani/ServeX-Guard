"""Tests for the quality evaluator's own logic, with the RAGAS stack replaced.

These prove nothing about whether RAGAS itself works: 0.2.1 passed tests like
these while the real package could not even be imported. That is the job of
tests/test_ragas_integration.py, which uses the real stack.
"""

from __future__ import annotations

import builtins

import pytest

from servexguard import evaluator
from servexguard.evaluator import LLMSettings, QualityNotMeasuredError, evaluate_quality

SAMPLE = [
    {"question": "q", "answer": "a", "contexts": ["c"], "ground_truth": "g"},
]


METRICS = ["faithfulness", "answer_relevancy", "context_recall"]
LLM = LLMSettings(model="m", base_url="http://localhost:1/v1", embedding_model="e")


class _FakeColumn:
    def __init__(self, values: list[float]):
        self._values = values

    def tolist(self) -> list[float]:
        return self._values


class _FakeDataFrame:
    def __init__(self, columns: dict[str, list[float]]):
        self._columns = columns

    def __getitem__(self, key: str) -> _FakeColumn:
        return _FakeColumn(self._columns[key])


def _fake_stack(monkeypatch, columns=None, error=None) -> dict:
    """Replace the RAGAS stack. Returns a dict recording what evaluate() received."""
    seen: dict = {}

    class FakeDataset:
        @staticmethod
        def from_list(rows):
            seen["rows"] = rows
            return rows

    class FakeResult:
        def to_pandas(self):
            return _FakeDataFrame(columns)

    def fake_evaluate(**kwargs):
        seen.update(kwargs)
        if error:
            raise error
        return FakeResult()

    def record_client(key):
        def build(**kwargs):
            seen[key] = kwargs
            return key

        return build

    stack = {
        "Dataset": FakeDataset,
        "ChatOpenAI": record_client("chat"),
        "OpenAIEmbeddings": record_client("embeddings_client"),
        "evaluate": fake_evaluate,
        "LLMWrapper": lambda llm: llm,
        "EmbeddingsWrapper": lambda emb: emb,
        "RunConfig": lambda **kwargs: kwargs,
        "metrics": {name: name for name in METRICS},
    }
    monkeypatch.setattr(evaluator, "_load_stack", lambda: stack)
    return seen


def test_missing_ragas_says_what_to_install(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "datasets":
            raise ModuleNotFoundError(name, name=name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(QualityNotMeasuredError) as exc:
        evaluate_quality(SAMPLE, METRICS, LLM)
    assert "pip install servex-guard[eval]" in exc.value.fix


def test_a_broken_stack_is_not_reported_as_missing(monkeypatch):
    """The 0.2.1 failure: installed fine, then died on import inside RAGAS."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "datasets":
            raise ImportError("cannot import name ChatVertexAI")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(QualityNotMeasuredError, match="failed to import.*ChatVertexAI"):
        evaluate_quality(SAMPLE, METRICS, LLM)


def test_no_model_means_nothing_is_sent(monkeypatch):
    """An API key lying around in the environment is not consent to send data."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    seen = _fake_stack(monkeypatch)
    with pytest.raises(QualityNotMeasuredError, match="no LLM"):
        evaluate_quality(SAMPLE, METRICS, LLMSettings())
    assert "rows" not in seen


def test_remote_model_without_a_key_is_not_measured(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _fake_stack(monkeypatch)
    with pytest.raises(QualityNotMeasuredError, match="OPENAI_API_KEY"):
        evaluate_quality(SAMPLE, METRICS, LLMSettings(model="gpt"))


def test_local_endpoint_needs_no_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    columns = {name: [0.5] for name in METRICS}
    seen = _fake_stack(monkeypatch, columns)
    evaluate_quality(SAMPLE, METRICS, LLM)
    assert seen["chat"]["base_url"] == "http://localhost:1/v1"
    assert seen["chat"]["api_key"] == "not-needed"
    assert seen["embeddings_client"]["check_embedding_ctx_length"] is False


def test_columns_use_the_names_ragas_expects(monkeypatch):
    seen = _fake_stack(monkeypatch, {name: [0.5] for name in METRICS})
    evaluate_quality(SAMPLE, METRICS, LLM)
    assert seen["rows"] == [
        {
            "user_input": "q",
            "response": "a",
            "retrieved_contexts": ["c"],
            "reference": "g",
        }
    ]


def test_scores_are_the_mean_across_rows(monkeypatch):
    _fake_stack(
        monkeypatch,
        {"faithfulness": [0.9, 0.7], "answer_relevancy": [0.8, 0.6], "context_recall": [0.5, 0.5]},
    )
    outcome = evaluate_quality(SAMPLE * 2, METRICS, LLM)
    assert outcome.scores["faithfulness"] == pytest.approx(0.8)
    assert outcome.scores["answer_relevancy"] == pytest.approx(0.7)
    assert outcome.scores["context_recall"] == pytest.approx(0.5)
    assert outcome.unmeasured == {}


def test_only_requested_metrics_run(monkeypatch):
    seen = _fake_stack(monkeypatch, {"faithfulness": [1.0]})
    outcome = evaluate_quality(SAMPLE, ["faithfulness"], LLM)
    assert seen["metrics"] == ["faithfulness"]
    assert set(outcome.scores) == {"faithfulness"}


def test_relevancy_without_embeddings_is_not_measured(monkeypatch):
    _fake_stack(monkeypatch, {"faithfulness": [1.0], "context_recall": [1.0]})
    llm = LLMSettings(model="m", base_url="http://localhost:1/v1")
    outcome = evaluate_quality(SAMPLE, METRICS, llm)
    assert "answer_relevancy" in outcome.unmeasured
    assert set(outcome.scores) == {"faithfulness", "context_recall"}


def test_a_metric_scoring_too_few_rows_is_not_measured(monkeypatch):
    """NaN means the judge failed on that row. It is not a low score."""
    nan = float("nan")
    _fake_stack(monkeypatch, {"faithfulness": [0.9, nan, nan, nan, nan]})
    outcome = evaluate_quality(SAMPLE * 5, ["faithfulness"], LLM)
    assert outcome.scores == {}
    assert "1 of 5" in outcome.unmeasured["faithfulness"]


def test_a_few_unscored_rows_are_reported_as_coverage(monkeypatch):
    nan = float("nan")
    _fake_stack(monkeypatch, {"faithfulness": [0.8, 0.8, 0.8, 0.8, nan]})
    outcome = evaluate_quality(SAMPLE * 5, ["faithfulness"], LLM)
    assert outcome.scores["faithfulness"] == pytest.approx(0.8)
    assert outcome.coverage["faithfulness"] == pytest.approx(0.8)


def test_an_unreachable_endpoint_is_not_measured(monkeypatch):
    _fake_stack(monkeypatch, error=ConnectionError("refused"))
    with pytest.raises(QualityNotMeasuredError, match="refused"):
        evaluate_quality(SAMPLE, METRICS, LLM)


def test_missing_required_field_raises(monkeypatch):
    with pytest.raises(ValueError, match="contexts"):
        evaluate_quality([{"question": "q", "answer": "a"}], ["faithfulness"], LLM)


def test_context_recall_requires_ground_truth(monkeypatch):
    row = {"question": "q", "answer": "a", "contexts": ["c"]}
    with pytest.raises(ValueError, match="ground_truth"):
        evaluate_quality([row], ["context_recall"], LLM)
