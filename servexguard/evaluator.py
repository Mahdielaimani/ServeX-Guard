"""
Quality evaluation module: wraps RAGAS for RAG quality scoring.

Nothing here sends data anywhere unless the user names a model. An
OPENAI_API_KEY that happens to be set in the environment is not consent to ship
a bank's documents to a third party, so the endpoint is always explicit.
"""

from __future__ import annotations

import logging
import math
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# A score averaged over a handful of surviving rows says little about the
# dataset, so below this share of scored rows the metric counts as not measured.
MIN_COVERAGE = 0.8

_REQUIRED_FIELDS = {"question", "answer", "contexts"}
_INSTALL_HINT = "pip install servex-guard[eval]"
_LLM_HINT = "Set llm.model in servexguard.yaml, or pass --llm-model and --llm-base-url"


class QualityNotMeasuredError(Exception):
    """Quality could not be measured. Says nothing about the system under test."""

    def __init__(self, reason: str, fix: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.fix = fix


@dataclass(frozen=True)
class LLMSettings:
    """The OpenAI-compatible endpoint RAGAS judges with (Ollama, vLLM, Azure...)."""

    model: str | None = None
    base_url: str | None = None
    embedding_model: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    timeout: int = 180
    max_workers: int = 4


@dataclass
class QualityScores:
    """Outcome of an evaluation, metric by metric."""

    scores: dict[str, float] = field(default_factory=dict)
    coverage: dict[str, float] = field(default_factory=dict)
    unmeasured: dict[str, str] = field(default_factory=dict)


def _api_key(llm: LLMSettings) -> str:
    key = os.environ.get(llm.api_key_env)
    if key:
        return key
    if llm.base_url:
        # Local servers ignore the key, but the client refuses an empty one.
        return "not-needed"
    raise QualityNotMeasuredError(
        f"{llm.api_key_env} is not set and no llm.base_url is configured",
        f"Export {llm.api_key_env}, or point llm.base_url at a local endpoint",
    )


def _validate(data: list[dict], metrics: list[str]) -> None:
    required = set(_REQUIRED_FIELDS)
    if "context_recall" in metrics:
        required.add("ground_truth")
    for i, row in enumerate(data):
        missing = required - set(row.keys())
        if missing:
            raise ValueError(f"Row {i} missing fields: {sorted(missing)}")


def _load_stack() -> dict:
    """Import the RAGAS stack, telling 'not installed' apart from 'broken'."""
    # RAGAS phones home by default, which contradicts everything this tool says
    # about nothing leaving the machine. Must be set before the import.
    os.environ.setdefault("RAGAS_DO_NOT_TRACK", "true")
    try:
        from datasets import Dataset
        from langchain_openai import ChatOpenAI, OpenAIEmbeddings
        from ragas import evaluate
        from ragas.embeddings import LangchainEmbeddingsWrapper
        from ragas.llms import LangchainLLMWrapper
        from ragas.metrics import answer_relevancy, context_recall, faithfulness
        from ragas.run_config import RunConfig
    except ModuleNotFoundError as exc:
        raise QualityNotMeasuredError(f"{exc.name} is not installed", _INSTALL_HINT) from exc
    except Exception as exc:
        raise QualityNotMeasuredError(
            f"the RAGAS stack failed to import: {exc}", f"Reinstall: {_INSTALL_HINT}"
        ) from exc
    return {
        "Dataset": Dataset,
        "ChatOpenAI": ChatOpenAI,
        "OpenAIEmbeddings": OpenAIEmbeddings,
        "evaluate": evaluate,
        "LLMWrapper": LangchainLLMWrapper,
        "EmbeddingsWrapper": LangchainEmbeddingsWrapper,
        "RunConfig": RunConfig,
        "metrics": {
            "faithfulness": faithfulness,
            "answer_relevancy": answer_relevancy,
            "context_recall": context_recall,
        },
    }


def _to_ragas_rows(data: list[dict], metrics: list[str]) -> list[dict]:
    rows = []
    for row in data:
        converted = {
            "user_input": row["question"],
            "response": row["answer"],
            "retrieved_contexts": row["contexts"],
        }
        if "context_recall" in metrics:
            converted["reference"] = row["ground_truth"]
        rows.append(converted)
    return rows


def evaluate_quality(
    data: list[dict],
    metrics: list[str],
    llm: LLMSettings | None = None,
) -> QualityScores:
    """Score ``data`` on the requested RAGAS metrics.

    Args:
        data: Rows with question, answer, contexts (and ground_truth for
            context_recall).
        metrics: Metric names to compute.
        llm: The endpoint to judge with. Without a model nothing is sent anywhere.

    Returns:
        Scores, plus the metrics that could not be measured and why.

    Raises:
        ValueError: The dataset itself is invalid.
        QualityNotMeasuredError: Nothing could be measured.
    """
    _validate(data, metrics)

    llm = llm or LLMSettings()
    stack = _load_stack()

    if not llm.model:
        raise QualityNotMeasuredError("no LLM is configured to judge the answers", _LLM_HINT)
    api_key = _api_key(llm)

    outcome = QualityScores()
    requested = list(metrics)
    if "answer_relevancy" in requested and not llm.embedding_model:
        requested.remove("answer_relevancy")
        outcome.unmeasured["answer_relevancy"] = (
            "answer_relevancy needs embeddings and no llm.embedding_model is set"
        )
    if not requested:
        return outcome

    client_args = {"api_key": api_key, "base_url": llm.base_url, "timeout": llm.timeout}
    try:
        kwargs = {
            "dataset": stack["Dataset"].from_list(_to_ragas_rows(data, requested)),
            "metrics": [stack["metrics"][name] for name in requested],
            "llm": stack["LLMWrapper"](
                stack["ChatOpenAI"](model=llm.model, temperature=0, **client_args)
            ),
            "run_config": stack["RunConfig"](
                timeout=llm.timeout, max_workers=llm.max_workers, max_retries=3
            ),
            "show_progress": False,
        }
        if llm.embedding_model:
            # The token-length check would pull a tiktoken encoding off the
            # internet and send token ids that local servers do not understand.
            kwargs["embeddings"] = stack["EmbeddingsWrapper"](
                stack["OpenAIEmbeddings"](
                    model=llm.embedding_model,
                    check_embedding_ctx_length=False,
                    **client_args,
                )
            )
        frame = stack["evaluate"](**kwargs).to_pandas()
    except Exception as exc:
        raise QualityNotMeasuredError(
            f"the evaluation did not complete: {type(exc).__name__}: {exc}",
            "Check that the LLM endpoint is reachable and the model exists",
        ) from exc

    for name in requested:
        values = [float(v) for v in frame[name].tolist()]
        scored = [v for v in values if not math.isnan(v)]
        coverage = len(scored) / len(values) if values else 0.0
        if coverage < MIN_COVERAGE:
            outcome.unmeasured[name] = (
                f"only {len(scored)} of {len(values)} rows could be scored; "
                "check that the LLM endpoint is reachable and the model exists"
            )
            continue
        outcome.scores[name] = sum(scored) / len(scored)
        outcome.coverage[name] = coverage

    logger.info("Quality scores: %s", outcome.scores)
    return outcome
