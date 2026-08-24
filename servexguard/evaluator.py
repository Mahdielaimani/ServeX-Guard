"""
Quality evaluation module — wraps RAGAS for RAG quality scoring.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def evaluate_quality(data: list[dict]) -> dict[str, float] | None:
    """
    Evaluate RAG quality using RAGAS metrics.

    Args:
        data: List of dicts with keys: question, answer, contexts, ground_truth

    Returns:
        Dict of metric_name → score (0.0 to 1.0), or ``None`` when RAGAS is not
        installed. ``None`` and a dict of zeros are very different things: the
        first means "not measured", the second means "measured, and terrible".
    """
    try:
        from datasets import Dataset
        from ragas import evaluate
        from ragas.metrics import (
            answer_relevancy,
            context_precision,
            context_recall,
            faithfulness,
        )

        # Validate required fields
        required = {"question", "answer", "contexts"}
        for i, row in enumerate(data):
            missing = required - set(row.keys())
            if missing:
                raise ValueError(f"Row {i} missing fields: {missing}")

        # Build HuggingFace dataset
        dataset = Dataset.from_list(data)

        # Run RAGAS evaluation
        metrics = [faithfulness, answer_relevancy, context_recall, context_precision]
        result = evaluate(dataset=dataset, metrics=metrics)

        # Aggregate scores (mean across all samples)
        scores_df = result.to_pandas()
        scores = {
            "faithfulness": float(scores_df["faithfulness"].mean()),
            "answer_relevancy": float(scores_df["answer_relevancy"].mean()),
            "context_recall": float(scores_df["context_recall"].mean()),
            "context_precision": float(scores_df["context_precision"].mean()),
        }

        logger.info(f"Quality scores: {scores}")
        return scores

    except ImportError:
        # Returning zeros made a missing optional dependency indistinguishable
        # from a model that scored zero on every metric, so a correct first
        # install printed three failed checks and "GATE FAILED". Report absence
        # and let the caller mark those checks skipped instead.
        logger.warning("RAGAS not installed. Run: pip install servex-guard[eval]")
        return None
