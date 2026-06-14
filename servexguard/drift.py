"""
Drift detection module — detect query distribution shifts.
"""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

ALLOWED_BASELINE_EXT = {".npy"}


def _validate_baseline_path(path: str) -> Path:
    """Resolve and validate a baseline path (anti path-traversal).

    Args:
        path: User-supplied baseline path.

    Returns:
        The resolved absolute path.

    Raises:
        ValueError: If the path escapes the working directory or is not ``.npy``.
    """
    resolved = Path(path).resolve()
    cwd = Path.cwd().resolve()
    if not resolved.is_relative_to(cwd):
        raise ValueError(f"Baseline path escapes the working directory: {path}")
    if resolved.suffix.lower() not in ALLOWED_BASELINE_EXT:
        raise ValueError(f"Baseline file must be .npy: {path}")
    return resolved


def detect_drift(
    data: list[dict],
    baseline_path: str | None = None,
    save_baseline: bool = False,
) -> float:
    """
    Detect query distribution drift using embedding cosine similarity.

    Compares current query embeddings against a saved baseline.
    High drift score (>0.25) = users asking questions the system wasn't designed for.

    Args:
        data: List of dicts with 'question' field.
        baseline_path: Path to .npy file with baseline embeddings.

    Returns:
        Drift score (0.0 = no drift, 1.0 = complete drift).
    """
    questions = [row.get("question", "") for row in data if row.get("question")]

    if not questions:
        logger.warning("No questions found in dataset for drift detection")
        return 0.0

    # Validate the baseline path up front (anti path-traversal, extension).
    resolved_baseline = _validate_baseline_path(baseline_path) if baseline_path else None

    # Generate simple embeddings (bag-of-words for now, upgrade to real embeddings later)
    current_embeddings = _simple_embed_batch(questions)

    if resolved_baseline and resolved_baseline.exists():
        # allow_pickle=False blocks arbitrary-object deserialization attacks.
        baseline_embeddings = np.load(resolved_baseline, allow_pickle=False)
        drift_score = _compute_drift(baseline_embeddings, current_embeddings)
    else:
        # No baseline → save current as baseline, report 0 drift
        if resolved_baseline:
            _save_baseline(resolved_baseline, current_embeddings)
        drift_score = 0.0

    # Explicit refresh of the baseline (e.g. --save-baseline after a clean run).
    if save_baseline and resolved_baseline:
        _save_baseline(resolved_baseline, current_embeddings)

    logger.info(f"Drift score: {drift_score:.4f}")
    return drift_score


def _save_baseline(baseline_path: str, embeddings: np.ndarray) -> None:
    """Persist embeddings as the drift baseline, creating parent dirs."""
    Path(baseline_path).parent.mkdir(parents=True, exist_ok=True)
    np.save(baseline_path, embeddings)
    logger.info(f"Baseline saved to {baseline_path}")


def _simple_embed_batch(texts: list[str], vocab_size: int = 256) -> np.ndarray:
    """
    Simple bag-of-words embedding for drift detection.
    Replace with real embeddings (Azure OpenAI / BGE) in production.
    """
    # Build vocabulary from all texts
    all_words = set()
    for text in texts:
        all_words.update(text.lower().split())
    vocab = sorted(all_words)[:vocab_size]

    # Encode each text
    embeddings = []
    for text in texts:
        words = text.lower().split()
        vec = np.array([words.count(w) for w in vocab], dtype=np.float32)
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        embeddings.append(vec)

    return np.array(embeddings)


def _compute_drift(
    baseline: np.ndarray,
    current: np.ndarray,
) -> float:
    """
    Compute drift as 1 - mean cosine similarity between
    current queries and their nearest baseline neighbors.
    """
    if baseline.shape[1] != current.shape[1]:
        # Vocabulary mismatch — high drift signal
        return 0.8

    # For each current query, find max similarity to any baseline query
    similarities = []
    for curr_vec in current:
        if np.linalg.norm(curr_vec) == 0:
            similarities.append(0.0)
            continue

        sims = []
        for base_vec in baseline[:100]:  # Cap for performance
            if np.linalg.norm(base_vec) == 0:
                continue
            sim = float(
                np.dot(curr_vec, base_vec)
                / (np.linalg.norm(curr_vec) * np.linalg.norm(base_vec) + 1e-8)
            )
            sims.append(sim)

        if sims:
            similarities.append(max(sims))  # Best match
        else:
            similarities.append(0.0)

    # Drift = 1 - mean(best similarities)
    mean_sim = float(np.mean(similarities)) if similarities else 0.0
    drift_score = round(1.0 - mean_sim, 4)

    return max(0.0, min(1.0, drift_score))  # Clamp to [0, 1]
