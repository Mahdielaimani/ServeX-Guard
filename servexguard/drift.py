"""
Query drift detection: has what users ask moved away from a saved baseline?

Questions become hashed character n-gram vectors. That needs no model and no
network, and works the same on French, Arabic and Darija in either script, where
word lists fall apart on spelling variation. The vectors hold hashes, not text,
so a baseline file can be kept in a repository.

It sees wording, not meaning: a paraphrase using entirely different words looks
like drift, and a new topic worded like the old one does not. Treat it as a cheap
early signal in CI, not as a measure of semantic distance.
"""

from __future__ import annotations

import hashlib
import logging
import unicodedata
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

ALLOWED_BASELINE_EXT = {".npy"}

# Part of the baseline format: a baseline built at another width cannot be compared.
VECTOR_DIM = 2048
NGRAM_SIZES = (3, 4, 5)
# Below this many questions the score moves with a single unusual row.
MIN_RELIABLE_QUESTIONS = 20
_BATCH_ROWS = 512


class DriftNotMeasuredError(Exception):
    """Drift could not be computed. Says nothing about the system under test."""

    def __init__(self, reason: str, fix: str | None = None):
        super().__init__(reason)
        self.reason = reason
        self.fix = fix


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
) -> float | None:
    """Score how far the questions in ``data`` have moved from the baseline.

    Args:
        data: Rows with a ``question`` field.
        baseline_path: Path to the ``.npy`` baseline.
        save_baseline: Replace the baseline with these questions, without comparing.

    Returns:
        0.0 (matches the baseline) to 1.0 (nothing in common), or ``None`` when a
        new baseline was saved and so nothing was compared.

    Raises:
        DriftNotMeasuredError: There is nothing to compare, so no score exists.
    """
    questions = [row.get("question", "") for row in data if row.get("question")]
    if not questions:
        raise DriftNotMeasuredError("the dataset has no questions to compare")
    if not baseline_path:
        raise DriftNotMeasuredError(
            "no baseline file is configured", "Set drift.baseline_file or pass --baseline"
        )

    # Validate up front (anti path-traversal, extension).
    resolved = _validate_baseline_path(baseline_path)
    current = embed(questions)

    if save_baseline:
        _save_baseline(resolved, current)
        return None

    if not resolved.exists():
        raise DriftNotMeasuredError(
            f"no baseline exists at {baseline_path}",
            "Run once on a known-good dataset with --save-baseline",
        )

    # allow_pickle=False blocks arbitrary-object deserialization attacks.
    baseline = np.load(resolved, allow_pickle=False)
    if baseline.ndim != 2 or baseline.shape[1] != VECTOR_DIM:
        raise DriftNotMeasuredError(
            f"{baseline_path} was built by an older version and cannot be compared",
            "Rebuild it on a known-good dataset with --save-baseline",
        )
    if len(questions) < MIN_RELIABLE_QUESTIONS or len(baseline) < MIN_RELIABLE_QUESTIONS:
        logger.warning(
            "Drift compares %d questions to a baseline of %d. Under %d either way, "
            "one unusual question can move the score.",
            len(questions), len(baseline), MIN_RELIABLE_QUESTIONS,
        )

    score = compute_drift(baseline, current)
    logger.info("Drift score: %.4f", score)
    return score


def _save_baseline(baseline_path: Path, vectors: np.ndarray) -> None:
    """Persist vectors as the drift baseline, creating parent dirs."""
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    np.save(baseline_path, vectors)
    logger.info("Baseline saved to %s", baseline_path)


def _normalize(text: str) -> str:
    """Fold case and presentation forms, and drop Arabic marks and elongation."""
    text = unicodedata.normalize("NFKC", text).casefold()
    return "".join(
        ch for ch in text if unicodedata.category(ch) != "Mn" and ch != "ـ"
    )


def _ngrams(text: str) -> list[str]:
    """Character n-grams inside each word, with its boundaries marked."""
    grams: list[str] = []
    for word in _normalize(text).split():
        marked = f"<{word}>"
        for size in NGRAM_SIZES:
            grams.extend(marked[i : i + size] for i in range(len(marked) - size + 1))
    return grams


def embed(texts: list[str]) -> np.ndarray:
    """Hash each text to a unit vector. Stable across runs, batches and machines."""
    matrix = np.zeros((len(texts), VECTOR_DIM), dtype=np.float32)
    for row, text in enumerate(texts):
        for gram in _ngrams(text):
            digest = hashlib.blake2b(gram.encode("utf-8"), digest_size=8).digest()
            value = int.from_bytes(digest, "big")
            # The sign bit stops hash collisions from all pushing the same way.
            matrix[row, value % VECTOR_DIM] += 1.0 if value >> 63 else -1.0
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


def _nearest_similarity(
    queries: np.ndarray, reference: np.ndarray, skip_self: bool = False
) -> np.ndarray:
    """For each query, its cosine similarity to the closest reference vector."""
    best = np.empty(len(queries), dtype=np.float32)
    for start in range(0, len(queries), _BATCH_ROWS):
        batch = queries[start : start + _BATCH_ROWS]
        sims = batch @ reference.T
        if skip_self:
            sims[np.arange(len(batch)), np.arange(start, start + len(batch))] = -np.inf
        best[start : start + _BATCH_ROWS] = sims.max(axis=1)
    return best


def compute_drift(baseline: np.ndarray, current: np.ndarray) -> float:
    """Compare how close current questions get to the baseline with what is normal.

    Raw similarity has no meaning alone: two different questions on one topic
    still score well below 1. The yardstick is the baseline itself, namely how
    close each of its questions gets to the nearest other one. Current questions
    that fit as well as that score about 0.

    Args:
        baseline: Baseline vectors.
        current: Current vectors.

    Returns:
        Drift score clamped to [0, 1].
    """
    if len(baseline) > 1:
        normal = float(_nearest_similarity(baseline, baseline, skip_self=True).mean())
    else:
        normal = 1.0
    observed = float(_nearest_similarity(current, baseline).mean())
    if normal <= 0:
        return 0.0 if observed >= normal else 1.0
    return round(float(np.clip((normal - observed) / normal, 0.0, 1.0)), 4)
