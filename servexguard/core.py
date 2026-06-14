"""
Core ServeXGuard orchestrator — coordinates evaluation, security, and drift checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ── Input hardening limits ───────────────────────────────────────
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB — reject larger datasets
MAX_ROWS = 10_000  # only the first 10K rows are processed
MAX_FIELD_CHARS = 50_000  # truncate any single text field to this length
ALLOWED_DATASET_EXT = {".jsonl", ".json"}
_TEXT_FIELDS = ("question", "answer", "ground_truth")


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class CheckResult:
    """Result of a single check (quality, security, or drift)."""

    name: str
    status: CheckStatus
    score: float | None = None
    threshold: float | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status == CheckStatus.PASSED

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status.value,
            "score": self.score,
            "threshold": self.threshold,
            "passed": self.passed,
            "details": self.details,
        }


@dataclass
class GuardResult:
    """Aggregated result of all ServeXGuard checks."""

    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.passed or c.status == CheckStatus.SKIPPED for c in self.checks)

    @property
    def failures(self) -> list[str]:
        return [
            f"{c.name}: {c.score:.3f} < {c.threshold}"
            if c.score is not None
            else f"{c.name}: {c.details}"
            for c in self.checks
            if not c.passed and c.status != CheckStatus.SKIPPED
        ]

    @property
    def exit_code(self) -> int:
        """0 = passed, 1 = failed. Use in CI/CD."""
        return 0 if self.passed else 1

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "exit_code": self.exit_code,
            "failures": self.failures,
            "checks": [c.to_dict() for c in self.checks],
        }

    def to_json(self, path: str | None = None) -> str:
        data = json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        if path:
            Path(path).write_text(data, encoding="utf-8")
        return data


class ServeXGuard:
    """
    Main ServeXGuard quality gate.

    Usage:
        guard = ServeXGuard(min_faithfulness=0.80, check_pii=True)
        result = guard.check("golden_dataset.jsonl")
        if not result.passed:
            sys.exit(1)
    """

    def __init__(
        self,
        min_faithfulness: float = 0.80,
        min_relevancy: float = 0.75,
        min_context_recall: float = 0.70,
        check_pii: bool = False,
        check_injection: bool = False,
        check_drift: bool = False,
        drift_threshold: float = 0.25,
        baseline_path: str | None = None,
        language: str = "en",
        custom_entities: list[dict] | None = None,
        save_baseline: bool = False,
    ):
        self.min_faithfulness = min_faithfulness
        self.min_relevancy = min_relevancy
        self.min_context_recall = min_context_recall
        self.check_pii = check_pii
        self.check_injection = check_injection
        self.check_drift = check_drift
        self.drift_threshold = drift_threshold
        self.baseline_path = baseline_path
        self.language = language
        self.custom_entities = custom_entities or []
        self.save_baseline = save_baseline

    def check(self, dataset_path: str) -> GuardResult:
        """
        Run all configured checks on the dataset.

        Args:
            dataset_path: Path to JSONL golden dataset.

        Returns:
            GuardResult with all check outcomes.
        """
        result = GuardResult()

        # Load dataset
        data = self._load_dataset(dataset_path)

        # 1. Quality evaluation (RAGAS)
        quality_checks = self._run_quality(data)
        result.checks.extend(quality_checks)

        # 2. Security scanning
        if self.check_pii:
            pii_check = self._run_pii_scan(data)
            result.checks.append(pii_check)

        if self.check_injection:
            injection_check = self._run_injection_scan(data)
            result.checks.append(injection_check)

        # 3. Drift detection
        if self.check_drift:
            drift_check = self._run_drift_detection(data)
            result.checks.append(drift_check)

        return result

    @staticmethod
    def _validate_dataset_path(path: str) -> Path:
        """Resolve and validate a dataset path (anti path-traversal).

        Args:
            path: User-supplied dataset path.

        Returns:
            The resolved absolute path.

        Raises:
            ValueError: If the path escapes the working directory or has an
                unsupported extension.
        """
        resolved = Path(path).resolve()
        cwd = Path.cwd().resolve()
        if not resolved.is_relative_to(cwd):
            raise ValueError(
                f"Dataset path escapes the working directory: {path}"
            )
        if resolved.suffix.lower() not in ALLOWED_DATASET_EXT:
            raise ValueError(
                f"Unsupported dataset extension '{resolved.suffix}' "
                f"(allowed: {', '.join(sorted(ALLOWED_DATASET_EXT))}): {path}"
            )
        return resolved

    def _load_dataset(self, path: str) -> list[dict]:
        """Load and harden a JSONL golden dataset.

        Enforces path-traversal protection, a file-size cap, a row cap, and
        per-field length truncation.
        """
        dataset_path = self._validate_dataset_path(path)
        if not dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {path}")

        size = dataset_path.stat().st_size
        if size > MAX_FILE_SIZE:
            raise ValueError(
                f"Dataset too large ({size} bytes > {MAX_FILE_SIZE} limit): {path}"
            )

        data: list[dict] = []
        with open(dataset_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if len(data) >= MAX_ROWS:
                    import logging

                    logging.getLogger(__name__).warning(
                        "Dataset exceeds %d rows; ignoring the rest", MAX_ROWS
                    )
                    break
                data.append(self._truncate_fields(json.loads(line)))

        if not data:
            raise ValueError(f"Dataset is empty: {path}")

        return data

    @staticmethod
    def _truncate_fields(row: dict) -> dict:
        """Truncate oversized text fields to :data:`MAX_FIELD_CHARS`."""
        for key in _TEXT_FIELDS:
            value = row.get(key)
            if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
                row[key] = value[:MAX_FIELD_CHARS]
        return row

    def _run_quality(self, data: list[dict]) -> list[CheckResult]:
        """Run RAGAS quality evaluation."""
        from servexguard.evaluator import evaluate_quality

        scores = evaluate_quality(data)
        checks = []

        # Faithfulness
        faith_score = scores.get("faithfulness", 0.0)
        checks.append(
            CheckResult(
                name="faithfulness",
                status=(
                    CheckStatus.PASSED
                    if faith_score >= self.min_faithfulness
                    else CheckStatus.FAILED
                ),
                score=faith_score,
                threshold=self.min_faithfulness,
            )
        )

        # Answer Relevancy
        rel_score = scores.get("answer_relevancy", 0.0)
        checks.append(
            CheckResult(
                name="answer_relevancy",
                status=(
                    CheckStatus.PASSED
                    if rel_score >= self.min_relevancy
                    else CheckStatus.FAILED
                ),
                score=rel_score,
                threshold=self.min_relevancy,
            )
        )

        # Context Recall
        recall_score = scores.get("context_recall", 0.0)
        checks.append(
            CheckResult(
                name="context_recall",
                status=(
                    CheckStatus.PASSED
                    if recall_score >= self.min_context_recall
                    else CheckStatus.FAILED
                ),
                score=recall_score,
                threshold=self.min_context_recall,
            )
        )

        return checks

    def _run_pii_scan(self, data: list[dict]) -> CheckResult:
        """Scan for PII leaks in answers."""
        from servexguard.security import scan_pii

        leaks = scan_pii(
            data, language=self.language, custom_entities=self.custom_entities
        )
        return CheckResult(
            name="pii_scan",
            status=CheckStatus.PASSED if len(leaks) == 0 else CheckStatus.FAILED,
            score=float(len(leaks)),
            threshold=0.0,
            details={"leaks": leaks[:10]},  # First 10 leaks
        )

    def _run_injection_scan(self, data: list[dict]) -> CheckResult:
        """Scan for prompt injection vulnerabilities."""
        from servexguard.security import scan_injection

        vulnerabilities = scan_injection(data)
        return CheckResult(
            name="injection_scan",
            status=CheckStatus.PASSED if len(vulnerabilities) == 0 else CheckStatus.FAILED,
            score=float(len(vulnerabilities)),
            threshold=0.0,
            details={"vulnerabilities": vulnerabilities[:10]},
        )

    def _run_drift_detection(self, data: list[dict]) -> CheckResult:
        """Detect query distribution drift."""
        from servexguard.drift import detect_drift

        drift_score = detect_drift(
            data, self.baseline_path, save_baseline=self.save_baseline
        )
        return CheckResult(
            name="query_drift",
            status=(
                CheckStatus.PASSED
                if drift_score <= self.drift_threshold
                else CheckStatus.FAILED
            ),
            score=drift_score,
            threshold=self.drift_threshold,
        )
