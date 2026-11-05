"""
Core ServeXGuard orchestrator — coordinates evaluation, security, and drift checks.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from servexguard.evaluator import LLMSettings

# ── Input hardening limits ───────────────────────────────────────
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB — reject larger datasets
MAX_ROWS = 10_000  # only the first 10K rows are processed
MAX_FIELD_CHARS = 50_000  # truncate any single text field to this length
ALLOWED_DATASET_EXT = {".jsonl", ".json"}
_TEXT_FIELDS = ("question", "answer", "ground_truth")


# Exit codes. Distinct from 1 so CI can tell "your system is bad" from "nobody
# looked", and from 2, which the CLI framework uses for bad arguments.
EXIT_PASSED = 0
EXIT_FAILED = 1
EXIT_NOT_MEASURED = 3

# Each quality check, with the attribute holding its threshold.
_QUALITY_CHECKS = (
    ("faithfulness", "min_faithfulness"),
    ("answer_relevancy", "min_relevancy"),
    ("context_recall", "min_context_recall"),
)


class CheckStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    # Switched off on purpose. Not part of the verdict.
    SKIPPED = "skipped"
    # Asked for, but no evidence was produced. Never reads as a pass.
    NOT_MEASURED = "not_measured"


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
        """True only when something was measured and nothing failed or went unmeasured."""
        return (
            any(c.status == CheckStatus.PASSED for c in self.checks)
            and not self.failures
            and not self.not_measured
        )

    @property
    def not_measured(self) -> list[CheckResult]:
        return [c for c in self.checks if c.status == CheckStatus.NOT_MEASURED]

    @property
    def verdict(self) -> str:
        """passed, failed, or not_measured. A real failure outranks missing evidence."""
        if self.failures:
            return "failed"
        return "passed" if self.passed else "not_measured"

    # Quality metrics fail by falling below a floor; security checks fail by
    # counting above a ceiling. Printing both as "score < threshold" made every
    # security failure read backwards, e.g. "injection_scan: 1.000 < 0.0".
    _COUNT_CHECKS = {"pii_scan", "injection_scan", "injection_judge"}

    @property
    def failures(self) -> list[str]:
        out = []
        for c in self.checks:
            if c.status != CheckStatus.FAILED:
                continue
            if c.score is None:
                out.append(f"{c.name}: {c.details}")
            elif c.name in self._COUNT_CHECKS:
                count = int(c.score)
                noun = "leak" if c.name == "pii_scan" else "risk"
                out.append(
                    f"{c.name}: {count} {noun}{'s' if count != 1 else ''} found "
                    f"(max {int(c.threshold or 0)})"
                )
            else:
                out.append(f"{c.name}: {c.score:.3f} below the {c.threshold} threshold")
        return out

    @property
    def exit_code(self) -> int:
        """0 = passed, 1 = failed, 3 = not measured. Use in CI/CD."""
        return {
            "passed": EXIT_PASSED,
            "failed": EXIT_FAILED,
            "not_measured": EXIT_NOT_MEASURED,
        }[self.verdict]

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "verdict": self.verdict,
            "exit_code": self.exit_code,
            "failures": self.failures,
            "not_measured": [c.name for c in self.not_measured],
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
        drift_threshold: float = 0.20,
        baseline_path: str | None = None,
        language: str = "en",
        custom_entities: list[dict] | None = None,
        save_baseline: bool = False,
        llm: LLMSettings | None = None,
        allow_unmeasured: bool = False,
        pii_presets: list[str] | None = None,
        llm_injection: bool = False,
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
        self.llm = llm
        self.allow_unmeasured = allow_unmeasured
        self.pii_presets = pii_presets or []
        self.llm_injection = llm_injection

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

        if self.llm_injection:
            result.checks.append(self._run_injection_judge(data))

        # 3. Drift detection
        if self.check_drift:
            drift_check = self._run_drift_detection(data)
            result.checks.append(drift_check)

        if self.allow_unmeasured:
            for c in result.not_measured:
                c.status = CheckStatus.SKIPPED
        elif not result.not_measured and not any(
            c.status in (CheckStatus.PASSED, CheckStatus.FAILED) for c in result.checks
        ):
            # Every check switched off is still not evidence of a safe deploy.
            result.checks.append(
                CheckResult(
                    name="gate",
                    status=CheckStatus.NOT_MEASURED,
                    details={"reason": "every check is disabled, so nothing was measured"},
                )
            )

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
            for number, row in enumerate(self._read_rows(f, dataset_path.suffix), start=1):
                if len(data) >= MAX_ROWS:
                    import logging

                    logging.getLogger(__name__).warning(
                        "Dataset exceeds %d rows; ignoring the rest", MAX_ROWS
                    )
                    break
                if not isinstance(row, dict):
                    raise ValueError(
                        f"Row {number} of {path} must be an object, got {type(row).__name__}"
                    )
                data.append(self._truncate_fields(row))

        if not data:
            raise ValueError(f"Dataset is empty: {path}")

        return data

    @staticmethod
    def _read_rows(f: Any, suffix: str) -> Iterable[Any]:
        """Yield rows from a JSON array file, or from JSON Lines."""
        if suffix.lower() == ".json":
            content = json.load(f)
            yield from content if isinstance(content, list) else [content]
            return
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)

    @staticmethod
    def _truncate_fields(row: dict) -> dict:
        """Truncate oversized text fields to :data:`MAX_FIELD_CHARS`."""
        for key in _TEXT_FIELDS:
            value = row.get(key)
            if isinstance(value, str) and len(value) > MAX_FIELD_CHARS:
                row[key] = value[:MAX_FIELD_CHARS]
        return row

    def _run_quality(self, data: list[dict]) -> list[CheckResult]:
        """Run the RAGAS metrics whose threshold is above zero.

        A threshold of zero switches a metric off. Any other metric that cannot
        be scored comes back NOT_MEASURED, which blocks the gate: a broken install
        or an unreachable LLM must never read as a deploy that passed.
        """
        from servexguard.evaluator import QualityNotMeasuredError, evaluate_quality

        thresholds = {name: getattr(self, attr) for name, attr in _QUALITY_CHECKS}
        requested = [name for name, threshold in thresholds.items() if threshold > 0]

        reasons: dict[str, dict[str, Any]] = {}
        scores: dict[str, float] = {}
        coverage: dict[str, float] = {}
        if requested:
            try:
                outcome = evaluate_quality(data, requested, self.llm)
            except QualityNotMeasuredError as exc:
                reasons = {
                    name: {"reason": exc.reason, "fix": exc.fix} for name in requested
                }
            else:
                scores, coverage = outcome.scores, outcome.coverage
                reasons = {
                    name: {"reason": reason} for name, reason in outcome.unmeasured.items()
                }

        checks = []
        for name, threshold in thresholds.items():
            if name not in requested:
                status, score, details = (
                    CheckStatus.SKIPPED, None, {"reason": "disabled by a threshold of 0"}
                )
            elif name in scores:
                score = scores[name]
                status = CheckStatus.PASSED if score >= threshold else CheckStatus.FAILED
                details = {"coverage": round(coverage[name], 3)}
            else:
                status, score, details = CheckStatus.NOT_MEASURED, None, reasons[name]
            checks.append(CheckResult(name, status, score, threshold, details))
        return checks

    def _run_pii_scan(self, data: list[dict]) -> CheckResult:
        """Scan for PII leaks in answers."""
        from servexguard.security import pii_detector, scan_pii

        leaks = scan_pii(
            data,
            language=self.language,
            custom_entities=self.custom_entities,
            presets=self.pii_presets,
        )
        return CheckResult(
            name="pii_scan",
            status=CheckStatus.PASSED if len(leaks) == 0 else CheckStatus.FAILED,
            score=float(len(leaks)),
            threshold=0.0,
            details={  # First 10 leaks
                "leaks": leaks[:10],
                "detector": pii_detector(self.language),
                "presets": self.pii_presets,
            },
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

    def _run_injection_judge(self, data: list[dict]) -> CheckResult:
        """Ask the configured LLM whether questions and contexts are attacks."""
        from servexguard.evaluator import QualityNotMeasuredError
        from servexguard.injection_judge import MIN_COVERAGE, judge_dataset

        try:
            outcome = judge_dataset(data, self.llm)
        except QualityNotMeasuredError as exc:
            return CheckResult(
                name="injection_judge",
                status=CheckStatus.NOT_MEASURED,
                threshold=0.0,
                details={"reason": exc.reason, "fix": exc.fix},
            )

        details: dict[str, Any] = {
            "findings": outcome.findings[:10],
            "judged": outcome.judged,
            "unjudged": outcome.unjudged,
            "truncated_fields": outcome.truncated,
            "coverage": round(outcome.coverage, 3),
        }
        # A found attack stands however little was judged. A clean result needs coverage.
        if outcome.findings:
            status = CheckStatus.FAILED
        elif outcome.coverage < MIN_COVERAGE:
            details["reason"] = (
                f"only {outcome.judged} of {outcome.judged + outcome.unjudged} texts "
                "got a clear verdict; check the LLM endpoint and model"
            )
            return CheckResult(
                name="injection_judge",
                status=CheckStatus.NOT_MEASURED,
                threshold=0.0,
                details=details,
            )
        else:
            status = CheckStatus.PASSED
        return CheckResult(
            name="injection_judge",
            status=status,
            score=float(len(outcome.findings)),
            threshold=0.0,
            details=details,
        )

    def _run_drift_detection(self, data: list[dict]) -> CheckResult:
        """Compare the questions with the saved baseline."""
        from servexguard.drift import DriftNotMeasuredError, detect_drift

        try:
            drift_score = detect_drift(
                data, self.baseline_path, save_baseline=self.save_baseline
            )
        except DriftNotMeasuredError as exc:
            return CheckResult(
                name="query_drift",
                status=CheckStatus.NOT_MEASURED,
                threshold=self.drift_threshold,
                details={"reason": exc.reason, "fix": exc.fix},
            )
        if drift_score is None:
            return CheckResult(
                name="query_drift",
                status=CheckStatus.SKIPPED,
                threshold=self.drift_threshold,
                details={"reason": "baseline saved, nothing compared on this run"},
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
