"""Tests for report generation (JSON / Markdown / terminal)."""

from __future__ import annotations

import json

from rich.console import Console

from servexguard import reporter
from servexguard.core import CheckResult, CheckStatus, GuardResult


def _result(drift_passed: bool = True) -> GuardResult:
    return GuardResult(checks=[
        CheckResult("faithfulness", CheckStatus.PASSED, 0.91, 0.80),
        CheckResult("pii_scan", CheckStatus.FAILED, 2.0, 0.0),
        CheckResult(
            "query_drift",
            CheckStatus.PASSED if drift_passed else CheckStatus.FAILED,
            0.10 if drift_passed else 0.40,
            0.25,
        ),
    ])


def test_build_report_dict():
    report = reporter.build_report_dict(_result(), "data.jsonl")
    assert report["tool"] == "servex-guard"
    assert report["dataset"] == "data.jsonl"
    assert "timestamp" in report


def test_to_json_writes_file(tmp_path):
    path = tmp_path / "out" / "report.json"
    text = reporter.to_json(_result(), str(path), "data.jsonl")
    assert path.exists()
    assert json.loads(text)["dataset"] == "data.jsonl"


def test_to_markdown_writes_file(tmp_path):
    path = tmp_path / "report.md"
    text = reporter.to_markdown(_result(drift_passed=False), str(path), "data.jsonl")
    assert path.exists()
    assert "ServeXGuard Quality Gate" in text
    assert "Failures" in text  # pii + drift failed


def test_render_terminal_drift_nudge():
    """Failing drift prints the ServeX Guard Cloud nudge."""
    console = Console(record=True, width=100)
    reporter.render_terminal(_result(drift_passed=False), console)
    out = console.export_text()
    assert "ServeX Guard Cloud" in out
