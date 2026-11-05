"""Core gate behaviour."""

import json


def _core():
    from servexguard import core

    return core


ROW = {"question": "q", "answer": "a", "contexts": ["c"], "ground_truth": "g"}


def _not_measured(*args, **kwargs):
    from servexguard.evaluator import QualityNotMeasuredError

    raise QualityNotMeasuredError("RAGAS is not installed", "pip install servex-guard[eval]")


def test_requested_quality_that_cannot_run_blocks_the_gate(monkeypatch):
    """A missing dependency must not read as a deploy that passed."""
    core = _core()
    monkeypatch.setattr("servexguard.evaluator.evaluate_quality", _not_measured)
    checks = core.ServeXGuard()._run_quality([ROW])

    assert [c.status for c in checks] == [core.CheckStatus.NOT_MEASURED] * 3
    assert all(c.score is None for c in checks)

    result = core.GuardResult(checks=checks)
    assert result.passed is False
    assert result.verdict == "not_measured"
    assert result.exit_code == 3
    assert result.failures == []


def test_a_real_failure_outranks_missing_evidence():
    core = _core()
    result = core.GuardResult(
        checks=[
            core.CheckResult("faithfulness", core.CheckStatus.NOT_MEASURED),
            core.CheckResult("pii_scan", core.CheckStatus.FAILED, 1.0, 0.0),
        ]
    )
    assert result.verdict == "failed"
    assert result.exit_code == 1


def test_threshold_zero_switches_a_metric_off_without_calling_the_llm(monkeypatch):
    core = _core()
    monkeypatch.setattr("servexguard.evaluator.evaluate_quality", _not_measured)
    guard = core.ServeXGuard(min_faithfulness=0.0, min_relevancy=0.0, min_context_recall=0.0)
    checks = guard._run_quality([ROW])
    assert [c.status for c in checks] == [core.CheckStatus.SKIPPED] * 3


def test_only_positive_thresholds_are_requested(monkeypatch):
    from servexguard.evaluator import QualityScores

    core = _core()
    asked = []

    def fake(data, metrics, llm):
        asked.extend(metrics)
        return QualityScores(scores={"faithfulness": 0.9}, coverage={"faithfulness": 1.0})

    monkeypatch.setattr("servexguard.evaluator.evaluate_quality", fake)
    guard = core.ServeXGuard(min_relevancy=0.0, min_context_recall=0.0)
    checks = {c.name: c for c in guard._run_quality([ROW])}
    assert asked == ["faithfulness"]
    assert checks["faithfulness"].status == core.CheckStatus.PASSED
    assert checks["faithfulness"].details == {"coverage": 1.0}


def test_nothing_enabled_is_not_a_pass(monkeypatch, tmp_path):
    """Every check off used to print PASSED, Safe to deploy, and exit 0."""
    core = _core()
    monkeypatch.chdir(tmp_path)
    (tmp_path / "d.jsonl").write_text(json.dumps(ROW), encoding="utf-8")
    guard = core.ServeXGuard(min_faithfulness=0.0, min_relevancy=0.0, min_context_recall=0.0)
    result = guard.check("d.jsonl")
    assert result.verdict == "not_measured"
    assert result.exit_code == 3


def test_allow_unmeasured_accepts_the_gap_explicitly(monkeypatch, tmp_path):
    core = _core()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("servexguard.evaluator.evaluate_quality", _not_measured)
    (tmp_path / "d.jsonl").write_text(json.dumps(ROW), encoding="utf-8")
    result = core.ServeXGuard(check_injection=True, allow_unmeasured=True).check("d.jsonl")
    assert result.verdict == "passed"
    assert result.exit_code == 0


def test_security_failures_read_in_the_right_direction():
    """A count check fails by exceeding a ceiling, not by falling below a floor."""
    from servexguard.core import CheckResult, CheckStatus, GuardResult

    result = GuardResult(checks=[
        CheckResult(name="injection_scan", status=CheckStatus.FAILED,
                    score=1.0, threshold=0.0),
        CheckResult(name="faithfulness", status=CheckStatus.FAILED,
                    score=0.41, threshold=0.8),
    ])
    assert result.failures[0] == "injection_scan: 1 risk found (max 0)"
    assert result.failures[1] == "faithfulness: 0.410 below the 0.8 threshold"


def test_demo_datasets_do_what_the_narration_claims(tmp_path, monkeypatch):
    """The demo only works if the flawed set fails and the clean set passes.

    Asserted rather than assumed: this is the first thing a new user runs, and
    a demo whose "after" still failed would be worse than shipping none.
    """
    from servexguard.core import ServeXGuard
    from servexguard.demo import CLEAN, FLAWED, write_dataset

    monkeypatch.chdir(tmp_path)
    guard = ServeXGuard(
        min_faithfulness=0.0,
        min_relevancy=0.0,
        min_context_recall=0.0,
        check_pii=True,
        check_injection=True,
        language="fr",
    )

    before = guard.check(str(write_dataset(FLAWED, tmp_path / "flawed.jsonl")))
    assert before.passed is False
    assert before.exit_code == 1
    names = {c.name for c in before.checks if not c.passed
             and c.status != __import__("servexguard.core", fromlist=["x"]).CheckStatus.SKIPPED}
    assert names == {"pii_scan", "injection_scan"}

    after = guard.check(str(write_dataset(CLEAN, tmp_path / "clean.jsonl")))
    assert after.passed is True
    assert after.exit_code == 0
    assert after.failures == []
