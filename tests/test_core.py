

def test_missing_ragas_skips_rather_than_fails(monkeypatch):
    """A missing optional dependency must not block a deploy.

    evaluate_quality returns None when RAGAS is absent. Those checks are then
    skipped, and GuardResult.passed ignores skipped checks, so the gate reports
    on what it actually measured instead of failing three metrics it never ran.
    """
    from servexguard import core as core_mod

    monkeypatch.setattr(core_mod, "_run_quality", None, raising=False)
    guard = core_mod.ServeXGuard()
    monkeypatch.setattr(
        "servexguard.evaluator.evaluate_quality", lambda data: None
    )
    checks = guard._run_quality([{"question": "q", "answer": "a", "contexts": ["c"]}])

    assert len(checks) == 3
    assert all(c.status == core_mod.CheckStatus.SKIPPED for c in checks)
    assert all(c.score is None for c in checks)

    result = core_mod.GuardResult(checks=list(checks))
    assert result.passed is True
    assert result.exit_code == 0
    assert result.failures == []


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
