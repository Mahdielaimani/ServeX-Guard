"""Upload must never break a CI run, and must map scores to the Cloud's shape."""

from __future__ import annotations

import json

import pytest

from servexguard import uploader
from servexguard.core import CheckResult, CheckStatus, GuardResult


@pytest.fixture(autouse=True)
def _no_git_or_key(monkeypatch):
    """Isolate from the ambient repo and environment."""
    monkeypatch.delenv("SERVEXGUARD_API_KEY", raising=False)
    monkeypatch.delenv("SERVEXGUARD_CLOUD_URL", raising=False)
    for var in ("GITHUB_SHA", "GITHUB_REF", "CI_COMMIT_SHA", "CI_COMMIT_REF_NAME"):
        monkeypatch.delenv(var, raising=False)


def _result() -> GuardResult:
    return GuardResult(
        checks=[
            CheckResult("faithfulness", CheckStatus.PASSED, 0.91, 0.80),
            CheckResult("answer_relevancy", CheckStatus.PASSED, 0.88, 0.75),
            CheckResult("context_recall", CheckStatus.PASSED, 0.79, 0.70),
            CheckResult("pii_scan", CheckStatus.FAILED, 2.0, 0.0),
            CheckResult("injection_scan", CheckStatus.PASSED, 0.0, 0.0),
            CheckResult("query_drift", CheckStatus.PASSED, 0.12, 0.25),
        ]
    )


def test_payload_maps_every_stored_metric():
    payload = uploader.build_payload(_result(), project="my-rag", dataset_path="golden.jsonl")

    assert payload["project"] == "my-rag"
    assert payload["passed"] is False  # pii_scan failed
    assert payload["faithfulness"] == 0.91
    assert payload["answer_relevancy"] == 0.88
    assert payload["context_recall"] == 0.79
    assert payload["pii_leaks"] == 2
    assert payload["injection_risks"] == 0
    assert payload["drift_score"] == 0.12
    assert payload["raw_report"]["dataset"] == "golden.jsonl"


def test_payload_is_json_serializable():
    json.dumps(uploader.build_payload(_result()))


def test_skipped_and_absent_checks_are_omitted():
    """A scan that never ran must not be reported as a clean zero."""
    result = GuardResult(
        checks=[
            CheckResult("faithfulness", CheckStatus.SKIPPED, 0.0, 0.80),
            CheckResult("injection_scan", CheckStatus.PASSED, 0.0, 0.0),
        ]
    )
    payload = uploader.build_payload(result)

    assert "faithfulness" not in payload
    assert "pii_leaks" not in payload          # scan was never enabled
    assert payload["injection_risks"] == 0     # scan ran and found nothing


def test_oversized_fields_are_clipped(monkeypatch):
    monkeypatch.setenv("GITHUB_REF", "refs/heads/" + "x" * 500)
    payload = uploader.build_payload(_result(), project="p" * 300)

    assert len(payload["project"]) == uploader.MAX_PROJECT_CHARS
    assert len(payload["git_ref"]) == uploader.MAX_REF_CHARS


def test_git_metadata_read_from_ci_env(monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_REF", "refs/heads/main")
    payload = uploader.build_payload(_result())

    assert payload["git_sha"] == "abc123"
    assert payload["git_ref"] == "refs/heads/main"


def test_upload_without_api_key_returns_false():
    assert uploader.upload(_result()) is False


def test_upload_to_unreachable_host_never_raises():
    assert (
        uploader.upload(
            _result(), api_key="sxg_fake", cloud_url="http://127.0.0.1:1/v1/runs"
        )
        is False
    )


def test_upload_survives_a_broken_payload(monkeypatch):
    """Even an internal error must degrade to False, not propagate."""
    monkeypatch.setattr(uploader, "build_payload", lambda *a, **k: object())
    assert uploader.upload(_result(), api_key="sxg_fake") is False


def test_default_cloud_url_env_override(monkeypatch):
    assert uploader.default_cloud_url() == uploader.DEFAULT_CLOUD_URL
    monkeypatch.setenv("SERVEXGUARD_CLOUD_URL", "http://localhost:8000/v1/runs")
    assert uploader.default_cloud_url() == "http://localhost:8000/v1/runs"
