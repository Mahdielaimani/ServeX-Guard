"""
Upload already-computed results to ServeX Guard Cloud.

No detection logic lives here — every score in the payload was computed locally
by :mod:`servexguard.core`. This module only flattens the report to the shape the
Cloud's ``POST /v1/runs`` endpoint expects and ships it.

Uses :mod:`urllib.request` from the standard library so the CLI gains no new
dependency: the offline core stays offline.

An upload must never fail the CI run. Every entry point here swallows its
exceptions and logs a warning instead.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from servexguard.core import GuardResult

DEFAULT_CLOUD_URL = "https://api.servexguard.com/v1/runs"
API_KEY_ENV = "SERVEXGUARD_API_KEY"
TIMEOUT_SECONDS = 10

# Cloud-side validation caps; truncate here so an oversized value can't turn a
# successful run into a rejected upload.
MAX_PROJECT_CHARS = 100
MAX_SHA_CHARS = 40
MAX_REF_CHARS = 200

logger = logging.getLogger(__name__)

# CLI check name -> Cloud column, for the metrics the Cloud stores flat.
_QUALITY_FIELDS = {
    "faithfulness": "faithfulness",
    "answer_relevancy": "answer_relevancy",
    "context_recall": "context_recall",
}
_COUNT_FIELDS = {
    "pii_scan": "pii_leaks",
    "injection_scan": "injection_risks",
}


def default_cloud_url() -> str:
    """Cloud endpoint: ``SERVEXGUARD_CLOUD_URL`` if set, else the public API."""
    return os.getenv("SERVEXGUARD_CLOUD_URL") or DEFAULT_CLOUD_URL


def _git(*args: str) -> str | None:
    """Run a git command, returning stripped stdout or ``None`` on any failure."""
    try:
        out = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = out.stdout.strip()
    return value or None


def git_sha() -> str | None:
    """Commit SHA — from the CI environment first, then the local repo."""
    return (
        os.getenv("GITHUB_SHA")
        or os.getenv("CI_COMMIT_SHA")
        or _git("rev-parse", "HEAD")
    )


def git_ref() -> str | None:
    """Branch or tag ref — from the CI environment first, then the local repo."""
    return (
        os.getenv("GITHUB_REF")
        or os.getenv("CI_COMMIT_REF_NAME")
        or _git("rev-parse", "--abbrev-ref", "HEAD")
    )


def _clip(value: str | None, limit: int) -> str | None:
    return value[:limit] if value else value


def build_payload(
    result: GuardResult,
    project: str = "default",
    dataset_path: str | None = None,
) -> dict[str, Any]:
    """Flatten a :class:`~servexguard.core.GuardResult` for ``POST /v1/runs``.

    Checks that did not run are omitted rather than sent as zeros, so the Cloud
    can't display "0 PII leaks" for a scan that was never enabled. The complete
    report still travels in ``raw_report``, which the Cloud treats as the source
    of truth.

    Args:
        result: The locally computed guard result.
        project: Cloud project name; the Cloud creates it on first upload.
        dataset_path: Dataset path, for provenance inside ``raw_report``.

    Returns:
        JSON-serializable payload dict.
    """
    from servexguard import reporter
    from servexguard.core import CheckStatus

    payload: dict[str, Any] = {
        "project": (project or "default")[:MAX_PROJECT_CHARS],
        "passed": result.passed,
        "git_sha": _clip(git_sha(), MAX_SHA_CHARS),
        "git_ref": _clip(git_ref(), MAX_REF_CHARS),
        "raw_report": reporter.build_report_dict(result, dataset_path),
    }

    for check in result.checks:
        if check.status == CheckStatus.SKIPPED or check.score is None:
            continue
        if check.name in _QUALITY_FIELDS:
            payload[_QUALITY_FIELDS[check.name]] = float(check.score)
        elif check.name in _COUNT_FIELDS:
            payload[_COUNT_FIELDS[check.name]] = int(check.score)
        elif check.name == "query_drift":
            payload["drift_score"] = float(check.score)

    return payload


def upload(
    result: GuardResult,
    project: str = "default",
    dataset_path: str | None = None,
    cloud_url: str | None = None,
    api_key: str | None = None,
) -> bool:
    """POST the computed report to ServeX Guard Cloud.

    Never raises: a missing key, an unreachable Cloud, or a rejected payload all
    log a warning and return ``False``. The CI verdict comes from the local
    checks, never from the upload.

    Args:
        result: The locally computed guard result.
        project: Cloud project name.
        dataset_path: Dataset path, for provenance.
        cloud_url: Endpoint override; defaults to :func:`default_cloud_url`.
        api_key: API key override; defaults to ``$SERVEXGUARD_API_KEY``.

    Returns:
        ``True`` if the Cloud accepted the run, ``False`` otherwise.
    """
    key = api_key or os.getenv(API_KEY_ENV, "")
    if not key:
        logger.warning("Upload skipped: %s is not set.", API_KEY_ENV)
        return False

    url = cloud_url or default_cloud_url()
    try:
        body = json.dumps(build_payload(result, project, dataset_path)).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            if 200 <= response.status < 300:
                return True
            logger.warning("Upload failed: HTTP %s from %s", response.status, url)
            return False
    except urllib.error.HTTPError as exc:
        logger.warning("Upload failed: HTTP %s from %s — %s", exc.code, url, exc.reason)
    except Exception as exc:  # network down, DNS, bad payload — never fail the run
        logger.warning("Upload failed: %s", exc)
    return False
