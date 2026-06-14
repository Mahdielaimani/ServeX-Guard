"""CLI integration tests using typer's CliRunner."""

from __future__ import annotations

from typer.testing import CliRunner

from servexguard import __version__
from servexguard.cli import app

runner = CliRunner()

GOLDEN = "examples/golden_dataset.jsonl"


def test_check_missing_dataset(tmp_path, monkeypatch):
    """Missing dataset → exit 1 with an error message."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["check", "--dataset", "nope.jsonl"])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_check_injection_only():
    """Injection-only run on the golden dataset passes (no injections)."""
    result = runner.invoke(
        app,
        [
            "check",
            "--dataset", GOLDEN,
            "--check-injection",
            "--min-faithfulness", "0.0",
            "--min-relevancy", "0.0",
            "--min-context-recall", "0.0",
        ],
    )
    assert result.exit_code == 0


def test_init_command(tmp_path, monkeypatch):
    """init creates servexguard.yaml in the working directory."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert (tmp_path / "servexguard.yaml").exists()


def test_init_duplicate_blocked(tmp_path, monkeypatch):
    """A second init without --force exits 1."""
    monkeypatch.chdir(tmp_path)
    assert runner.invoke(app, ["init"]).exit_code == 0
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 1


def test_version_command():
    """version prints the package version string."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
