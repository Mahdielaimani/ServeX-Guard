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


_OFF = ["--min-faithfulness", "0", "--min-relevancy", "0", "--min-context-recall", "0"]
_ROW = '{"question": "q", "answer": "a", "contexts": ["c"], "ground_truth": "g"}\n'


def test_saving_a_baseline_succeeds(tmp_path, monkeypatch):
    """The documented first step exited 3, which would fail any CI job running it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "d.jsonl").write_text(_ROW, encoding="utf-8")
    args = ["check", "-d", "d.jsonl", "--baseline", "b.npy", *_OFF]

    saved = runner.invoke(app, [*args, "--check-drift", "--save-baseline"])
    assert saved.exit_code == 0, saved.output
    assert (tmp_path / "b.npy").exists()
    assert "baseline saved" in saved.output.lower()

    compared = runner.invoke(app, [*args, "--check-drift"])
    assert compared.exit_code == 0, compared.output


def test_save_baseline_alone_does_save(tmp_path, monkeypatch):
    """Without --check-drift the flag used to do nothing, and say nothing."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "d.jsonl").write_text(_ROW, encoding="utf-8")
    result = runner.invoke(
        app, ["check", "-d", "d.jsonl", "--baseline", "b.npy", "--save-baseline", *_OFF]
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "b.npy").exists()


def test_saving_a_baseline_does_not_excuse_missing_quality(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "d.jsonl").write_text(_ROW, encoding="utf-8")
    result = runner.invoke(
        app, ["check", "-d", "d.jsonl", "--baseline", "b.npy", "--save-baseline"]
    )
    assert result.exit_code == 3, result.output


def test_allow_unmeasured_does_not_pass_a_run_that_measured_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "d.jsonl").write_text(_ROW, encoding="utf-8")
    result = runner.invoke(app, ["check", "-d", "d.jsonl", "--allow-unmeasured"])
    assert result.exit_code == 3, result.output
    assert "turn on at least one check" in result.output
