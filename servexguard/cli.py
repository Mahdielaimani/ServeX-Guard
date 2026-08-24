"""
🛡️ ServeXGuard CLI — Production quality gate for RAG systems.

Usage:
    servexguard check --dataset golden.jsonl --min-faithfulness 0.80
    servexguard check --dataset golden.jsonl --check-pii --check-injection
    servexguard init
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from servexguard import reporter
from servexguard.config import load_config, merge_cli_overrides, write_default_config
from servexguard.core import ServeXGuard
from servexguard.uploader import DEFAULT_CLOUD_URL

# Make emoji-rich output safe on legacy Windows consoles (cp1252) so the CLI
# never crashes with UnicodeEncodeError. Best-effort; no-op where unsupported.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure is not None:
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

app = typer.Typer(
    name="servexguard",
    help="🛡️ ServeXGuard — Production quality gate for RAG systems.",
    add_completion=False,
)
console = Console()


@app.command()
def check(
    dataset: str | None = typer.Option(
        None, "--dataset", "-d", help="Path to JSONL golden dataset"
    ),
    config: str | None = typer.Option(
        None, "--config", "-c", help="Path to servexguard.yaml (auto-discovered if omitted)"
    ),
    min_faithfulness: float | None = typer.Option(
        None, "--min-faithfulness", help="Minimum faithfulness score [default: 0.80]"
    ),
    min_relevancy: float | None = typer.Option(
        None, "--min-relevancy", help="Minimum answer relevancy score [default: 0.75]"
    ),
    min_context_recall: float | None = typer.Option(
        None, "--min-context-recall", help="Minimum context recall score [default: 0.70]"
    ),
    check_pii: bool | None = typer.Option(
        None, "--check-pii/--no-check-pii", help="Enable PII leak detection"
    ),
    check_injection: bool | None = typer.Option(
        None, "--check-injection/--no-check-injection", help="Enable prompt injection scanning"
    ),
    check_drift: bool | None = typer.Option(
        None, "--check-drift/--no-check-drift", help="Enable query drift detection"
    ),
    drift_threshold: float | None = typer.Option(
        None, "--drift-threshold", help="Maximum drift score [default: 0.25]"
    ),
    language: str | None = typer.Option(
        None, "--language", help="PII language: en | fr | ar [default: en]"
    ),
    baseline: str | None = typer.Option(
        None, "--baseline", help="Path to baseline embeddings (.npy)"
    ),
    save_baseline: bool = typer.Option(
        False, "--save-baseline", help="Save current embeddings as the new drift baseline"
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Save report to file"
    ),
    fmt: str | None = typer.Option(
        None, "--format", "-f", help="Report format: terminal | json | markdown"
    ),
    upload: bool = typer.Option(
        False, "--upload", help="Upload the report to ServeX Guard Cloud "
        "(requires SERVEXGUARD_API_KEY)"
    ),
    cloud_url: str | None = typer.Option(
        None, "--cloud-url", help=f"Cloud ingest endpoint [default: {DEFAULT_CLOUD_URL}]"
    ),
    project: str | None = typer.Option(
        None, "--project", help="Cloud project name [default: default]"
    ),
) -> None:
    """
    🛡️ Run ServeXGuard quality gate on your RAG golden dataset.

    Checks quality (RAGAS), security (PII + injection), and drift.
    Returns exit code 1 if any check fails — blocks CI/CD deployment.

    Configuration is loaded from servexguard.yaml (auto-discovered or --config);
    CLI flags override YAML values.
    """
    console.print()
    console.print(
        Panel("[bold white]🛡️ ServeXGuard Quality Gate[/]", border_style="bright_blue")
    )

    # Load config (YAML/defaults) then apply CLI overrides
    try:
        cfg = load_config(config)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[red]❌ {exc}[/]")
        raise typer.Exit(code=1)

    cfg = merge_cli_overrides(
        cfg,
        {
            "min_faithfulness": min_faithfulness,
            "min_relevancy": min_relevancy,
            "min_context_recall": min_context_recall,
            "check_pii": check_pii,
            "check_injection": check_injection,
            "check_drift": check_drift,
            "drift_threshold": drift_threshold,
            "language": language,
            "baseline": baseline,
            "dataset": dataset,
            "output": output,
        },
    )

    dataset_path = cfg.dataset.path
    if not dataset_path:
        console.print(
            "\n[red]❌ No dataset specified "
            "(use --dataset or set dataset.path in config)[/]"
        )
        raise typer.Exit(code=1)

    if not Path(dataset_path).exists():
        console.print(f"\n[red]❌ Dataset not found: {dataset_path}[/]")
        raise typer.Exit(code=1)

    guard = ServeXGuard(
        min_faithfulness=cfg.quality.min_faithfulness,
        min_relevancy=cfg.quality.min_relevancy,
        min_context_recall=cfg.quality.min_context_recall,
        check_pii=cfg.security.check_pii,
        check_injection=cfg.security.check_injection,
        check_drift=cfg.drift.enabled,
        drift_threshold=cfg.drift.max_query_drift,
        baseline_path=cfg.drift.baseline_file,
        language=cfg.security.language,
        custom_entities=[e.model_dump() for e in cfg.security.custom_entities],
        save_baseline=save_baseline,
    )

    console.print("\n[dim]Running checks...[/]\n")
    try:
        result = guard.check(dataset_path)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"\n[red]❌ {exc}[/]")
        raise typer.Exit(code=1)

    reporter.render_terminal(result, console)

    # Calibration tip when quality scoring produced no signal.
    quality_scores = [
        c.score for c in result.checks
        if c.name in {"faithfulness", "answer_relevancy", "context_recall"}
        and c.score is not None
    ]
    if quality_scores and all(s == 0.0 for s in quality_scores):
        # A missing RAGAS now yields skipped checks with no score, so it cannot
        # reach here: real zeros mean RAGAS ran and had nothing to call.
        console.print(
            "\n[yellow]Tip:[/] Every quality score is 0.0, which means RAGAS ran "
            "but had no LLM endpoint configured. Set your provider key, or run "
            "with [bold]--min-faithfulness 0.0[/] to gate on the security scans "
            "alone."
        )

    # Save report in requested format
    report_format = (fmt or cfg.output.format or "terminal").lower()
    out_path = output or cfg.output.path
    if out_path:
        if report_format == "markdown":
            reporter.to_markdown(result, out_path, dataset_path)
        else:
            reporter.to_json(result, out_path, dataset_path)
        console.print(f"\n[dim]📄 Report saved to: {out_path}[/]")

    # Ship the already-computed report to the Cloud. Never affects the verdict
    # or the exit code — a failed upload is a warning, not a broken pipeline.
    if upload:
        from servexguard import uploader

        if uploader.upload(
            result,
            project=project or "default",
            dataset_path=dataset_path,
            cloud_url=cloud_url,
        ):
            console.print("\n[dim]☁️  Uploaded to ServeX Guard Cloud[/]")
        else:
            console.print(
                "\n[yellow]⚠️  Cloud upload failed — run result is unaffected.[/]\n"
                "[dim]   Check SERVEXGUARD_API_KEY and --cloud-url.[/]"
            )

    console.print()
    if result.passed:
        console.print("[bold green]✅ QUALITY GATE PASSED — Safe to deploy[/]\n")
    else:
        console.print("[bold red]🚫 QUALITY GATE FAILED — Deployment blocked[/]")
        console.print(f"[red]   Failures: {', '.join(result.failures)}[/]\n")

    raise typer.Exit(code=result.exit_code)


@app.command()
def init(
    path: str = typer.Option(
        "servexguard.yaml", "--path", "-p", help="Where to write the config"
    ),
    force: bool = typer.Option(False, "--force", help="Overwrite if it exists"),
) -> None:
    """Generate a default servexguard.yaml in the current project."""
    target = Path(path)
    if target.exists() and not force:
        console.print(f"[yellow]⚠️  {target} already exists. Use --force to overwrite.[/]")
        raise typer.Exit(code=1)
    if target.exists() and force:
        target.unlink()
    write_default_config(target)
    console.print(f"[green]✅ Wrote default config: {target}[/]")


@app.command()
def demo() -> None:
    """Run the gate on a bundled example. No dataset or API key needed.

    Writes a small golden dataset into the current directory and runs the gate
    against it twice: once with two planted problems, once after they are fixed.
    Seeing a deploy blocked and then allowed is the fastest way to understand
    what this tool does.
    """
    import logging

    from servexguard.core import ServeXGuard
    from servexguard.demo import CLEAN, DEMO_FILE, FLAWED, write_dataset

    # The optional-dependency warnings are already reported, once and in plain
    # English, by the report itself. Logging them raw before each of the two
    # runs is four extra lines of noise in the first thing anyone sees.
    logging.getLogger("servexguard").setLevel(logging.ERROR)
    for name in ("servexguard.evaluator", "servexguard.security"):
        logging.getLogger(name).setLevel(logging.ERROR)

    console.print(
        "\n[bold]ServeXGuard demo[/]\n"
        "A retail-banking assistant, checked the way your CI would check it.\n"
    )

    console.rule("[bold red]1 of 2 — before the fix[/]")
    console.print(
        f"[dim]{len(FLAWED)} rows written to {DEMO_FILE}. One answer repeats a "
        f"customer's bank details; one question tries a prompt injection, and it "
        f"matches two known patterns.[/]\n"
    )
    write_dataset(FLAWED, DEMO_FILE)
    guard = ServeXGuard(check_pii=True, check_injection=True, language="fr")
    before = guard.check(DEMO_FILE)
    reporter.render_terminal(before, console)
    console.print(
        f"\n[red]Exit code {before.exit_code} — this deploy is blocked.[/]"
        if not before.passed
        else "\n[green]Passed.[/]"
    )
    for f in before.failures:
        console.print(f"  [red]•[/] {f}")

    console.rule("\n[bold green]2 of 2 — after the fix[/]")
    console.print(
        "[dim]The assistant now refuses to repeat personal data, and the "
        "injection row is gone. Nothing else changed.[/]\n"
    )
    write_dataset(CLEAN, DEMO_FILE)
    after = guard.check(DEMO_FILE)
    reporter.render_terminal(after, console)
    console.print(
        f"\n[green]Exit code {after.exit_code} — this deploy is allowed.[/]"
        if after.passed
        else f"\n[red]Exit code {after.exit_code}.[/]"
    )

    # Leave the flawed version behind: a file they can open and break again is
    # worth more than a clean one they have no reason to look at.
    write_dataset(FLAWED, DEMO_FILE)
    console.print(
        f"\n[bold]What just happened[/]\n"
        f"  The gate returns a non-zero exit code, so CI stops the merge.\n"
        f"  Quality metrics need an extra: [bold]pip install servex-guard\\[eval][/]\n\n"
        f"[bold]Next[/]\n"
        f"  [dim]# {DEMO_FILE} is on disk with the problems back in. Edit it and rerun:[/]\n"
        f"  servexguard check --dataset {DEMO_FILE} --check-pii --check-injection\n"
    )


@app.command()
def version() -> None:
    """Show ServeXGuard version."""
    from servexguard import __version__

    console.print(f"🛡️ ServeXGuard v{__version__}")


if __name__ == "__main__":
    app()
