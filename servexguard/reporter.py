"""
Report generation for ServeXGuard.

Renders a :class:`~servexguard.core.GuardResult` as a terminal table (Rich),
a JSON document, or a Markdown report suitable for GitHub PR comments.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from servexguard.core import GuardResult

QUALITY_METRICS = {"faithfulness", "answer_relevancy", "context_recall", "context_precision"}
SECURITY_CHECKS = {"pii_scan", "injection_scan"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_report_dict(result: GuardResult, dataset_path: str | None = None) -> dict:
    """Assemble a structured report dict with metadata.

    Args:
        result: The aggregated guard result.
        dataset_path: Path of the evaluated dataset (for provenance).

    Returns:
        JSON-serializable report dict.
    """
    return {
        "tool": "servex-guard",
        "timestamp": _now_iso(),
        "dataset": dataset_path,
        **result.to_dict(),
    }


def to_json(result: GuardResult, path: str | None = None, dataset_path: str | None = None) -> str:
    """Serialize the result to JSON, optionally writing to ``path``.

    Args:
        result: The guard result.
        path: Output file path; if ``None``, only returns the string.
        dataset_path: Dataset path for provenance metadata.

    Returns:
        JSON string.
    """
    data = json.dumps(build_report_dict(result, dataset_path), indent=2, ensure_ascii=False)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(data, encoding="utf-8")
    return data


def to_markdown(
    result: GuardResult, path: str | None = None, dataset_path: str | None = None
) -> str:
    """Render the result as a Markdown report (PR-comment friendly).

    Args:
        result: The guard result.
        path: Output file path; if ``None``, only returns the string.
        dataset_path: Dataset path for provenance metadata.

    Returns:
        Markdown string.
    """
    badge = "✅ **PASSED**" if result.passed else "🚫 **FAILED**"
    lines: list[str] = [
        "# 🛡️ ServeXGuard Quality Gate",
        "",
        f"**Status:** {badge}",
        f"**Timestamp:** {_now_iso()}",
    ]
    if dataset_path:
        lines.append(f"**Dataset:** `{dataset_path}`")
    lines.append("")

    quality = [c for c in result.checks if c.name in QUALITY_METRICS]
    if quality:
        lines += [
            "## 📊 Quality Metrics",
            "",
            "| Metric | Score | Threshold | Status |",
            "|---|---|---|---|",
        ]
        for c in quality:
            score = f"{c.score:.3f}" if c.score is not None else "—"
            thresh = f"{c.threshold:.2f}" if c.threshold is not None else "—"
            lines.append(f"| {c.name} | {score} | {thresh} | {_status_icon(c)} |")
        lines.append("")

    security = [c for c in result.checks if c.name in SECURITY_CHECKS]
    if security:
        lines += ["## 🔒 Security Scan", "", "| Check | Issues | Status |", "|---|---|---|"]
        for c in security:
            count = int(c.score) if c.score is not None else 0
            lines.append(f"| {c.name.replace('_', ' ').title()} | {count} | {_status_icon(c)} |")
        lines.append("")

    drift = [c for c in result.checks if c.name == "query_drift"]
    if drift:
        c = drift[0]
        score = f"{c.score:.3f}" if c.score is not None else "—"
        lines += [
            "## 📈 Drift",
            "",
            f"Drift score: **{score}** (max {c.threshold}) {_status_icon(c)}",
            "",
        ]

    if not result.passed:
        lines += ["## ❌ Failures", ""]
        lines += [f"- {f}" for f in result.failures]
        lines.append("")

    text = "\n".join(lines)
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(text, encoding="utf-8")
    return text


def _status_icon(check) -> str:
    from servexguard.core import CheckStatus

    if check.status == CheckStatus.SKIPPED:
        return "⏭️"
    return "✅" if check.passed else "❌"


def render_terminal(result: GuardResult, console: Console | None = None) -> None:
    """Print the result as Rich tables to the terminal.

    Args:
        result: The guard result.
        console: Optional Rich console; a new one is created if omitted.
    """
    from servexguard.core import CheckStatus

    console = console or Console()

    quality = [c for c in result.checks if c.name in QUALITY_METRICS]
    if quality:
        table = Table(title="📊 Quality Metrics", border_style="blue")
        table.add_column("Metric", style="bold")
        table.add_column("Score", justify="right")
        table.add_column("Threshold", justify="right")
        table.add_column("Status", justify="center")
        skipped = [c for c in quality if c.status == CheckStatus.SKIPPED]
        for c in quality:
            # A skipped check must not wear the same red cross as a failed one:
            # one means "your system is bad", the other means "we did not look".
            if c.status == CheckStatus.SKIPPED:
                status, score_str = "[dim]skipped[/]", "[dim]not measured[/]"
            else:
                status = "[green]✅[/]" if c.passed else "[red]❌[/]"
                score_str = f"{c.score:.3f}" if c.score is not None else "-"
            thresh_str = f"{c.threshold:.2f}" if c.threshold is not None else "-"
            table.add_row(c.name, score_str, thresh_str, status)
        console.print(table)
        if skipped:
            console.print(
                "  [yellow]Quality metrics were not measured.[/] RAGAS is an optional "
                "extra:\n  [bold]pip install servex-guard\\[eval][/]  "
                "[dim](security scans ran normally)[/]"
            )

    security = [c for c in result.checks if c.name in SECURITY_CHECKS]
    if security:
        console.print()
        table = Table(title="🔒 Security Scan", border_style="yellow")
        table.add_column("Check", style="bold")
        table.add_column("Issues Found", justify="right")
        table.add_column("Status", justify="center")
        for c in security:
            status = "[green]✅[/]" if c.passed else "[red]❌[/]"
            count = int(c.score) if c.score is not None else 0
            noun = "leak" if c.name == "pii_scan" else "risk"
            label = f"{count} {noun}{'s' if count != 1 else ''}"
            table.add_row(c.name.replace("_", " ").title(), label, status)
        console.print(table)

    drift = [c for c in result.checks if c.name == "query_drift"]
    if drift:
        console.print()
        c = drift[0]
        status = "[green]✅[/]" if c.passed else "[red]❌[/]"
        console.print(f"  📈 Drift Score: {c.score:.3f}  (max: {c.threshold})  {status}")
        if not c.passed:
            console.print(
                "  [yellow]⚠️  Drift detected in CI.[/] For continuous monitoring "
                "and real-time alerts, see [bold]ServeX Guard Cloud[/]."
            )
