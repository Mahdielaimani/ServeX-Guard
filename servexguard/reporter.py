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
SECURITY_CHECKS = {"pii_scan", "injection_scan", "injection_judge"}


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
    badge = {
        "passed": "✅ **PASSED**",
        "failed": "🚫 **FAILED**",
        "not_measured": "⛔ **NOT MEASURED**",
    }[result.verdict]
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
            count = int(c.score) if c.score is not None else "—"
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

    if result.failures:
        lines += ["## ❌ Failures", ""]
        lines += [f"- {f}" for f in result.failures]
        lines.append("")

    if result.not_measured:
        lines += ["## ⛔ Not measured", ""]
        lines += [f"- {c.name}: {c.details.get('reason')}" for c in result.not_measured]
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
    if check.status == CheckStatus.NOT_MEASURED:
        return "⛔"
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
        for c in quality:
            # Neither of these may wear the red cross of a failed check: that one
            # means "your system is bad", these mean "we did not look".
            if c.status == CheckStatus.SKIPPED:
                status, score_str = "[dim]off[/]", "[dim]-[/]"
            elif c.status == CheckStatus.NOT_MEASURED:
                status, score_str = "[yellow]⛔[/]", "[yellow]not measured[/]"
            else:
                status = "[green]✅[/]" if c.passed else "[red]❌[/]"
                score_str = f"{c.score:.3f}" if c.score is not None else "-"
            thresh_str = f"{c.threshold:.2f}" if c.threshold is not None else "-"
            table.add_row(c.name, score_str, thresh_str, status)
        console.print(table)
        fixes = {c.details["fix"] for c in quality if c.details.get("fix")}
        for fix in sorted(fixes):
            console.print(f"  [yellow]To measure quality:[/] {fix}", markup=False)

    security = [c for c in result.checks if c.name in SECURITY_CHECKS]
    if security:
        console.print()
        table = Table(title="🔒 Security Scan", border_style="yellow")
        table.add_column("Check", style="bold")
        table.add_column("Issues Found", justify="right")
        table.add_column("Status", justify="center")
        for c in security:
            if c.score is None:
                # "0 risks" here would read as a clean scan that never happened.
                status, label = "[yellow]⛔[/]", "[yellow]not measured[/]"
            else:
                status = "[green]✅[/]" if c.passed else "[red]❌[/]"
                count = int(c.score)
                noun = "leak" if c.name == "pii_scan" else "risk"
                label = f"{count} {noun}{'s' if count != 1 else ''}"
            table.add_row(c.name.replace("_", " ").title(), label, status)
        console.print(table)
        detector = next(
            (c.details["detector"] for c in security if c.details.get("detector")), None
        )
        if detector and detector != "presidio":
            console.print(f"  [yellow]PII detector:[/] {detector}", highlight=False)
        if any(c.name.startswith("injection") for c in security):
            console.print(
                "  [dim]Injection checks miss attacks they have not seen. Zero risks "
                "does not prove a system is safe.[/]"
            )
        for c in security:
            if c.name != "injection_judge":
                continue
            if c.details.get("unjudged"):
                console.print(
                    f"  [yellow]Injection judge:[/] {c.details['unjudged']} texts got no "
                    "clear verdict and were not cleared."
                )
            if c.details.get("truncated_fields"):
                console.print(
                    f"  [yellow]Injection judge:[/] {c.details['truncated_fields']} long "
                    "fields were judged only in part."
                )

    drift = [c for c in result.checks if c.name == "query_drift"]
    if drift:
        console.print()
        c = drift[0]
        if c.score is None:
            console.print(f"  📈 Drift: [yellow]{c.details.get('reason')}[/]")
            if c.details.get("fix"):
                console.print(f"     {c.details['fix']}", markup=False)
            return
        status = "[green]✅[/]" if c.passed else "[red]❌[/]"
        console.print(f"  📈 Drift Score: {c.score:.3f}  (max: {c.threshold})  {status}")
        if not c.passed:
            console.print(
                "  [yellow]⚠️  Drift detected in CI.[/] For continuous monitoring "
                "and real-time alerts, see [bold]ServeX Guard Cloud[/]."
            )
