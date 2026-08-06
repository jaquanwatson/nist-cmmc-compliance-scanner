"""Typer CLI: scan, score, poam, evidence, and report subcommands."""

from __future__ import annotations

import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from compliance_scanner import __version__
from compliance_scanner.evidence import DEFAULT_EVIDENCE_DIR, collect_evidence
from compliance_scanner.poam import generate_poam, to_markdown, write_csv
from compliance_scanner.report import write_json, write_markdown
from compliance_scanner.scan import run_scan
from compliance_scanner.score import score_scan

app = typer.Typer(
    name="compliance-scanner",
    help="CLI compliance automation for NIST 800-171 / CMMC 2.0 controls.",
    no_args_is_help=True,
)
console = Console()

STATUS_STYLES = {"pass": "green", "fail": "red", "error": "yellow", "not_applicable": "dim"}


@app.command()
def version() -> None:
    """Print the installed version."""
    typer.echo(__version__)


@app.command()
def scan(
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Write raw scan results as JSON to this path."
    ),
) -> None:
    """Run all registered checks and print a summary of results."""
    result = run_scan()

    table = Table(title=f"Scan results — {result.host}")
    table.add_column("Control")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Summary")
    for r in sorted(result.results, key=lambda r: r.control_id):
        style = STATUS_STYLES.get(r.status.value, "white")
        table.add_row(r.control_id, r.check_name, f"[{style}]{r.status.value}[/{style}]", r.summary)
    console.print(table)

    if output:
        payload = [
            {
                "control_id": r.control_id,
                "check_name": r.check_name,
                "status": r.status.value,
                "summary": r.summary,
                "detail": r.detail,
                "checked_at": r.checked_at.isoformat(),
            }
            for r in result.results
        ]
        output.write_text(json.dumps(payload, indent=2))
        console.print(f"[green]Wrote scan results to {output}[/green]")


@app.command()
def score() -> None:
    """Run a scan and print compliance scores by family and overall."""
    result = run_scan()
    report = score_scan(result)

    table = Table(title="Compliance score by family")
    table.add_column("Family")
    table.add_column("Score")
    table.add_column("Passed")
    table.add_column("Failed")
    table.add_column("Errored")
    table.add_column("Manual review")
    for f in report.families:
        table.add_row(
            f.family,
            f"{f.percent}%",
            str(f.passed),
            str(f.failed),
            str(f.errored),
            str(f.not_checked),
        )
    console.print(table)
    console.print(f"\n[bold]Overall compliance: {report.overall_percent}%[/bold]")


@app.command()
def poam(
    csv_path: Path | None = typer.Option(
        None, "--csv", help="Write POA&M items to this CSV path."
    ),
) -> None:
    """Run a scan and generate POA&M entries for failed controls."""
    result = run_scan()
    items = generate_poam(result)
    console.print(to_markdown(items))
    if csv_path:
        write_csv(items, csv_path)
        console.print(f"[green]Wrote {len(items)} POA&M item(s) to {csv_path}[/green]")


@app.command()
def evidence(
    output_dir: Path = typer.Option(
        DEFAULT_EVIDENCE_DIR, "--output-dir", "-o", help="Directory to write evidence artifacts to."
    ),
) -> None:
    """Run a scan and collect hashed evidence artifacts for every check result."""
    result = run_scan()
    index_path = collect_evidence(result, output_dir)
    console.print(
        f"[green]Wrote evidence for {len(result.results)} check(s) to "
        f"{output_dir} (index: {index_path})[/green]"
    )


@app.command()
def report(
    output: Path = typer.Option(
        Path("report.md"), "--output", "-o", help="Path to write the report to."
    ),
    json_output: Path | None = typer.Option(
        None, "--json", help="Also write a JSON report to this path."
    ),
    with_evidence: bool = typer.Option(
        False, "--with-evidence", help="Also collect evidence artifacts alongside the report."
    ),
    evidence_dir: Path = typer.Option(
        DEFAULT_EVIDENCE_DIR, "--evidence-dir", help="Directory for evidence artifacts."
    ),
) -> None:
    """Run the full pipeline (scan -> score -> poam[ -> evidence]) and write a report."""
    result = run_scan()
    score_report = score_scan(result)
    poam_items = generate_poam(result)

    write_markdown(score_report, poam_items, output)
    console.print(f"[green]Wrote report to {output}[/green]")

    if json_output:
        write_json(score_report, poam_items, json_output)
        console.print(f"[green]Wrote JSON report to {json_output}[/green]")

    if with_evidence:
        index_path = collect_evidence(result, evidence_dir)
        console.print(f"[green]Wrote evidence to {evidence_dir} (index: {index_path})[/green]")

    console.print(f"\n[bold]Overall compliance: {score_report.overall_percent}%[/bold]")


if __name__ == "__main__":
    app()
