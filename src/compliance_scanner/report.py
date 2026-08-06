"""Renders scan, score, and POA&M results into a markdown report or JSON export."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from compliance_scanner.models import CheckStatus, POAMItem, ScoreReport
from compliance_scanner.poam import to_markdown as poam_to_markdown


def render_markdown(score: ScoreReport, poam_items: list[POAMItem]) -> str:
    scan = score.scan
    lines = [
        "# NIST 800-171 Compliance Report",
        "",
        f"**Host:** {scan.host}  ",
        f"**Scan window:** {scan.started_at.isoformat()} -> {scan.finished_at.isoformat()}  ",
        f"**Overall compliance:** {score.overall_percent}%",
        "",
        "## Score by Family",
        "",
        "| Family | Score | Passed | Failed | Errored | Manual Review | N/A |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in score.families:
        lines.append(
            f"| {f.family} | {f.percent}% | {f.passed} | {f.failed} | {f.errored} | "
            f"{f.not_checked} | {f.not_applicable} |"
        )

    lines += ["", "## Findings", "", "| Control | Check | Status | Summary |", "|---|---|---|---|"]
    for result in sorted(scan.results, key=lambda r: r.control_id):
        lines.append(
            f"| {result.control_id} | {result.check_name} | {result.status.value} | "
            f"{result.summary} |"
        )

    lines += ["", "## POA&M — Open Items", "", poam_to_markdown(poam_items)]

    return "\n".join(lines)


def render_json(score: ScoreReport, poam_items: list[POAMItem]) -> str:
    scan = score.scan
    payload = {
        "host": scan.host,
        "started_at": scan.started_at,
        "finished_at": scan.finished_at,
        "overall_percent": score.overall_percent,
        "families": [asdict(f) for f in score.families],
        "results": [asdict(r) for r in scan.results],
        "poam": [asdict(p) for p in poam_items],
    }
    return json.dumps(payload, indent=2, default=_json_default)


def write_markdown(score: ScoreReport, poam_items: list[POAMItem], path: str | Path) -> None:
    Path(path).write_text(render_markdown(score, poam_items))


def write_json(score: ScoreReport, poam_items: list[POAMItem], path: str | Path) -> None:
    Path(path).write_text(render_json(score, poam_items))


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, CheckStatus):
        return obj.value
    raise TypeError(f"Not JSON serializable: {obj!r}")
