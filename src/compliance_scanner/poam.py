"""Generates and exports POA&M (Plan of Action & Milestones) entries for failed controls."""

from __future__ import annotations

import csv
from datetime import datetime, timedelta
from pathlib import Path

from compliance_scanner.controls.loader import catalog_by_id, load_catalog
from compliance_scanner.models import CheckStatus, Control, POAMItem, ScanResult

DEFAULT_REMEDIATION_WINDOW_DAYS = 60
HIGH_SEVERITY_FAMILIES = {"AC", "IA"}

CSV_FIELDS = [
    "control_id",
    "family",
    "weakness",
    "severity",
    "identified_at",
    "scheduled_completion",
    "resources_required",
    "milestones",
    "status",
]


def generate_poam(scan: ScanResult, controls: list[Control] | None = None) -> list[POAMItem]:
    controls = controls if controls is not None else load_catalog()
    by_id = catalog_by_id(controls)

    items: list[POAMItem] = []
    seen: set[str] = set()
    for result in scan.results:
        if result.status not in (CheckStatus.FAIL, CheckStatus.ERROR):
            continue
        if result.control_id in seen:
            continue
        seen.add(result.control_id)

        control = by_id.get(result.control_id)
        if control is None:
            continue

        items.append(
            POAMItem(
                control_id=control.id,
                family=control.family,
                weakness=f"{control.title}: {result.summary}",
                severity=_severity_for(control),
                identified_at=result.checked_at,
                scheduled_completion=_scheduled_completion(result.checked_at),
            )
        )

    return sorted(items, key=lambda item: item.control_id)


def _severity_for(control: Control) -> str:
    return "High" if control.family in HIGH_SEVERITY_FAMILIES else "Moderate"


def _scheduled_completion(identified_at: datetime) -> str:
    return (identified_at + timedelta(days=DEFAULT_REMEDIATION_WINDOW_DAYS)).date().isoformat()


def write_csv(items: list[POAMItem], path: str | Path) -> None:
    with Path(path).open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for item in items:
            writer.writerow(
                {
                    "control_id": item.control_id,
                    "family": item.family,
                    "weakness": item.weakness,
                    "severity": item.severity,
                    "identified_at": item.identified_at.isoformat(),
                    "scheduled_completion": item.scheduled_completion,
                    "resources_required": item.resources_required,
                    "milestones": item.milestones,
                    "status": item.status,
                }
            )


def to_markdown(items: list[POAMItem]) -> str:
    if not items:
        return "No open POA&M items — every checked control passed.\n"

    header = "| Control | Family | Severity | Weakness | Scheduled Completion | Status |"
    separator = "|---|---|---|---|---|---|"
    rows = [
        f"| {i.control_id} | {i.family} | {i.severity} | {i.weakness} | "
        f"{i.scheduled_completion} | {i.status} |"
        for i in items
    ]
    return "\n".join([header, separator, *rows]) + "\n"
