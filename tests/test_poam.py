from __future__ import annotations

import csv

from compliance_scanner.models import CheckResult, CheckStatus, ScanResult
from compliance_scanner.poam import generate_poam, to_markdown, write_csv


def test_generate_poam_only_includes_failed_and_errored_controls(
    sample_scan, sample_controls
) -> None:
    items = generate_poam(sample_scan, controls=sample_controls)
    control_ids = {item.control_id for item in items}

    assert control_ids == {"1.1.2", "2.2.1"}


def test_generate_poam_assigns_higher_severity_to_ac_and_ia(sample_scan, sample_controls) -> None:
    items = {item.control_id: item for item in generate_poam(sample_scan, controls=sample_controls)}

    assert items["1.1.2"].severity == "High"  # AC family
    assert items["2.2.1"].severity == "Moderate"  # AU family


def test_generate_poam_deduplicates_repeated_control_failures(sample_controls) -> None:
    from datetime import datetime

    started = datetime(2026, 1, 1)
    scan = ScanResult(
        host="h",
        started_at=started,
        finished_at=started,
        results=[
            CheckResult(control_id="1.1.2", check_name="a", status=CheckStatus.FAIL, summary="x"),
            CheckResult(control_id="1.1.2", check_name="b", status=CheckStatus.FAIL, summary="y"),
        ],
    )
    items = generate_poam(scan, controls=sample_controls)
    assert len(items) == 1


def test_to_markdown_reports_clean_scan_with_no_findings() -> None:
    assert "No open POA&M items" in to_markdown([])


def test_write_csv_round_trips_poam_items(tmp_path, sample_scan, sample_controls) -> None:
    items = generate_poam(sample_scan, controls=sample_controls)
    out_path = tmp_path / "poam.csv"

    write_csv(items, out_path)

    with out_path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == len(items)
    assert {row["control_id"] for row in rows} == {item.control_id for item in items}
