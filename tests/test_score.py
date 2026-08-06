from __future__ import annotations

from compliance_scanner.score import score_scan


def test_score_scan_counts_each_status_per_family(sample_scan, sample_controls) -> None:
    report = score_scan(sample_scan, controls=sample_controls)
    by_family = {f.family: f for f in report.families}

    ac = by_family["AC"]
    assert (ac.total, ac.passed, ac.failed, ac.errored, ac.not_checked) == (2, 1, 1, 0, 0)

    au = by_family["AU"]
    assert (au.total, au.passed, au.failed, au.errored, au.not_checked) == (1, 0, 0, 1, 0)

    ia = by_family["IA"]
    assert (ia.total, ia.passed, ia.failed, ia.errored, ia.not_checked) == (1, 0, 0, 0, 1)


def test_family_with_no_checked_controls_scores_100_not_0(sample_scan, sample_controls) -> None:
    # A family where every control lacks an automated check should not read
    # as 0% compliant — that would be indistinguishable from "everything failed".
    report = score_scan(sample_scan, controls=sample_controls)
    ia = next(f for f in report.families if f.family == "IA")
    assert ia.percent == 100.0


def test_overall_percent_is_passed_over_scored_across_families(
    sample_scan, sample_controls
) -> None:
    report = score_scan(sample_scan, controls=sample_controls)
    # scored = AC(1 pass + 1 fail) + AU(1 errored) + IA(0, excluded) = 3; passed = 1
    assert report.overall_percent == round(100 * 1 / 3, 1)


def test_score_scan_with_no_results_is_fully_manual_review(sample_controls) -> None:
    from datetime import datetime

    from compliance_scanner.models import ScanResult

    empty_scan = ScanResult(
        host="h", started_at=datetime.now(), finished_at=datetime.now(), results=[]
    )
    report = score_scan(empty_scan, controls=sample_controls)
    assert report.overall_percent == 100.0
    assert all(f.not_checked == f.total for f in report.families)
