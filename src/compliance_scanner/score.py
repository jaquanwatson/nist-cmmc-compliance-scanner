"""Turns a ScanResult into per-family and overall compliance scores."""

from __future__ import annotations

from collections import defaultdict

from compliance_scanner.controls.loader import load_catalog
from compliance_scanner.models import CheckStatus, Control, FamilyScore, ScanResult, ScoreReport


def score_scan(scan: ScanResult, controls: list[Control] | None = None) -> ScoreReport:
    controls = controls if controls is not None else load_catalog()
    latest_status = _latest_status_by_control(scan)

    by_family: dict[str, list[CheckStatus | None]] = defaultdict(list)
    for control in controls:
        by_family[control.family].append(latest_status.get(control.id))

    family_scores = [
        _score_family(family, statuses) for family, statuses in sorted(by_family.items())
    ]

    total_passed = sum(f.passed for f in family_scores)
    total_scored = sum(f.passed + f.failed + f.errored for f in family_scores)
    overall = round(100.0 * total_passed / total_scored, 1) if total_scored else 100.0

    return ScoreReport(overall_percent=overall, families=family_scores, scan=scan)


def _latest_status_by_control(scan: ScanResult) -> dict[str, CheckStatus]:
    latest: dict[str, CheckStatus] = {}
    for result in scan.results:
        latest[result.control_id] = result.status
    return latest


def _score_family(family: str, statuses: list[CheckStatus | None]) -> FamilyScore:
    return FamilyScore(
        family=family,
        total=len(statuses),
        passed=sum(1 for s in statuses if s == CheckStatus.PASS),
        failed=sum(1 for s in statuses if s == CheckStatus.FAIL),
        errored=sum(1 for s in statuses if s == CheckStatus.ERROR),
        not_applicable=sum(1 for s in statuses if s == CheckStatus.NOT_APPLICABLE),
        not_checked=sum(1 for s in statuses if s is None),
    )
