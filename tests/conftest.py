from __future__ import annotations

from datetime import datetime

import pytest

from compliance_scanner.models import CheckResult, CheckStatus, Control, ScanResult

SAMPLE_CONTROLS = [
    Control(id="1.1.1", family="AC", title="Sample AC control", description="desc"),
    Control(id="1.1.2", family="AC", title="Sample AC control 2", description="desc"),
    Control(id="2.2.1", family="AU", title="Sample AU control", description="desc"),
    Control(id="3.3.1", family="IA", title="Sample IA control", description="desc"),
]


@pytest.fixture
def sample_controls() -> list[Control]:
    return list(SAMPLE_CONTROLS)


@pytest.fixture
def sample_scan() -> ScanResult:
    """One PASS, one FAIL, one ERROR, and one control with no result at all."""
    started = datetime(2026, 1, 1, 12, 0, 0)
    results = [
        CheckResult(
            control_id="1.1.1",
            check_name="check_a",
            status=CheckStatus.PASS,
            summary="all good",
            checked_at=started,
        ),
        CheckResult(
            control_id="1.1.2",
            check_name="check_b",
            status=CheckStatus.FAIL,
            summary="not configured",
            detail="raw output",
            checked_at=started,
        ),
        CheckResult(
            control_id="2.2.1",
            check_name="check_c",
            status=CheckStatus.ERROR,
            summary="check raised an exception",
            checked_at=started,
        ),
        # 3.3.1 intentionally has no CheckResult: no automated check registered.
    ]
    return ScanResult(host="test-host", started_at=started, finished_at=started, results=results)
