"""Orchestrates a full scan: runs every registered check and captures the results."""

from __future__ import annotations

import socket
from datetime import datetime

from compliance_scanner.checks.registry import all_checks
from compliance_scanner.models import ScanResult


def run_scan(host: str | None = None) -> ScanResult:
    started_at = datetime.utcnow()
    results = [check.run() for check in all_checks()]
    finished_at = datetime.utcnow()

    return ScanResult(
        host=host or socket.gethostname(),
        started_at=started_at,
        finished_at=finished_at,
        results=results,
    )
