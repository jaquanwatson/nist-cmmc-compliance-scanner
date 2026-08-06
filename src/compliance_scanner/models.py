"""Core data model shared by every stage of the pipeline: scan -> score -> poam -> report."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True)
class Control:
    """A single control from a compliance catalog (e.g. NIST 800-171 3.1.1)."""

    id: str
    family: str
    title: str
    description: str
    source: str = "NIST SP 800-171 Rev 2"
    cmmc_practice: str | None = None


@dataclass
class CheckResult:
    """The outcome of running one check against one control."""

    control_id: str
    check_name: str
    status: CheckStatus
    summary: str
    detail: str = ""
    checked_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ScanResult:
    """The full set of check results produced by a single scan run."""

    host: str
    started_at: datetime
    finished_at: datetime
    results: list[CheckResult] = field(default_factory=list)

    def result_for(self, control_id: str) -> list[CheckResult]:
        return [r for r in self.results if r.control_id == control_id]


@dataclass
class FamilyScore:
    family: str
    total: int
    passed: int
    failed: int
    errored: int
    not_applicable: int

    @property
    def percent(self) -> float:
        scored = self.total - self.not_applicable
        if scored <= 0:
            return 100.0
        return round(100.0 * self.passed / scored, 1)


@dataclass
class ScoreReport:
    overall_percent: float
    families: list[FamilyScore]
    scan: ScanResult


@dataclass
class POAMItem:
    """A single Plan of Action & Milestones entry generated from a failed control."""

    control_id: str
    family: str
    weakness: str
    severity: str
    identified_at: datetime
    scheduled_completion: str = "TBD"
    resources_required: str = "TBD"
    milestones: str = "TBD"
    status: str = "Open"
