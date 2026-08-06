"""Base class every check implementation extends.

Checks are read-only: they inspect local configuration files and system
state and report what they find. They never modify anything.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from compliance_scanner.models import CheckResult, CheckStatus


class BaseCheck(ABC):
    control_id: ClassVar[str]
    name: ClassVar[str]

    @abstractmethod
    def execute(self) -> tuple[CheckStatus, str, str]:
        """Run the check and return (status, one-line summary, detail text)."""

    def run(self) -> CheckResult:
        try:
            status, summary, detail = self.execute()
        except Exception as exc:  # noqa: BLE001 - a failed check must not crash the scan
            status = CheckStatus.ERROR
            summary = f"Check raised an exception: {exc}"
            detail = ""
        return CheckResult(
            control_id=self.control_id,
            check_name=self.name,
            status=status,
            summary=summary,
            detail=detail,
        )
