from __future__ import annotations

from compliance_scanner import scan as scan_module
from compliance_scanner.checks.base import BaseCheck
from compliance_scanner.models import CheckStatus


class _FakeCheck(BaseCheck):
    control_id = "9.9.9"
    name = "fake_check"

    def execute(self) -> tuple[CheckStatus, str, str]:
        return CheckStatus.PASS, "fake pass", ""


class _FakeFailingCheck(BaseCheck):
    control_id = "9.9.9"
    name = "fake_check"

    def execute(self) -> tuple[CheckStatus, str, str]:
        raise RuntimeError("boom")


def test_run_scan_collects_results_from_all_registered_checks(monkeypatch) -> None:
    monkeypatch.setattr(scan_module, "all_checks", lambda: [_FakeCheck()])

    result = scan_module.run_scan(host="unit-test-host")

    assert result.host == "unit-test-host"
    assert len(result.results) == 1
    assert result.results[0].status == CheckStatus.PASS
    assert result.finished_at >= result.started_at


def test_run_scan_turns_check_exceptions_into_error_results(monkeypatch) -> None:
    monkeypatch.setattr(scan_module, "all_checks", lambda: [_FakeFailingCheck()])

    result = scan_module.run_scan(host="unit-test-host")

    assert result.results[0].status == CheckStatus.ERROR
    assert "boom" in result.results[0].summary


def test_run_scan_defaults_host_to_local_hostname(monkeypatch) -> None:
    monkeypatch.setattr(scan_module, "all_checks", lambda: [])

    result = scan_module.run_scan()

    assert result.host
