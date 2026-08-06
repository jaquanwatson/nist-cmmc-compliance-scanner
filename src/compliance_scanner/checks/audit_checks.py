"""Audit and Accountability (AU) family checks."""

from __future__ import annotations

from pathlib import Path

from compliance_scanner.checks.base import BaseCheck
from compliance_scanner.checks.registry import register
from compliance_scanner.models import CheckStatus

AUDITD_CONF = Path("/etc/audit/auditd.conf")
JOURNALD_CONF = Path("/etc/systemd/journald.conf")


def _parse_ini(text: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        settings[key.strip()] = value.strip()
    return settings


@register
class AuditLoggingEnabledCheck(BaseCheck):
    control_id = "3.3.1"
    name = "audit_logging_enabled"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if AUDITD_CONF.exists():
            return (
                CheckStatus.PASS,
                f"auditd is configured ({AUDITD_CONF})",
                AUDITD_CONF.read_text(),
            )
        if JOURNALD_CONF.exists():
            settings = _parse_ini(JOURNALD_CONF.read_text())
            storage = settings.get("Storage", "").lower()
            if storage in {"persistent", "auto"}:
                return (
                    CheckStatus.PASS,
                    f"journald persistent storage configured (Storage={storage or 'auto'})",
                    JOURNALD_CONF.read_text(),
                )
        return (
            CheckStatus.FAIL,
            "Neither auditd nor persistent journald logging is configured",
            f"Checked: {AUDITD_CONF}, {JOURNALD_CONF}",
        )


@register
class AuditFailureAlertingCheck(BaseCheck):
    control_id = "3.3.4"
    name = "audit_failure_alerting"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not AUDITD_CONF.exists():
            return (
                CheckStatus.FAIL,
                f"{AUDITD_CONF} not found — auditd is not installed/configured",
                "",
            )
        text = AUDITD_CONF.read_text()
        settings = _parse_ini(text)
        space_left_action = settings.get("space_left_action", "").lower()
        admin_space_left_action = settings.get("admin_space_left_action", "").lower()

        weak_actions = {"", "ignore"}
        if space_left_action not in weak_actions and admin_space_left_action not in weak_actions:
            return (
                CheckStatus.PASS,
                f"Audit space failure actions configured "
                f"(space_left_action={space_left_action}, "
                f"admin_space_left_action={admin_space_left_action})",
                text,
            )
        return (
            CheckStatus.FAIL,
            "auditd space_left_action/admin_space_left_action is unset or 'ignore' — "
            "no alert on audit logging failure",
            text,
        )
