"""Access Control (AC) family checks: local account and session controls.

Every check here reads local configuration files only. Nothing is
modified, and nothing leaves the host.
"""

from __future__ import annotations

import re
from pathlib import Path

from compliance_scanner.checks.base import BaseCheck
from compliance_scanner.checks.registry import register
from compliance_scanner.models import CheckStatus

PAM_AUTH_FILES = [
    Path("/etc/pam.d/common-auth"),
    Path("/etc/pam.d/system-auth"),
    Path("/etc/pam.d/password-auth"),
]
FAILLOCK_CONF = Path("/etc/security/faillock.conf")
LOGIND_CONF = Path("/etc/systemd/logind.conf")
PROFILE_D = Path("/etc/profile.d")
SHELL_PROFILES = [Path("/etc/profile")]


@register
class AccountLockoutCheck(BaseCheck):
    control_id = "3.1.8"
    name = "account_lockout_policy"

    def execute(self) -> tuple[CheckStatus, str, str]:
        for pam_file in PAM_AUTH_FILES:
            if not pam_file.exists():
                continue
            text = pam_file.read_text()
            if "pam_faillock.so" in text or "pam_tally2.so" in text:
                deny = self._deny_threshold()
                if deny is not None:
                    return (
                        CheckStatus.PASS,
                        f"Account lockout enforced via {pam_file.name} (deny={deny})",
                        text,
                    )
                return (
                    CheckStatus.PASS,
                    f"Lockout module active in {pam_file.name}, but no explicit deny "
                    "threshold found",
                    text,
                )
        searched = ", ".join(str(p) for p in PAM_AUTH_FILES)
        return (
            CheckStatus.FAIL,
            "No pam_faillock/pam_tally2 module found in the PAM auth stack",
            f"Searched: {searched}",
        )

    def _deny_threshold(self) -> int | None:
        if not FAILLOCK_CONF.exists():
            return None
        for line in FAILLOCK_CONF.read_text().splitlines():
            match = re.search(r"^\s*deny\s*=\s*(\d+)", line)
            if match:
                return int(match.group(1))
        return None


@register
class SessionLockCheck(BaseCheck):
    control_id = "3.1.10"
    name = "session_lock_idle_action"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not LOGIND_CONF.exists():
            return CheckStatus.FAIL, f"{LOGIND_CONF} not found", ""

        text = LOGIND_CONF.read_text()
        settings = self._parse_ini(text)
        idle_action = settings.get("IdleAction", "").lower()
        idle_sec = settings.get("IdleActionSec")

        if idle_action == "lock" and idle_sec:
            return (
                CheckStatus.PASS,
                f"Idle session lock configured (IdleAction=lock, IdleActionSec={idle_sec})",
                text,
            )
        return (
            CheckStatus.FAIL,
            "IdleAction is not set to 'lock' with a bounded IdleActionSec in logind.conf",
            text,
        )

    @staticmethod
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
class SessionTerminationCheck(BaseCheck):
    control_id = "3.1.11"
    name = "shell_idle_timeout"
    max_recommended_seconds = 900

    def execute(self) -> tuple[CheckStatus, str, str]:
        candidates = list(SHELL_PROFILES)
        if PROFILE_D.is_dir():
            candidates.extend(sorted(PROFILE_D.glob("*.sh")))

        for path in candidates:
            if not path.exists():
                continue
            text = path.read_text()
            match = re.search(r"^\s*(?:export\s+)?TMOUT\s*=\s*(\d+)", text, re.MULTILINE)
            if not match:
                continue
            timeout = int(match.group(1))
            if 0 < timeout <= self.max_recommended_seconds:
                return CheckStatus.PASS, f"TMOUT={timeout}s set in {path}", text
            return (
                CheckStatus.FAIL,
                f"TMOUT={timeout}s in {path} exceeds the "
                f"{self.max_recommended_seconds}s recommended max",
                text,
            )

        searched = ", ".join(str(p) for p in candidates)
        return (
            CheckStatus.FAIL,
            "No TMOUT idle-timeout setting found in shell profile scripts",
            f"Searched: {searched}",
        )
