"""File permission checks on sensitive local paths.

These map back into the Access Control (AC) family: an authorization
policy is only as good as the file permissions enforcing it.
"""

from __future__ import annotations

import stat
from pathlib import Path

from compliance_scanner.checks.base import BaseCheck
from compliance_scanner.checks.registry import register
from compliance_scanner.models import CheckStatus

SHADOW_FILE = Path("/etc/shadow")
SHADOW_MAX_MODE = 0o640

SENSITIVE_PATHS = [
    Path("/etc/passwd"),
    Path("/etc/shadow"),
    Path("/etc/sudoers"),
    Path("/etc/ssh/sshd_config"),
]


@register
class ShadowFilePermissionsCheck(BaseCheck):
    control_id = "3.1.5"
    name = "shadow_file_permissions"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not SHADOW_FILE.exists():
            return CheckStatus.FAIL, f"{SHADOW_FILE} not found", ""

        mode = stat.S_IMODE(SHADOW_FILE.stat().st_mode)
        if mode & ~SHADOW_MAX_MODE:
            return (
                CheckStatus.FAIL,
                f"{SHADOW_FILE} mode {oct(mode)} is looser than the "
                f"{oct(SHADOW_MAX_MODE)} baseline",
                f"mode={oct(mode)}",
            )
        return (
            CheckStatus.PASS,
            f"{SHADOW_FILE} mode {oct(mode)} meets the least-privilege baseline",
            "",
        )


@register
class WorldWritableSensitiveFilesCheck(BaseCheck):
    control_id = "3.1.1"
    name = "world_writable_sensitive_files"

    def execute(self) -> tuple[CheckStatus, str, str]:
        offenders = []
        checked = []
        for path in SENSITIVE_PATHS:
            if not path.exists():
                continue
            mode = stat.S_IMODE(path.stat().st_mode)
            checked.append(f"{path}={oct(mode)}")
            if mode & stat.S_IWOTH:
                offenders.append(str(path))

        if offenders:
            return (
                CheckStatus.FAIL,
                f"World-writable sensitive file(s): {', '.join(offenders)}",
                "; ".join(checked),
            )
        return (
            CheckStatus.PASS,
            "No world-writable permissions found on sensitive files",
            "; ".join(checked),
        )
