"""Identification and Authentication (IA) family checks."""

from __future__ import annotations

import re
from pathlib import Path

from compliance_scanner.checks.base import BaseCheck
from compliance_scanner.checks.registry import register
from compliance_scanner.models import CheckStatus

PWQUALITY_CONF = Path("/etc/security/pwquality.conf")
PAM_PASSWORD_FILES = [
    Path("/etc/pam.d/common-password"),
    Path("/etc/pam.d/system-auth"),
]
LOGIN_DEFS = Path("/etc/login.defs")
STRONG_HASH_METHODS = {"SHA512", "SHA256", "YESCRYPT"}

PAM_MFA_MODULES = (
    "pam_google_authenticator.so",
    "pam_oath.so",
    "pam_u2f.so",
    "pam_pkcs11.so",
    "pam_duo.so",
)
PAM_AUTH_FILES = [
    Path("/etc/pam.d/common-auth"),
    Path("/etc/pam.d/system-auth"),
    Path("/etc/pam.d/sshd"),
]


@register
class PasswordComplexityCheck(BaseCheck):
    control_id = "3.5.7"
    name = "password_complexity"
    min_length_required = 12

    def execute(self) -> tuple[CheckStatus, str, str]:
        minlen = self._minlen_from_pwquality()
        if minlen is None:
            minlen = self._minlen_from_pam()

        if minlen is None:
            return (
                CheckStatus.FAIL,
                "No enforced password minimum length found "
                "(pwquality.conf / pam_pwquality minlen)",
                f"Checked: {PWQUALITY_CONF}, {', '.join(str(p) for p in PAM_PASSWORD_FILES)}",
            )
        if minlen >= self.min_length_required:
            return CheckStatus.PASS, f"Password minimum length enforced: {minlen} characters", ""
        return (
            CheckStatus.FAIL,
            f"Password minimum length is {minlen}, below the "
            f"{self.min_length_required}-character baseline",
            "",
        )

    def _minlen_from_pwquality(self) -> int | None:
        if not PWQUALITY_CONF.exists():
            return None
        for line in PWQUALITY_CONF.read_text().splitlines():
            match = re.search(r"^\s*minlen\s*=\s*(\d+)", line)
            if match:
                return int(match.group(1))
        return None

    def _minlen_from_pam(self) -> int | None:
        for pam_file in PAM_PASSWORD_FILES:
            if not pam_file.exists():
                continue
            text = pam_file.read_text()
            match = re.search(r"pam_pwquality\.so.*?minlen=(\d+)", text)
            if match:
                return int(match.group(1))
        return None


@register
class PasswordStorageCheck(BaseCheck):
    control_id = "3.5.10"
    name = "password_hash_strength"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not LOGIN_DEFS.exists():
            return CheckStatus.FAIL, f"{LOGIN_DEFS} not found", ""

        text = LOGIN_DEFS.read_text()
        match = re.search(r"^\s*ENCRYPT_METHOD\s+(\S+)", text, re.MULTILINE)
        if not match:
            return (
                CheckStatus.FAIL,
                "No ENCRYPT_METHOD set in login.defs — password hashing algorithm is unconfirmed",
                text,
            )

        method = match.group(1).upper()
        if method in STRONG_HASH_METHODS:
            return CheckStatus.PASS, f"Password hashing method is {method}", text
        return (
            CheckStatus.FAIL,
            f"Password hashing method is {method}, a weak/legacy algorithm",
            text,
        )


@register
class MultifactorAuthenticationCheck(BaseCheck):
    control_id = "3.5.3"
    name = "mfa_pam_module_present"

    def execute(self) -> tuple[CheckStatus, str, str]:
        for pam_file in PAM_AUTH_FILES:
            if not pam_file.exists():
                continue
            text = pam_file.read_text()
            found = [module for module in PAM_MFA_MODULES if module in text]
            if found:
                return (
                    CheckStatus.PASS,
                    f"MFA PAM module(s) found in {pam_file}: {', '.join(found)}",
                    text,
                )
        return (
            CheckStatus.FAIL,
            "No recognized MFA PAM module configured for local or SSH authentication",
            f"Checked: {', '.join(str(p) for p in PAM_AUTH_FILES)}",
        )
