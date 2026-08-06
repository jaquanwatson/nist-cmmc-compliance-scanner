"""System and Communications Protection (SC) family checks."""

from __future__ import annotations

import re
from pathlib import Path

from compliance_scanner.checks.base import BaseCheck
from compliance_scanner.checks.registry import register
from compliance_scanner.models import CheckStatus

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
WEAK_SSH_CIPHERS = ("3des", "arcfour", "cbc", "des")

UFW_CONF = Path("/etc/ufw/ufw.conf")
NFTABLES_CONF = Path("/etc/nftables.conf")
FIREWALLD_STATE = Path("/etc/firewalld/firewalld.conf")

FIPS_FLAG = Path("/proc/sys/crypto/fips_enabled")

CRYPTTAB = Path("/etc/crypttab")


@register
class BoundaryProtectionCheck(BaseCheck):
    control_id = "3.13.1"
    name = "firewall_enabled"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if UFW_CONF.exists() and "ENABLED=yes" in UFW_CONF.read_text():
            return CheckStatus.PASS, "ufw firewall is enabled", UFW_CONF.read_text()
        if FIREWALLD_STATE.exists():
            return (
                CheckStatus.PASS,
                "firewalld configuration present",
                FIREWALLD_STATE.read_text(),
            )
        if NFTABLES_CONF.exists() and NFTABLES_CONF.read_text().strip():
            return (
                CheckStatus.PASS,
                "nftables ruleset configured",
                NFTABLES_CONF.read_text(),
            )
        return (
            CheckStatus.FAIL,
            "No active firewall configuration found (ufw/firewalld/nftables)",
            f"Checked: {UFW_CONF}, {FIREWALLD_STATE}, {NFTABLES_CONF}",
        )


@register
class TransmissionConfidentialityCheck(BaseCheck):
    control_id = "3.13.8"
    name = "ssh_cipher_strength"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not SSHD_CONFIG.exists():
            return (
                CheckStatus.FAIL,
                f"{SSHD_CONFIG} not found — cannot verify SSH transport encryption",
                "",
            )

        text = SSHD_CONFIG.read_text()
        match = re.search(r"^\s*Ciphers\s+(\S+)", text, re.MULTILINE)
        if not match:
            return (
                CheckStatus.PASS,
                "No explicit Ciphers directive — relying on OpenSSH's modern default cipher set",
                text,
            )

        ciphers = match.group(1).lower().split(",")
        weak = [c for c in ciphers if any(bad in c for bad in WEAK_SSH_CIPHERS)]
        if weak:
            return (
                CheckStatus.FAIL,
                f"Weak SSH cipher(s) explicitly enabled: {', '.join(weak)}",
                text,
            )
        return CheckStatus.PASS, "Configured SSH ciphers exclude known-weak algorithms", text


@register
class FipsCryptographyCheck(BaseCheck):
    control_id = "3.13.11"
    name = "fips_mode_enabled"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not FIPS_FLAG.exists():
            return (
                CheckStatus.FAIL,
                "Kernel FIPS mode flag not present — FIPS-validated cryptography not confirmed",
                "",
            )
        value = FIPS_FLAG.read_text().strip()
        if value == "1":
            return CheckStatus.PASS, "Kernel FIPS mode is enabled", value
        return CheckStatus.FAIL, "Kernel FIPS mode is disabled", value


@register
class DataAtRestEncryptionCheck(BaseCheck):
    control_id = "3.13.16"
    name = "disk_encryption_present"

    def execute(self) -> tuple[CheckStatus, str, str]:
        if not CRYPTTAB.exists():
            return CheckStatus.FAIL, f"{CRYPTTAB} not found", ""

        entries = [
            line
            for line in CRYPTTAB.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if entries:
            return (
                CheckStatus.PASS,
                f"{len(entries)} encrypted volume(s) configured in crypttab",
                "\n".join(entries),
            )
        return CheckStatus.FAIL, "crypttab exists but defines no encrypted volumes", ""
