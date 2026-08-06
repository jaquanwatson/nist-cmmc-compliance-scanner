# NIST 800-171 Compliance Report

**Host:** vm  
**Scan window:** 2026-08-06T10:13:19.611762 -> 2026-08-06T10:13:19.616638  
**Overall compliance:** 28.6%

## Score by Family

| Family | Score | Passed | Failed | Errored | Manual Review | N/A |
|---|---|---|---|---|---|---|
| AC | 40.0% | 2 | 3 | 0 | 1 | 0 |
| AU | 0.0% | 0 | 2 | 0 | 2 | 0 |
| IA | 33.3% | 1 | 2 | 0 | 2 | 0 |
| SC | 25.0% | 1 | 3 | 0 | 1 | 0 |

## Findings

| Control | Check | Status | Summary |
|---|---|---|---|
| 3.1.1 | world_writable_sensitive_files | pass | No world-writable permissions found on sensitive files |
| 3.1.10 | session_lock_idle_action | fail | IdleAction is not set to 'lock' with a bounded IdleActionSec in logind.conf |
| 3.1.11 | shell_idle_timeout | fail | No TMOUT idle-timeout setting found in shell profile scripts |
| 3.1.5 | shadow_file_permissions | pass | /etc/shadow mode 0o640 meets the least-privilege baseline |
| 3.1.8 | account_lockout_policy | fail | No pam_faillock/pam_tally2 module found in the PAM auth stack |
| 3.13.1 | firewall_enabled | pass | nftables ruleset configured |
| 3.13.11 | fips_mode_enabled | fail | Kernel FIPS mode flag not present — FIPS-validated cryptography not confirmed |
| 3.13.16 | disk_encryption_present | fail | /etc/crypttab not found |
| 3.13.8 | ssh_cipher_strength | fail | /etc/ssh/sshd_config not found — cannot verify SSH transport encryption |
| 3.3.1 | audit_logging_enabled | fail | Neither auditd nor persistent journald logging is configured |
| 3.3.4 | audit_failure_alerting | fail | /etc/audit/auditd.conf not found — auditd is not installed/configured |
| 3.5.10 | password_hash_strength | pass | Password hashing method is SHA512 |
| 3.5.3 | mfa_pam_module_present | fail | No recognized MFA PAM module configured for local or SSH authentication |
| 3.5.7 | password_complexity | fail | No enforced password minimum length found (pwquality.conf / pam_pwquality minlen) |

## POA&M — Open Items

| Control | Family | Severity | Weakness | Scheduled Completion | Status |
|---|---|---|---|---|---|
| 3.1.10 | AC | High | Session lock: IdleAction is not set to 'lock' with a bounded IdleActionSec in logind.conf | 2026-10-05 | Open |
| 3.1.11 | AC | High | Session termination: No TMOUT idle-timeout setting found in shell profile scripts | 2026-10-05 | Open |
| 3.1.8 | AC | High | Unsuccessful logon attempts: No pam_faillock/pam_tally2 module found in the PAM auth stack | 2026-10-05 | Open |
| 3.13.11 | SC | Moderate | FIPS-validated cryptography: Kernel FIPS mode flag not present — FIPS-validated cryptography not confirmed | 2026-10-05 | Open |
| 3.13.16 | SC | Moderate | Protection of CUI at rest: /etc/crypttab not found | 2026-10-05 | Open |
| 3.13.8 | SC | Moderate | Transmission confidentiality: /etc/ssh/sshd_config not found — cannot verify SSH transport encryption | 2026-10-05 | Open |
| 3.3.1 | AU | Moderate | Audit record creation and retention: Neither auditd nor persistent journald logging is configured | 2026-10-05 | Open |
| 3.3.4 | AU | Moderate | Audit logging process failure alerts: /etc/audit/auditd.conf not found — auditd is not installed/configured | 2026-10-05 | Open |
| 3.5.3 | IA | High | Multifactor authentication: No recognized MFA PAM module configured for local or SSH authentication | 2026-10-05 | Open |
| 3.5.7 | IA | High | Password complexity: No enforced password minimum length found (pwquality.conf / pam_pwquality minlen) | 2026-10-05 | Open |
