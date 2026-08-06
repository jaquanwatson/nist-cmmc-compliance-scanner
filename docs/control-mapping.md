# Control Mapping

This is the full traceability table for the control catalog shipped in
[`src/compliance_scanner/controls/nist_800_171.yaml`](../src/compliance_scanner/controls/nist_800_171.yaml):
20 NIST SP 800-171 Rev 2 controls across four families (AC, AU, IA, SC),
each mapped to its CMMC 2.0 practice ID and, where one exists, the
automated check that evaluates it.

14 of the 20 controls have an automated check. The remaining 6 are
architectural or procedural — they depend on organizational process,
multi-system context, or design review, not a single host's config
files — and are reported by `score` as **manual review required**
rather than silently marked pass or fail. That distinction is the
point: a compliance tool that can't automate a control should say so,
not quietly drop it from the denominator.

| Control | Family | Title | CMMC Practice | Automated Check | Mechanism |
|---|---|---|---|---|---|
| 3.1.1 | AC | Authorized access control | AC.L1-3.1.1 | `world_writable_sensitive_files` | Checks `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config` for world-writable permission bits |
| 3.1.2 | AC | Transaction and function control | AC.L1-3.1.2 | _Manual review_ | Requires reviewing application-level authorization logic |
| 3.1.5 | AC | Least privilege | AC.L2-3.1.5 | `shadow_file_permissions` | Verifies `/etc/shadow` mode is no looser than `0640` |
| 3.1.8 | AC | Unsuccessful logon attempts | AC.L2-3.1.8 | `account_lockout_policy` | Checks PAM auth stack for `pam_faillock`/`pam_tally2` and its `deny` threshold |
| 3.1.10 | AC | Session lock | AC.L2-3.1.10 | `session_lock_idle_action` | Checks `logind.conf` for `IdleAction=lock` with a bounded `IdleActionSec` |
| 3.1.11 | AC | Session termination | AC.L2-3.1.11 | `shell_idle_timeout` | Checks shell profile scripts for a `TMOUT` value ≤ 900s |
| 3.3.1 | AU | Audit record creation and retention | AU.L2-3.3.1 | `audit_logging_enabled` | Checks for `auditd` config or persistent `journald` storage |
| 3.3.2 | AU | User traceability | AU.L2-3.3.2 | _Manual review_ | Requires log correlation/SIEM review, not a single-host check |
| 3.3.4 | AU | Audit logging process failure alerts | AU.L2-3.3.4 | `audit_failure_alerting` | Checks `auditd.conf` `space_left_action`/`admin_space_left_action` are not `ignore` |
| 3.3.5 | AU | Audit review, analysis, and reporting | AU.L2-3.3.5 | _Manual review_ | Requires a documented review/reporting process |
| 3.5.1 | IA | User and device identification | IA.L1-3.5.1 | _Manual review_ | Requires an identity inventory/process review |
| 3.5.2 | IA | Identity authentication | IA.L1-3.5.2 | _Manual review_ | Too broad for a single check; overlaps with 3.5.3/3.5.7/3.5.10 below |
| 3.5.3 | IA | Multifactor authentication | IA.L2-3.5.3 | `mfa_pam_module_present` | Checks PAM auth stack for a recognized MFA module (`pam_google_authenticator`, `pam_u2f`, `pam_duo`, etc.) |
| 3.5.7 | IA | Password complexity | IA.L2-3.5.7 | `password_complexity` | Checks `pwquality.conf`/`pam_pwquality` for a `minlen` ≥ 12 |
| 3.5.10 | IA | Cryptographically-protected passwords | IA.L2-3.5.10 | `password_hash_strength` | Checks `login.defs` `ENCRYPT_METHOD` is SHA-512/SHA-256/yescrypt, not a legacy algorithm |
| 3.13.1 | SC | Boundary protection | SC.L1-3.13.1 | `firewall_enabled` | Checks for an enabled `ufw`, `firewalld`, or `nftables` configuration |
| 3.13.2 | SC | Secure architecture and design | SC.L2-3.13.2 | _Manual review_ | Architecture/design review, not a runtime check |
| 3.13.8 | SC | Transmission confidentiality | SC.L2-3.13.8 | `ssh_cipher_strength` | Checks `sshd_config` `Ciphers` directive for known-weak algorithms (3DES, arcfour, CBC) |
| 3.13.11 | SC | FIPS-validated cryptography | SC.L2-3.13.11 | `fips_mode_enabled` | Checks the kernel FIPS flag at `/proc/sys/crypto/fips_enabled` |
| 3.13.16 | SC | Protection of CUI at rest | SC.L2-3.13.16 | `disk_encryption_present` | Checks `/etc/crypttab` for configured encrypted volumes |

## Why this subset

The full NIST SP 800-171 Rev 2 catalog has 110 controls; CMMC 2.0 Level 2
maps to the same 110. This project deliberately implements 20 — see the
[README](../README.md#why-a-20-control-subset-not-all-110) for the reasoning.
The four families here (AC, AU, IA, SC) were chosen because they contain
the highest concentration of controls that are genuinely host-checkable,
which keeps the automated/manual split honest instead of padding the
catalog with controls no script could ever verify.

## Extending the catalog

Adding a control is a two-step, decoupled process:

1. Add an entry to `nist_800_171.yaml` (or point `load_catalog()` at a
   different file entirely — the loader takes any path).
2. Optionally implement a `BaseCheck` subclass in `checks/` and decorate
   it with `@register` under the new control's ID.

A control with no registered check is not an error — it will simply show
up as `not_checked` in the score and as "requires manual review" in the
report, which is the correct behavior for a control this tool doesn't
(yet) know how to automate.
