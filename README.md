# NIST 800-171 / CMMC 2.0 Compliance Scanner

[![CI](https://github.com/jaquanwatson/nist-cmmc-compliance-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/jaquanwatson/nist-cmmc-compliance-scanner/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](pyproject.toml)

A CLI tool that scans a host's actual configuration against a NIST SP
800-171 / CMMC 2.0 control catalog, scores compliance per control family,
generates POA&M entries for what's failing, collects hashed evidence, and
writes an assessor-readable report — end to end, from one command.

```
$ compliance-scanner report --output report.md
Wrote report to report.md

Overall compliance: 28.6%
```

This README is written as a case study: the problem, why this framework,
how the mapping works, and what real output looks like — not just an API
reference. If you want that instead, jump to [Usage](#usage) or
[`docs/control-mapping.md`](docs/control-mapping.md).

---

## The problem

Every company in the U.S. defense industrial base — an estimated
200,000+ contractors and subcontractors — is being required to prove
compliance with NIST SP 800-171 as CMMC 2.0 rolls out as a contractual
requirement. In practice, "proving compliance" today usually means one
of two things:

1. **A consultant runs a spreadsheet-driven manual assessment.** Someone
   walks through 110 controls, interviews admins, eyeballs configs, and
   fills in a spreadsheet. It's slow, it's expensive, and the moment
   someone changes a config the following Tuesday, the assessment is
   stale.
2. **Nothing gets checked until an audit forces the issue.** Compliance
   becomes a fire drill instead of an operating discipline.

Neither scales, and neither produces the artifact an assessor actually
wants: evidence that a specific control was checked, on a specific date,
with a specific result — tied to a documented remediation plan for
anything that failed.

This tool automates the piece of that workflow that *can* be automated:
pulling real configuration state, scoring it against the control
catalog, and generating the POA&M and evidence artifacts a C3PAO
assessor or an internal audit would ask for. It does not replace a human
assessor — a third of the controls in scope here are flagged as
requiring manual review, on purpose (see [below](#the-honest-part-not-everything-is-automatable)) — but it
replaces the manual, error-prone parts of getting to that assessment.

## Why NIST 800-171 / CMMC 2.0 specifically

Two reasons, one practical and one personal:

- **It's the framework with a hard deadline attached.** CMMC 2.0 is
  being written into DoD contracts as a pass/fail gate, not a
  best-practice suggestion. That makes automatable, evidence-backed
  compliance tooling a real operational need for defense contractors and
  the MSPs supporting them — not a hypothetical.
- **It's the framework I work in.** I've been hands-on with NIST 800-171
  and CMMC environments as a Professional Services Engineer at an MSP,
  and my current research is on quantifying the ROI of compliance
  automation versus manual GRC operations. This project is that research
  made concrete — a working implementation of the thing the theory is
  about.

## How it works

```
control catalog (YAML)          check registry            pipeline
┌────────────────────┐    ┌──────────────────────┐    scan ──▶ score ──▶ poam
│ 20 NIST 800-171     │───▶│ control_id -> Check   │              │        │
│ controls, mapped to │    │ classes (@register)   │              ▼        ▼
│ CMMC 2.0 practice   │    │                       │          evidence   report
│ IDs                 │    │ 14 controls have a    │        (hashed    (markdown
└────────────────────┘    │ check; 6 are flagged   │         JSON)     + JSON)
                           │ "manual review"        │
                           └──────────────────────┘
```

**The control catalog is data, not code.** `controls/nist_800_171.yaml`
holds the 20 controls this tool covers — ID, family, title, description,
CMMC practice mapping — completely decoupled from the Python that
evaluates them. Swap in a different catalog file and `load_catalog()`
picks it up with no code changes. This mirrors how real organizations
maintain control catalogs (as governed reference data) separately from
the tooling that implements checks against them.

**Checks are a registry, not a big if/elif block.** Each `BaseCheck`
subclass declares the `control_id` it evaluates and registers itself via
a `@register` decorator. `scan.py` doesn't know or care what a check
does internally — it just runs every registered check and collects the
result. Adding a new check for an existing or new control is a one-file,
no-touch-anything-else change.

**Every check is read-only.** They inspect local configuration —
`/etc/pam.d/*`, `/etc/ssh/sshd_config`, `/etc/security/pwquality.conf`,
`/etc/systemd/logind.conf`, file permission bits — and report what they
find. Nothing is modified, nothing leaves the host, nothing requires
elevated exploitation-style probing.

**The pipeline is five composable stages**, each independently testable
and independently usable from the CLI:

| Stage | What it does |
|---|---|
| `scan` | Runs every registered check, returns raw pass/fail/error results |
| `score` | Aggregates results into per-family and overall compliance percentages |
| `poam` | Converts failed/errored controls into POA&M entries (control, weakness, severity, remediation window) |
| `evidence` | Writes a SHA-256-hashed JSON artifact per check result, plus an index |
| `report` | Combines all of the above into a markdown or JSON report |

### The honest part: not everything is automatable

Of the 20 controls in the catalog, **14 have an automated check; 6 are
explicitly marked as requiring manual review** — things like "employ
architectural designs that promote effective information security"
(3.13.2) or "correlate audit record review and reporting processes"
(3.3.5) that depend on organizational process or multi-system context, not
a single host's config files.

The scorer treats these as a distinct category (`not_checked`), separate
from `not_applicable`. A control with no automated check is **excluded
from the score's denominator**, not silently counted as a pass — a tool
that quietly drops unautomatable controls from the math would produce a
compliance percentage that means nothing. See
[`docs/control-mapping.md`](docs/control-mapping.md) for the full
traceability table and the reasoning behind every automated/manual
split.

## Sample output

Real output from running `compliance-scanner scan` against an
unhardened container — the full artifacts (`report.md`, `report.json`,
`poam.csv`, and the evidence directory) are committed at
[`examples/sample-scan-output/`](examples/sample-scan-output/).

```
                               Scan results — vm
┏━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Control ┃ Check                       ┃ Status ┃ Summary                     ┃
┡━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 3.1.1   │ world_writable_sensitive_f… │ pass   │ No world-writable           │
│         │                             │        │ permissions found on        │
│         │                             │        │ sensitive files             │
│ 3.1.8   │ account_lockout_policy      │ fail   │ No pam_faillock/pam_tally2  │
│         │                             │        │ module found in the PAM     │
│         │                             │        │ auth stack                  │
│ 3.5.10  │ password_hash_strength      │ pass   │ Password hashing method is  │
│         │                             │        │ SHA512                      │
│ 3.5.3   │ mfa_pam_module_present      │ fail   │ No recognized MFA PAM       │
│         │                             │        │ module configured...        │
└─────────┴─────────────────────────────┴────────┴─────────────────────────────┘
```

```
$ compliance-scanner score

                  Compliance score by family
┏━━━━━━━━┳━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━┓
┃ Family ┃ Score ┃ Passed ┃ Failed ┃ Errored ┃ Manual review ┃
┡━━━━━━━━╇━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━┩
│ AC     │ 40.0% │ 2      │ 3      │ 0       │ 1             │
│ AU     │ 0.0%  │ 0      │ 2      │ 0       │ 2             │
│ IA     │ 33.3% │ 1      │ 2      │ 0       │ 2             │
│ SC     │ 25.0% │ 1      │ 3      │ 0       │ 1             │
└────────┴───────┴────────┴────────┴─────────┴───────────────┘

Overall compliance: 28.6%
```

The resulting POA&M (excerpt — full table in
[`examples/sample-scan-output/poam.csv`](examples/sample-scan-output/poam.csv)):

| Control | Family | Severity | Weakness | Scheduled Completion | Status |
|---|---|---|---|---|---|
| 3.1.8 | AC | High | Unsuccessful logon attempts: No pam_faillock/pam_tally2 module found in the PAM auth stack | 2026-10-05 | Open |
| 3.5.3 | IA | High | Multifactor authentication: No recognized MFA PAM module configured | 2026-10-05 | Open |

Each finding also has a corresponding evidence artifact, e.g.
[`3.5.10_password_hash_strength.json`](examples/sample-scan-output/evidence/3.5.10_password_hash_strength.json):

```json
{
  "control_id": "3.5.10",
  "check_name": "password_hash_strength",
  "status": "pass",
  "summary": "Password hashing method is SHA512",
  "detail": "",
  "checked_at": "2026-08-06T10:13:19.964492",
  "sha256": "…"
}
```

That 28.6% isn't a demo number picked to look good — it's what a
default, un-hardened Linux container actually scores. The tool reports
what it finds.

## Usage

### Install

```bash
git clone https://github.com/jaquanwatson/nist-cmmc-compliance-scanner.git
cd nist-cmmc-compliance-scanner
pip install -e ".[dev]"
```

### Run

```bash
compliance-scanner scan                                   # run checks, print results
compliance-scanner score                                  # print compliance scores
compliance-scanner poam --csv poam.csv                     # generate POA&M
compliance-scanner evidence --output-dir evidence          # collect hashed evidence
compliance-scanner report --output report.md --json report.json --with-evidence
```

Run `compliance-scanner --help` or `compliance-scanner <command> --help`
for full option lists.

### Test

```bash
pytest            # 21 tests, deterministic (no live-system dependency)
ruff check .       # lint
mypy src/          # type check
```

## Project structure

```
src/compliance_scanner/
├── cli.py                    # Typer CLI: scan, score, poam, evidence, report
├── models.py                 # Control, CheckResult, ScanResult, FamilyScore, POAMItem
├── controls/
│   ├── nist_800_171.yaml     # control catalog (data, not code)
│   └── loader.py
├── checks/
│   ├── base.py                # BaseCheck contract
│   ├── registry.py            # control_id -> check class mapping
│   ├── os_checks.py           # AC: lockout, session lock, session timeout
│   ├── audit_checks.py        # AU: audit logging, failure alerting
│   ├── auth_checks.py         # IA: password complexity/hashing, MFA
│   ├── network_checks.py      # SC: firewall, SSH ciphers, FIPS, disk encryption
│   └── filesystem_checks.py   # file permission checks (feeds AC family)
├── scan.py / score.py / poam.py / evidence.py / report.py
tests/                         # 21 tests, mocked/fixture-based
docs/control-mapping.md        # full control -> check traceability table
examples/sample-scan-output/   # committed real output
```

## Why a 20-control subset, not all 110

NIST SP 800-171 Rev 2 has 110 controls; CMMC 2.0 Level 2 maps to the same
110. Implementing all 110 as automated checks is a multi-month effort for
a team, not a weekend portfolio project, and a lot of them (physical
security, personnel screening, incident response planning) can't be
verified by inspecting a host's config at all.

This project implements 20 controls across four families (AC, AU, IA,
SC) — chosen because they contain the highest concentration of controls
that are genuinely host-checkable — with 14 of them wired to real
checks. That's a smaller, honest claim: *this tool automates a
meaningful, verifiable slice of NIST 800-171*, not *this tool does
compliance for you*. See [`docs/control-mapping.md`](docs/control-mapping.md)
for the reasoning behind every included and excluded control.

## Roadmap (explicitly out of scope for v0.1)

- Cloud/API-based checks (AWS Config, Azure Policy, M365 security
  baselines) instead of local-host-only checks
- Full 110-control NIST 800-171 / CMMC Level 2 coverage
- Multi-host / fleet scanning with a central results store
- A web UI on top of the existing JSON output

## License

[MIT](LICENSE)
