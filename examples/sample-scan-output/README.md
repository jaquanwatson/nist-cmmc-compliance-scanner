# Sample scan output

Real output from running the tool against an unhardened Linux host, so
the README doesn't have to describe the output — it can just show it.

Generated with:

```
compliance-scanner report --output report.md --json report.json
compliance-scanner poam --csv poam.csv
compliance-scanner evidence --output-dir evidence
```

- `report.md` — the full markdown report (score by family, per-control
  findings, open POA&M items)
- `report.json` — the same report as machine-readable JSON
- `poam.csv` — POA&M entries for every failed control
- `evidence/` — one hashed JSON artifact per check result plus an
  `index.json` summary

This host scored 28.6% overall, which is exactly what you'd expect from
a default container image with no compliance hardening applied — the
tool isn't tuned to produce a flattering number, it reports what it
finds.
