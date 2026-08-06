from __future__ import annotations

import json

from compliance_scanner.poam import generate_poam
from compliance_scanner.report import render_json, render_markdown
from compliance_scanner.score import score_scan


def test_render_markdown_includes_all_sections(sample_scan, sample_controls) -> None:
    score = score_scan(sample_scan, controls=sample_controls)
    poam_items = generate_poam(sample_scan, controls=sample_controls)

    markdown = render_markdown(score, poam_items)

    assert "# NIST 800-171 Compliance Report" in markdown
    assert "## Score by Family" in markdown
    assert "## Findings" in markdown
    assert "## POA&M" in markdown
    assert "1.1.2" in markdown  # a failed control should show up in findings


def test_render_json_is_valid_and_contains_overall_percent(sample_scan, sample_controls) -> None:
    score = score_scan(sample_scan, controls=sample_controls)
    poam_items = generate_poam(sample_scan, controls=sample_controls)

    payload = json.loads(render_json(score, poam_items))

    assert payload["overall_percent"] == score.overall_percent
    assert payload["host"] == sample_scan.host
    assert len(payload["families"]) == len(score.families)
    assert len(payload["poam"]) == len(poam_items)
