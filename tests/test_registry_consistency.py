"""Guards against drift between the check registry and the control catalog."""

from __future__ import annotations

from compliance_scanner.checks.registry import covered_control_ids
from compliance_scanner.controls.loader import load_catalog


def test_every_registered_check_maps_to_a_cataloged_control() -> None:
    catalog_ids = {c.id for c in load_catalog()}
    covered_ids = covered_control_ids()
    orphaned = covered_ids - catalog_ids
    assert not orphaned, f"Checks registered for control IDs not in the catalog: {orphaned}"


def test_at_least_half_the_catalog_has_an_automated_check() -> None:
    catalog_ids = {c.id for c in load_catalog()}
    covered_ids = covered_control_ids()
    assert len(covered_ids) >= len(catalog_ids) // 2
