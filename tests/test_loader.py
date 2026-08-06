from __future__ import annotations

from compliance_scanner.controls.loader import catalog_by_id, load_catalog


def test_load_catalog_returns_bundled_controls() -> None:
    controls = load_catalog()
    assert len(controls) == 20
    assert all(c.id and c.family and c.title and c.description for c in controls)


def test_load_catalog_has_expected_families() -> None:
    controls = load_catalog()
    families = {c.family for c in controls}
    assert families == {"AC", "AU", "IA", "SC"}


def test_catalog_by_id_indexes_on_control_id() -> None:
    controls = load_catalog()
    by_id = catalog_by_id(controls)
    assert by_id["3.1.1"].family == "AC"
    assert by_id["3.5.3"].title == "Multifactor authentication"
