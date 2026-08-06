"""Loads a control catalog (YAML) into Control objects."""

from __future__ import annotations

from importlib import resources
from pathlib import Path

import yaml

from compliance_scanner.models import Control

DEFAULT_CATALOG = "nist_800_171.yaml"


def load_catalog(path: str | Path | None = None) -> list[Control]:
    """Load a control catalog from a YAML file.

    If `path` is None, loads the bundled NIST 800-171 subset shipped with
    the package.
    """
    if path is None:
        raw = resources.files("compliance_scanner.controls").joinpath(DEFAULT_CATALOG).read_text()
    else:
        raw = Path(path).read_text()

    entries = yaml.safe_load(raw) or []
    return [
        Control(
            id=str(entry["id"]),
            family=entry["family"],
            title=entry["title"],
            description=entry["description"].strip(),
            source=entry.get("source", "NIST SP 800-171 Rev 2"),
            cmmc_practice=entry.get("cmmc_practice"),
        )
        for entry in entries
    ]


def catalog_by_id(controls: list[Control]) -> dict[str, Control]:
    return {c.id: c for c in controls}
