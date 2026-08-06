"""Maps control IDs to the check implementations that can evaluate them.

Not every control in the catalog has an automated check — plenty of
NIST 800-171 requirements (policy, training, physical security) can't be
verified by inspecting a single host. Controls with no registered check
are reported by the scorer as requiring manual review, not silently
passed.
"""

from __future__ import annotations

from collections import defaultdict

from compliance_scanner.checks.base import BaseCheck

_REGISTRY: dict[str, list[type[BaseCheck]]] = defaultdict(list)
_DISCOVERED = False


def register(check_cls: type[BaseCheck]) -> type[BaseCheck]:
    """Class decorator: register a check under its control_id."""
    _REGISTRY[check_cls.control_id].append(check_cls)
    return check_cls


def _discover() -> None:
    global _DISCOVERED
    if _DISCOVERED:
        return
    # Importing these modules triggers their @register decorators.
    from compliance_scanner.checks import os_checks  # noqa: F401

    _DISCOVERED = True


def checks_for(control_id: str) -> list[BaseCheck]:
    _discover()
    return [cls() for cls in _REGISTRY.get(control_id, [])]


def all_checks() -> list[BaseCheck]:
    _discover()
    return [cls() for classes in _REGISTRY.values() for cls in classes]


def covered_control_ids() -> set[str]:
    _discover()
    return set(_REGISTRY.keys())
