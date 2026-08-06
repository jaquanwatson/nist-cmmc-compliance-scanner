"""Persists raw check output as timestamped, hashed evidence artifacts.

Each check result is written as its own JSON file, plus an index that
lists every artifact and its SHA-256 hash — enough to let an assessor
verify the evidence wasn't altered after collection.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from compliance_scanner.models import CheckResult, ScanResult

DEFAULT_EVIDENCE_DIR = Path("evidence")


def collect_evidence(scan: ScanResult, output_dir: str | Path = DEFAULT_EVIDENCE_DIR) -> Path:
    """Write one evidence file per check result plus an index.json. Returns the index path."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    index_items = []
    for result in scan.results:
        record = _evidence_record(result)
        filename = f"{result.control_id}_{result.check_name}.json"
        (output_dir / filename).write_text(json.dumps(record, indent=2))
        index_items.append(
            {
                "control_id": result.control_id,
                "check_name": result.check_name,
                "status": result.status.value,
                "file": filename,
                "sha256": record["sha256"],
            }
        )

    index_path = output_dir / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "host": scan.host,
                "generated_at": datetime.utcnow().isoformat(),
                "items": index_items,
            },
            indent=2,
        )
    )
    return index_path


def _evidence_record(result: CheckResult) -> dict[str, Any]:
    payload = {
        "control_id": result.control_id,
        "check_name": result.check_name,
        "status": result.status.value,
        "summary": result.summary,
        "detail": result.detail,
        "checked_at": result.checked_at.isoformat(),
    }
    payload["sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()
    return payload
