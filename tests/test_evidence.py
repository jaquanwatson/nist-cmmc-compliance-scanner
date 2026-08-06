from __future__ import annotations

import hashlib
import json

from compliance_scanner.evidence import collect_evidence


def test_collect_evidence_writes_one_file_per_result_plus_index(tmp_path, sample_scan) -> None:
    out_dir = tmp_path / "evidence"

    index_path = collect_evidence(sample_scan, out_dir)

    assert index_path == out_dir / "index.json"
    index = json.loads(index_path.read_text())
    assert index["host"] == sample_scan.host
    assert len(index["items"]) == len(sample_scan.results)

    for item in index["items"]:
        artifact_path = out_dir / item["file"]
        assert artifact_path.exists()


def test_evidence_sha256_matches_recomputed_hash(tmp_path, sample_scan) -> None:
    out_dir = tmp_path / "evidence"
    collect_evidence(sample_scan, out_dir)

    result = sample_scan.results[0]
    filename = f"{result.control_id}_{result.check_name}.json"
    record = json.loads((out_dir / filename).read_text())

    claimed_hash = record.pop("sha256")
    recomputed = hashlib.sha256(json.dumps(record, sort_keys=True).encode("utf-8")).hexdigest()
    assert claimed_hash == recomputed
