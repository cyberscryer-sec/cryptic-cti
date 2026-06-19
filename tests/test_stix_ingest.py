from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cryptic.file_utils import PROJECT_ROOT, read_jsonl
from cryptic.normalization.normalize import normalize_candidates
from cryptic.stix_ingest.adapter import (
    ingest_stix_bundle,
    load_stix_bundle,
    records_from_stix_bundle,
)

SCRATCH = PROJECT_ROOT / ".test_stix_ingest_tmp"


def reset_scratch() -> Path:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH


def test_stix_ingest_parses_local_bundle_to_cryptic_records():
    scratch = reset_scratch()
    fixture = PROJECT_ROOT / "cryptic" / "stix_ingest" / "fixtures" / "demo_bundle.json"
    output_path = scratch / "stix_records.jsonl"
    ingest_stix_bundle(fixture, output_path)
    records = read_jsonl(output_path)
    assert len(records) == 2
    indicator_record = next(record for record in records if record["stix_type"] == "indicator")
    assert indicator_record["source"] == "stix"
    assert indicator_record["ingest_status"] == "ingested"
    assert indicator_record["indicators"] == [
        {"type": "domain", "value": "lumma-demo.example", "confidence": 72}
    ]
    assert indicator_record["gliner_candidates"][0]["text"] == "Lumma Stealer"
    shutil.rmtree(scratch, ignore_errors=True)


def test_stix_records_can_flow_into_existing_normalization():
    fixture = PROJECT_ROOT / "cryptic" / "stix_ingest" / "fixtures" / "demo_bundle.json"
    bundle, source_name = load_stix_bundle(fixture)
    records = records_from_stix_bundle(bundle, source_name)
    indicator_record = next(record for record in records if record["stix_type"] == "indicator")
    normalized = normalize_candidates(indicator_record)
    assert normalized["n_malware_or_tools"] == ["Lumma Stealer"]
    assert normalized["meta"]["n_malware_or_tools"]["Lumma Stealer"]["best_score"] == 1.0


def test_stix_ingest_rejects_non_bundle_json():
    scratch = reset_scratch()
    bad_path = scratch / "not_bundle.json"
    bad_path.write_text('{"type": "indicator", "objects": []}', encoding="utf-8")
    with pytest.raises(ValueError, match="bundle"):
        load_stix_bundle(bad_path)
    shutil.rmtree(scratch, ignore_errors=True)
