from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cryptic.analytics.loader import load_analytics_config, load_records_to_duckdb
from cryptic.file_utils import PROJECT_ROOT, write_jsonl
from cryptic.mcp_server.search import search_iocs, summarize_collection_gap
from cryptic.stix_export.exporter import records_to_stix_bundle
from cryptic.yara_check.validator import validate_yara_rules

SCRATCH = PROJECT_ROOT / ".test_cti_extensions_tmp"


def reset_scratch() -> Path:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH


def test_yara_lint_checks_metadata_name_and_attack_tags():
    scratch = reset_scratch()
    rule_path = scratch / "bad_rule.yar"
    rule_path.write_text(
        """
rule ab : tool
{
    meta:
        author = "cryptic"
    strings:
        $a = "test"
    condition:
        $a
}
""",
        encoding="utf-8",
    )
    report = validate_yara_rules(rule_path, run_syntax=False)
    codes = {finding.code for finding in report.findings}
    assert not report.passed
    assert "bad_rule_name" in codes
    assert "missing_metadata" in codes
    assert "missing_attack_tag" in codes
    shutil.rmtree(scratch, ignore_errors=True)


def test_stix_export_builds_malware_indicator_and_relationship():
    records = [
        {
            "id": "ctier_001",
            "raw_text": "Lumma infrastructure observed at bad.example",
            "n_malware_or_tools": ["Lumma"],
            "n_activity": ["credential_theft"],
            "classifier_predicted_label": "credential-theft-or-infostealer",
            "indicators": [{"type": "domain", "value": "bad.example", "confidence": 80}],
        }
    ]
    bundle = records_to_stix_bundle(records)
    types = {obj["type"] for obj in bundle["objects"]}
    relationships = [obj for obj in bundle["objects"] if obj["type"] == "relationship"]
    assert bundle["type"] == "bundle"
    assert "malware" in types
    assert "indicator" in types
    assert any(rel["relationship_type"] == "indicates" for rel in relationships)


def test_mcp_search_helpers_return_bounded_results_and_gap_summary():
    scratch = reset_scratch()
    records_path = scratch / "records.jsonl"
    write_jsonl(
        records_path,
        [
            {
                "id": "r1",
                "raw_text": "RedLine logs sold in forum post",
                "n_malware_or_tools": ["RedLine"],
                "n_activity": ["credential_theft"],
                "n_data_types": ["browser credentials"],
                "n_apps": [],
                "classifier_predicted_label": "credential-theft-or-infostealer",
            },
            {
                "id": "r2",
                "raw_text": "Unclear chatter",
                "n_malware_or_tools": [],
                "n_activity": [],
                "n_data_types": [],
                "n_apps": [],
            },
        ],
    )
    results = search_iocs("redline", records_path, limit=1)
    gaps = summarize_collection_gap(records_path)
    assert results["count"] == 1
    assert results["results"][0]["id"] == "r1"
    assert gaps["summary"]["missing_malware_or_tools_count"] == 1
    shutil.rmtree(scratch, ignore_errors=True)


def test_analytics_config_resolves_project_relative_duckdb_path():
    scratch = reset_scratch()
    config_path = scratch / "analytics.json"
    config_path.write_text(
        json.dumps(
            {
                "input_glob": "data/processed/*.jsonl",
                "duckdb_path": "data/output/example.duckdb",
                "records_table": "cti_records",
            }
        ),
        encoding="utf-8",
    )
    config = load_analytics_config(config_path)
    assert Path(config["duckdb_path"]) == PROJECT_ROOT / "data" / "output" / "example.duckdb"
    shutil.rmtree(scratch, ignore_errors=True)


def test_analytics_loader_rejects_unsafe_table_names():
    with pytest.raises(ValueError, match="Invalid DuckDB table name"):
        load_records_to_duckdb(
            {
                "input_glob": "data/processed/*.jsonl",
                "duckdb_path": str(PROJECT_ROOT / "data" / "output" / "example.duckdb"),
                "records_table": "cti_records; drop table x",
            }
        )
