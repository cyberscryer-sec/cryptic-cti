from __future__ import annotations

import shutil
from pathlib import Path

from cryptic.demo.runner import FIXTURES_DIR, run_demo
from cryptic.file_utils import PROJECT_ROOT, read_jsonl
from cryptic.normalization.normalize import normalize_candidates
from cryptic.rss_ingest.adapter import ingest_feed, parse_feed_xml

SCRATCH = PROJECT_ROOT / ".test_demo_rss_tmp"


def reset_scratch() -> Path:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH


def test_rss_ingest_parses_local_rss_fixture_to_cryptic_records():
    scratch = reset_scratch()
    output_path = scratch / "rss_records.jsonl"
    feed_path = PROJECT_ROOT / "cryptic" / "rss_ingest" / "fixtures" / "demo_feed.xml"
    ingest_feed(feed_path, output_path)
    records = read_jsonl(output_path)
    assert len(records) == 2
    assert records[0]["source"] == "rss"
    assert records[0]["ingest_status"] == "ingested"
    assert "RedLine" in records[0]["raw_text"]
    assert records[1]["title"] == "中文暗网帖子出售 Lumma 日志"
    shutil.rmtree(scratch, ignore_errors=True)


def test_atom_parser_handles_local_atom_entries():
    atom = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Demo Atom</title>
  <entry>
    <title>Atom CTI lead</title>
    <link href="https://example.test/atom/1"/>
    <updated>2026-06-17T12:00:00Z</updated>
    <summary>RedLine credential logs observed.</summary>
  </entry>
</feed>
"""
    records = parse_feed_xml(atom, "atom_demo")
    assert len(records) == 1
    assert records[0]["source_url"] == "https://example.test/atom/1"
    assert "RedLine credential logs observed" in records[0]["raw_text"]


def test_multilingual_normalization_resolves_chinese_and_english_to_canonical_values():
    english = normalize_candidates(
        {
            "id": "en",
            "gliner_candidates": [
                {"text": "RedLine", "label": "malware or tool name", "score": 0.9},
                {"text": "logs for sale", "label": "credential theft activity", "score": 0.9},
                {"text": "browser cookies", "label": "credential or data type", "score": 0.9},
                {"text": "Telegram", "label": "platform or application", "score": 0.9},
            ],
        }
    )
    chinese = normalize_candidates(
        {
            "id": "zh",
            "gliner_candidates": [
                {"text": "Lumma 窃密程序", "label": "malware or tool name", "score": 0.9},
                {"text": "出售日志", "label": "credential theft activity", "score": 0.9},
                {"text": "浏览器cookie", "label": "credential or data type", "score": 0.9},
                {"text": "电报", "label": "platform or application", "score": 0.9},
            ],
        }
    )
    assert english["n_malware_or_tools"] == ["RedLine Stealer"]
    assert english["n_activity"] == ["log_sale"]
    assert chinese["n_malware_or_tools"] == ["Lumma Stealer"]
    assert chinese["n_activity"] == ["log_sale"]
    assert english["n_data_types"] == chinese["n_data_types"] == ["cookies"]
    assert english["n_apps"] == chinese["n_apps"] == ["Telegram"]


def test_cryptic_demo_writes_expected_artifacts():
    scratch = reset_scratch()
    output_dir = scratch / "demo_out"
    result_dir = run_demo("infostealer", output_dir)
    expected = {
        "normalized.jsonl",
        "classified.jsonl",
        "clusters.jsonl",
        "collection_gap.json",
        "ctier_stix_bundle.json",
        "suggested_yara_rules.yar",
        "suggested_yara_rules.json",
        "yara_validation_report.json",
        "yara_validation_report.md",
        "analyst_report.md",
    }
    assert result_dir == output_dir
    assert expected == {p.name for p in output_dir.iterdir() if p.is_file()}
    classified = read_jsonl(output_dir / "classified.jsonl")
    report = (output_dir / "analyst_report.md").read_text(encoding="utf-8")
    assert {record["language"] for record in classified} == {"en", "zh", "mixed"}
    assert "Multilingual Normalization Highlights" in report
    assert "Lumma Stealer" in report
    assert "RedLine Stealer" in report
    assert "yara_suggestions" in report
    assert (FIXTURES_DIR / "demo_infostealer_rule.yar").exists()
    shutil.rmtree(scratch, ignore_errors=True)
