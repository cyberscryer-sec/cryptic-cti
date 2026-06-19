from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptic.extraction.regex_utils import extract_indicators, merge_indicator_lists
from cryptic.file_utils import OUTPUT_DIR, utc_now_iso, write_jsonl
from cryptic.mcp_server.search import summarize_collection_gap
from cryptic.normalization.normalize import normalize_candidates
from cryptic.stix_export.exporter import records_to_stix_bundle
from cryptic.yara_check.validator import validate_yara_rules, write_reports

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
DEFAULT_SAMPLE = FIXTURES_DIR / "infostealer_candidates.json"
DEFAULT_YARA_RULE = FIXTURES_DIR / "demo_infostealer_rule.yar"


def load_demo_candidates(sample: str = "infostealer") -> list[dict[str, Any]]:
    if sample != "infostealer":
        raise ValueError("Only the 'infostealer' demo sample is currently bundled")
    with DEFAULT_SAMPLE.open("r", encoding="utf-8") as f:
        return json.load(f)


def apply_demo_classification(record: dict[str, Any]) -> dict[str, Any]:
    out = dict(record)
    out["classifier_predicted_label"] = record.get("demo_label", "credential-theft-or-infostealer")
    out["classification_status"] = "demo_labelled"
    out["classifier_model"] = "deterministic_demo_fixture"
    out["embedding_model"] = "not_used_in_demo"
    return out


def add_demo_regex_indicators(record: dict[str, Any]) -> dict[str, Any]:
    out = dict(record)
    out["indicators"] = merge_indicator_lists(
        record.get("indicators", []),
        extract_indicators(str(record.get("raw_text", ""))),
    )
    return out


def build_demo_clusters(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    malware = []
    activities = []
    data_types = []
    platforms = []
    raw_texts = []
    indicators = []
    record_ids = []
    languages = []
    for record in records:
        record_ids.append(record.get("id", ""))
        languages.append(record.get("language", "unknown"))
        raw_texts.append(record.get("raw_text", ""))
        malware.extend(record.get("n_malware_or_tools", []))
        activities.extend(record.get("n_activity", []))
        data_types.extend(record.get("n_data_types", []))
        platforms.extend(record.get("n_apps", []))
        indicators.extend(record.get("indicators", []))
    def dedupe(values: list[Any]) -> list[Any]:
        return list(dict.fromkeys(v for v in values if v))

    return [
        {
            "id": "demo_cluster_infostealer_logs",
            "record_ids": dedupe(record_ids),
            "source": "demo_fixture",
            "languages": dedupe(languages),
            "representative_text": raw_texts[0] if raw_texts else "",
            "raw_texts": dedupe(raw_texts),
            "malware_or_tools": dedupe(malware),
            "activities": dedupe(activities),
            "credential_data_types": dedupe(data_types),
            "platforms": dedupe(platforms),
            "indicators": indicators,
            "confidence": 70,
            "notes": [
                "Demo cluster joining English, Chinese, and mixed-language infostealer leads."
            ],
        }
    ]


def write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path


def render_analyst_report(
    classified_records: list[dict[str, Any]],
    gap_summary: dict[str, Any],
    artifact_paths: dict[str, Path],
) -> str:
    malware = sorted(
        {v for record in classified_records for v in record.get("n_malware_or_tools", [])}
    )
    activities = sorted(
        {v for record in classified_records for v in record.get("n_activity", [])}
    )
    indicators = sorted(
        {
            f"{indicator.get('type')}:{indicator.get('value')}"
            for record in classified_records
            for indicator in record.get("indicators", [])
            if isinstance(indicator, dict) and indicator.get("type") and indicator.get("value")
        }
    )
    lines = [
        "# Cryptic CTI Demo Analyst Report",
        "",
        "## Executive Summary",
        (
            f"Processed {len(classified_records)} multilingual infostealer leads into "
            f"{len(malware)} malware/tool values, {len(activities)} normalized activities, "
            f"and {len(indicators)} technical indicators."
        ),
        "",
        "## Multilingual Normalization Highlights",
        "| Record | Language | Raw lead excerpt | Malware/tools | Activities | Data types | Apps |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for record in classified_records:
        excerpt = str(record.get("raw_text", "")).replace("|", "/")[:120]
        lines.append(
            "| {id} | {lang} | {excerpt} | {malware} | {activity} | {data} | {apps} |".format(
                id=record.get("id", ""),
                lang=record.get("language", ""),
                excerpt=excerpt,
                malware=", ".join(record.get("n_malware_or_tools", [])),
                activity=", ".join(record.get("n_activity", [])),
                data=", ".join(record.get("n_data_types", [])),
                apps=", ".join(record.get("n_apps", [])),
            )
        )
    lines.extend(["", "## Extracted Technical Indicators"])
    for indicator in indicators:
        lines.append(f"- {indicator}")
    lines.extend(
        [
            "",
            "## Collection Gap Summary",
            "- Missing malware/tool values: "
            f"{gap_summary['summary']['missing_malware_or_tools_count']}",
            f"- Missing activity values: {gap_summary['summary']['missing_activity_count']}",
            f"- Missing data type values: {gap_summary['summary']['missing_data_types_count']}",
            f"- Missing app/platform values: {gap_summary['summary']['missing_apps_count']}",
            "",
            "## Generated Artifacts",
        ]
    )
    for name, path in artifact_paths.items():
        lines.append(f"- {name}: `{path}`")
    return "\n".join(lines) + "\n"


def run_demo(sample: str = "infostealer", output_root: str | Path | None = None) -> Path:
    run_id = utc_now_iso().replace(":", "").replace("+", "_").replace(".", "_")
    out_dir = Path(output_root) if output_root else OUTPUT_DIR / "demo" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    raw_records = [add_demo_regex_indicators(record) for record in load_demo_candidates(sample)]
    normalized_records = [normalize_candidates(record) for record in raw_records]
    classified_records = [apply_demo_classification(record) for record in normalized_records]
    clusters = build_demo_clusters(classified_records)

    normalized_path = out_dir / "normalized.jsonl"
    classified_path = out_dir / "classified.jsonl"
    clusters_path = out_dir / "clusters.jsonl"
    gap_path = out_dir / "collection_gap.json"
    stix_path = out_dir / "ctier_stix_bundle.json"
    report_path = out_dir / "analyst_report.md"

    write_jsonl(normalized_path, normalized_records)
    write_jsonl(classified_path, classified_records)
    write_jsonl(clusters_path, clusters)
    gap_summary = summarize_collection_gap(classified_path)
    write_json(gap_path, gap_summary)
    write_json(stix_path, records_to_stix_bundle(classified_records))

    yara_report = validate_yara_rules(DEFAULT_YARA_RULE, run_syntax=False)
    yara_json_path, yara_md_path = write_reports(
        yara_report,
        out_dir / "yara_validation_report.json",
        out_dir / "yara_validation_report.md",
    )

    artifact_paths = {
        "normalized_records": normalized_path,
        "classified_records": classified_path,
        "clusters": clusters_path,
        "collection_gap": gap_path,
        "stix_bundle": stix_path,
        "yara_json": yara_json_path,
        "yara_markdown": yara_md_path,
    }
    report_path.write_text(
        render_analyst_report(classified_records, gap_summary, artifact_paths),
        encoding="utf-8",
    )
    return out_dir


def read_demo_report(output_dir: str | Path) -> str:
    return (Path(output_dir) / "analyst_report.md").read_text(encoding="utf-8")
