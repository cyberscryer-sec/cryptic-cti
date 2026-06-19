from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from cryptic.file_utils import PROCESSED_DIR, latest_matching_file, read_jsonl


def default_records_path() -> Path:
    return latest_matching_file(PROCESSED_DIR, "ctier_classified*.jsonl")


def default_clusters_path() -> Path:
    return latest_matching_file(PROCESSED_DIR, "ctier_clusters*.jsonl")


def load_records(input_path: str | Path | None = None) -> list[dict[str, Any]]:
    path = Path(input_path) if input_path is not None else default_records_path()
    return read_jsonl(path)


def searchable_values(record: dict[str, Any]) -> list[str]:
    fields = [
        "id",
        "raw_text",
        "classifier_predicted_label",
        "n_activity",
        "n_malware_or_tools",
        "n_data_types",
        "n_apps",
        "indicators",
        "indicator_enrichment",
    ]
    values: list[str] = []
    for field in fields:
        value = record.get(field)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    values.extend(str(v) for v in item.values() if isinstance(v, str))
                else:
                    values.append(str(item))
        elif value:
            values.append(str(value))
    return values


def enrichment_summary(record: dict[str, Any]) -> dict[str, Any]:
    enrichment = record.get("indicator_enrichment")
    if not isinstance(enrichment, dict):
        return {}
    summary: dict[str, Any] = {}
    for indicator_key, result in list(enrichment.items())[:5]:
        providers = result.get("providers", {}) if isinstance(result, dict) else {}
        summary[indicator_key] = {
            provider: provider_result.get("status")
            for provider, provider_result in providers.items()
            if isinstance(provider_result, dict)
        }
    return summary


def search_iocs(
    query: str,
    input_path: str | Path | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    query_norm = query.casefold().strip()
    if not query_norm:
        return {"query": query, "count": 0, "results": []}
    results: list[dict[str, Any]] = []
    for record in load_records(input_path):
        values = searchable_values(record)
        haystack = "\n".join(values).casefold()
        if query_norm not in haystack:
            continue
        results.append(
            {
                "id": record.get("id", ""),
                "score": haystack.count(query_norm),
                "classification": record.get("classifier_predicted_label", ""),
                "malware_or_tools": record.get("n_malware_or_tools", []),
                "activities": record.get("n_activity", []),
                "data_types": record.get("n_data_types", []),
                "apps": record.get("n_apps", []),
                "enrichment": enrichment_summary(record),
                "raw_text": str(record.get("raw_text", ""))[:500],
            }
        )
    results.sort(key=lambda item: item["score"], reverse=True)
    return {"query": query, "count": len(results), "results": results[:limit]}


def get_cluster(
    cluster_id: str,
    clusters_path: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(clusters_path) if clusters_path is not None else default_clusters_path()
    for cluster in read_jsonl(path):
        if str(cluster.get("id", "")) == cluster_id:
            return {"found": True, "cluster": cluster}
    return {"found": False, "cluster_id": cluster_id}


def summarize_collection_gap(
    input_path: str | Path | None = None,
    cluster_id: str | None = None,
    clusters_path: str | Path | None = None,
) -> dict[str, Any]:
    records = load_records(input_path)
    if cluster_id:
        cluster = get_cluster(cluster_id, clusters_path)
        record_ids = set(cluster.get("cluster", {}).get("record_ids", []))
        records = [record for record in records if record.get("id") in record_ids]
    total = len(records)
    classification_counter = Counter(
        str(r.get("classifier_predicted_label", "unclassified")) for r in records
    )
    missing_malware = [r.get("id", "") for r in records if not r.get("n_malware_or_tools")]
    missing_activity = [r.get("id", "") for r in records if not r.get("n_activity")]
    missing_data_types = [r.get("id", "") for r in records if not r.get("n_data_types")]
    missing_apps = [r.get("id", "") for r in records if not r.get("n_apps")]
    return {
        "scope": {"cluster_id": cluster_id, "record_count": total},
        "classification_distribution": dict(classification_counter),
        "gaps": {
            "missing_malware_or_tools": missing_malware[:25],
            "missing_activity": missing_activity[:25],
            "missing_data_types": missing_data_types[:25],
            "missing_apps": missing_apps[:25],
        },
        "summary": {
            "missing_malware_or_tools_count": len(missing_malware),
            "missing_activity_count": len(missing_activity),
            "missing_data_types_count": len(missing_data_types),
            "missing_apps_count": len(missing_apps),
        },
    }
