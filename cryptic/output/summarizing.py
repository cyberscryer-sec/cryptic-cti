from __future__ import annotations
from typing import Any
from cryptic.output.output_obj import Output
from cryptic.output.summary_obj import Summary
from cryptic.output.cluster_obj import Cluster
from cryptic.file_utils import read_jsonl

def top_values(values: list[str], limit: int = 3) -> list[str]:
    return [v for v in values if isinstance(v, str) and v.strip()][:limit]


def build_summary_text(cluster: Cluster) -> str:
    malware = top_values(cluster.malware_or_tools, 3)
    activities = top_values(cluster.activities, 3)
    creds = top_values(cluster.credential_data_types, 4)
    platforms = top_values(cluster.platforms, 3)
    parts: list[str] = []
    evidence_parts: list[str] = []
    if malware:
        evidence_parts.append(f"malware/tool references: {', '.join(malware)}")
    if activities:
        evidence_parts.append(f"activity mentions: {', '.join(activities)}")
    if creds:
        evidence_parts.append(f"credential/data mentions: {', '.join(creds)}")
    if platforms:
        evidence_parts.append(f"platform/app mentions: {', '.join(platforms)}")
    if evidence_parts:
        parts.append("This cluster contains " + "; ".join(evidence_parts) + ".")
    else:
        parts.append("This cluster contains limited structured signal after normalization and clustering.")
    if len(cluster.lang) > 1:
        parts.append(f"This cluster merges multilingual reporting across {', '.join(cluster.languages)} records.")
    if len(cluster.record_ids) > 1:
        parts.append(
            f"The cluster aggregates {len(cluster.record_ids)} related records from source {cluster.source}.")
    else:
        parts.append(f"The cluster is based on a single record from source {cluster.source}.")
    return " ".join(parts)


def build_gaps(cluster: Cluster) -> list[str]:
    gaps: list[str] = []
    if not cluster.malware_or_tools:
        gaps.append("No strong malware/tool name extracted.")
    if not cluster.activities:
        gaps.append("No explicit normalized activity extracted.")
    if not cluster.credential_data_types:
        gaps.append("No credential/data type extracted.")
    if not cluster.platforms:
        gaps.append("No platform/app context extracted.")
    if not cluster.indicators:
        gaps.append("No indicators retained in the cluster.")
    return gaps


# def compute_confidence():



def cluster_to_summary(cluster: Cluster) -> Summary:
    summary_text = build_summary_text(cluster)
    gaps = build_gaps(cluster)
    # confidence = compute_confidence(cluster)
    return Summary(
        cluster_id=cluster.id,
        source=cluster.source,
        record_ids=cluster.record_ids,
        lang=cluster.languages,
        summary_text=summary_text,
        representative_text=cluster.representative_text,
        malware_or_tools=cluster.malware_or_tools,
        activities=cluster.activities,
        credential_data_types=cluster.credential_data_types,
        platforms=cluster.platforms,
        indicator_count=len(cluster.indicators),
        # confidence=confidence,
        gaps=gaps,
    )

def summary_to_output(summary: Summary) -> Output:
    payload = summary.to_dict()
    tags: list[str] = []
    if summary.source:
        tags.append(summary.source)
    tags.extend(summary.languages[:2])
    tags.extend(summary.malware_or_tools[:2])
    tags.extend(summary.activities[:2])
    deduped_tags: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        cleaned = tag.strip()
        if not cleaned:
            continue
        norm = cleaned.casefold()
        if norm in seen:
            continue
        seen.add(norm)
        deduped_tags.append(cleaned)
    return Output(
        type="cluster_summary",
        producer=summary.source,
        source_ids=summary.record_ids,
        confidence=summary.confidence,
        tags=deduped_tags,
        payload=payload,
    )