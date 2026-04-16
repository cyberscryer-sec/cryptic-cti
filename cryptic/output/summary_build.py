from __future__ import annotations
from collections.abc import Callable
from cryptic.output.output_obj import Output
from cryptic.output.summary_obj import Summary
from cryptic.output.cluster_obj import Cluster
from cryptic.output.llm_text_utils import det_summary_text


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


def cluster_to_summary(
    cluster: Cluster,
    text_builder: Callable[[Cluster], str] = det_summary_text,
) -> Summary:
    summary_text = text_builder(cluster)
    gaps = build_gaps(cluster)
    return Summary(
        cluster_id=cluster.id,
        source=cluster.source,
        record_ids=cluster.record_ids,
        lang=cluster.languages,
        text=summary_text,
        representative_text=cluster.representative_text,
        malware_or_tools=cluster.malware_or_tools,
        activities=cluster.activities,
        credential_data_types=cluster.credential_data_types,
        platforms=cluster.platforms,
        indicator_count=len(cluster.indicators),
        confidence=cluster.confidence,
        gaps=gaps,
    )


def summary_to_output(summary: Summary) -> Output:
    payload = summary.to_dict()
    tags: list[str] = []
    if summary.source:
        tags.append(summary.source)
    tags.extend(summary.lang[:2])
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