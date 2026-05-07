from __future__ import annotations
from collections.abc import Callable
from cryptic.output.output_obj import Output
from cryptic.output.summary_obj import Summary
from cryptic.output.cluster_obj import Cluster
from cryptic.output.llm_text_utils import det_summary_text, llm_summary_text


def builder_selection(cluster: Cluster, llm_builder: Callable[[Cluster], str] | None = None,) -> Callable[[Cluster], str]:
    score = 0
    if len(cluster.languages) > 1:
        score += 2
    if len(cluster.record_ids) >= 4:
        score += 2
    if len(cluster.raw_texts) >= 3:
        score += 1
    raw_text_len = sum(len(t) for t in cluster.raw_texts)
    structured_signal_count = sum([len(cluster.malware_or_tools), len(cluster.activities), len(cluster.credential_data_types), len(cluster.platforms)])
    if structured_signal_count <= 2 and raw_text_len > 500:
        score += 2
    if raw_text_len > 1000:
        score += 1
    prefer_llm = score >= 3
    if prefer_llm and llm_builder is not None:
        return llm_builder
    return det_summary_text


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


def cluster_to_summary(cluster: Cluster, llm_builder: Callable[[Cluster], str] | None = None) -> Summary:
    selected_builder = builder_selection(cluster, llm_builder=llm_builder)
    summary_text = selected_builder(cluster)
    gaps = build_gaps(cluster)
    summary_method = "llm" if llm_builder is not None and selected_builder is llm_builder else "deterministic"
    return Summary(
        cluster_id=cluster.id,
        source=cluster.source,
        record_ids=cluster.record_ids,
        lang=cluster.languages,
        text=summary_text,
        method=summary_method,
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