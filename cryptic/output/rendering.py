from __future__ import annotations

from cryptic.file_utils import utc_now_iso
from cryptic.output.output_obj import Output

DEFAULT_TITLE = "CTI Collections Report"


def outputobj_to_md(output: Output) -> str:
    if output.type == "cluster_summary":
        return summary_to_md(output)
    if output.type == "indicator_list":
        return indicators_to_md(output)
    raise ValueError(f"unsupported output type: {output.type}")


def create_heading(output: Output) -> str:
    if output.type == "cluster_summary":
        cluster_id = output.payload.get("cluster_id", "unknown")
        return f"Summary: Cluster {cluster_id}"
    producer = output.producer.strip() or "unknown"
    short_id = output.id[:8]
    if output.type == "indicator_list":
        return f"Indicator List - {producer}-{short_id}"
    return f"{output.type} - {producer}-{short_id}"


def metadata_to_md(output: Output) -> list[str]:
    lines: list[str] = []
    meta_parts: list[str] = []
    if output.type:
        meta_parts.append(f"**Type:** {output.type}")
    if output.producer:
        meta_parts.append(f"**Producer:** {output.producer}")
    if output.generated_at:
        meta_parts.append(f"**Generated:** {output.generated_at}")
    if output.confidence is not None:
        meta_parts.append(f"**Confidence:** {output.confidence}")
    if output.tlp:
        meta_parts.append(f"**TLP:** {output.tlp}")
    if meta_parts:
        lines.append(" | ".join(meta_parts))
        lines.append("")
    if output.source_ids:
        lines.append(f"**Source IDs:** {', '.join(output.source_ids)}")
    if output.tags:
        lines.append(f"**Tags:** {', '.join(output.tags)}")
    if output.notes:
        lines.append("**Notes:**")
        for note in output.notes:
            lines.append(f"- {note}")
    if output.source_ids or output.tags or output.notes:
        lines.append("")
    return lines


def summary_to_md(output: Output) -> str:
    payload = output.payload
    text = (payload.get("text") or "").strip()
    source = (payload.get("source") or "").strip()
    record_ids = payload.get("record_ids", [])
    lang = payload.get("lang", [])
    malware = payload.get("malware_or_tools", [])
    activities = payload.get("activities", [])
    creds = payload.get("credential_data_types", [])
    platforms = payload.get("platforms", [])
    indicator_count = payload.get("indicator_count")
    gaps = payload.get("gaps", [])
    lines: list[str] = [f"## {create_heading(output)}", ""]
    lines.extend(metadata_to_md(output))
    if text:
        lines.append(text)
        lines.append("")
    detail_parts: list[str] = []
    if source:
        detail_parts.append(f"**Source:** {source}")
    if record_ids:
        detail_parts.append(f"**Records:** {len(record_ids)}")
    if lang:
        detail_parts.append(f"**Languages:** {', '.join(lang)}")
    if indicator_count is not None:
        detail_parts.append(f"**Indicators:** {indicator_count}")
    if detail_parts:
        lines.append(" | ".join(detail_parts))
        lines.append("")
    if malware:
        lines.append(f"**Malware / Tools:** {', '.join(malware)}")
    if activities:
        lines.append(f"**Activities:** {', '.join(activities)}")
    if creds:
        lines.append(f"**Credential / Data Types:** {', '.join(creds)}")
    if platforms:
        lines.append(f"**Platforms / Apps:** {', '.join(platforms)}")
    if malware or activities or creds or platforms:
        lines.append("")
    if gaps:
        lines.append("**Gaps:**")
        for gap in gaps:
            lines.append(f"- {gap}")
        lines.append("")
    return "\n".join(lines).strip()


def indicators_to_md(output: Output) -> str:
    payload = output.payload
    indicators = payload.get("indicators", [])
    lines: list[str] = [f"## {create_heading(output)}", ""]
    lines.extend(metadata_to_md(output))
    if not indicators:
        lines.append("_No indicators available._")
        return "\n".join(lines).strip()
    for item in indicators:
        ind_type = item.get("type", "unknown")
        value = item.get("value", "")
        confidence = item.get("confidence")
        source_id = item.get("source_id", "")
        detail_parts: list[str] = [ind_type]
        if confidence is not None:
            detail_parts.append(f"confidence={confidence}")
        if source_id:
            detail_parts.append(f"source={source_id}")
        lines.append(f"- `{value}` ({', '.join(detail_parts)})")
    return "\n".join(lines).strip()


def outputs_to_md_report(
    outputs: list[Output],
    title: str = DEFAULT_TITLE,
    w_toc: bool = False,
) -> str:
    if not outputs:
        raise ValueError("outputs cannot be empty")
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"**Generated:** {utc_now_iso()}")
    lines.append(f"**Output count:** {len(outputs)}")
    lines.append("")
    type_counts: dict[str, int] = {}
    for output in outputs:
        type_counts[output.type] = type_counts.get(output.type, 0) + 1
    if type_counts:
        lines.append("## Overview")
        lines.append("")
        for output_type, count in sorted(type_counts.items()):
            lines.append(f"- **{output_type}:** {count}")
        lines.append("")
    if w_toc:
        lines.append("## Contents")
        lines.append("")
        for output in outputs:
            heading = create_heading(output)
            anchor = _markdown_anchor(heading)
            lines.append(f"- [{heading}](#{anchor})")
        lines.append("")
    for idx, output in enumerate(outputs):
        lines.append(outputobj_to_md(output))
        if idx < len(outputs) - 1:
            lines.append("")
            lines.append("---")
            lines.append("")
    return "\n".join(lines).strip()


def _markdown_anchor(text: str) -> str:
    anchor = text.strip().lower().replace(" ", "-")
    return "".join(ch for ch in anchor if ch.isalnum() or ch == "-")
