from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

JUNK_CANDIDATES = {"mw", "is", "n"}


def drop_junk(record: dict[str, Any], min_score: float = 0.35) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    usable: list[dict[str, Any]] = []
    for cand in record.get("gliner_candidates", []):
        text = str(cand.get("text", "")).strip()
        label = str(cand.get("label", "")).strip().lower()
        score = float(cand.get("score", 0.0))
        if not text:
            continue
        if score < min_score:
            continue
        norm_text = text.casefold()
        if norm_text in JUNK_CANDIDATES:
            continue
        if len(norm_text) < 3:
            continue
        key = (label, norm_text)
        if key in seen:
            continue
        seen.add(key)
        usable.append(cand)
    return usable


def choose_rep(records: list[dict[str, Any]]) -> str:
    best_text = ""
    best_score: tuple[int, int] = (-1, -1)
    for r in records:
        text = str(r.get("raw_text", "")).strip()
        if not text:
            continue
        text_len = len(text)
        usable_count = len(drop_junk(r))
        score = (usable_count, text_len)
        if score > best_score:
            best_score = score
            best_text = text
    return best_text


def top_values(values: list[str], limit: int = 5) -> list[str]:
    counter = Counter(v.strip() for v in values if isinstance(v, str) and v.strip())
    ranked = sorted(counter.items(), key=lambda x: (x[1], x[0].casefold()))
    return [value for value, _count in ranked[:limit]]


def dedupe_list(values: list[Any]) -> list[Any]:
    if not isinstance(values, list):
        raise ValueError("Not a list, cannot dedupe")
    out = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def write_ioc_dict_rows(output_obj) -> list[dict]:
    payload = output_obj.payload or {}
    iocs = payload.get("iocs", [])
    rows = []
    for ioc in iocs:
        rows.append(
            {
                "indicator_type": ioc.get("indicator_type", ""),
                "value": ioc.get("value", ""),
                "sourced_from": ioc.get("sourced_from", ""),
                "confidence": ioc.get("confidence", ""),
                "tags": "|".join(ioc.get("tags", [])),
                "first_seen": ioc.get("first_seen", ""),
                "last_seen": ioc.get("last_seen", ""),
                "valid_til": ioc.get("valid_til", ""),
                "is_detection_ioc": ioc.get("is_detection_ioc", ""),
            }
        )
    return rows


def clean_text(text: str) -> str:
    clean = text.replace("\u0000", " ")
    clean = re.sub(r"\r\n?", "\n", clean)
    clean = re.sub(r"[ \t]+", " ", clean)
    clean = re.sub(r"\n{3,}", "\n\n", clean)
    return clean.strip()


def clean_cluster_entities(cluster: Any, members: list[dict[str, Any]]) -> None:
    allowed_malware_or_tools: set[str] = set()
    allowed_activities: set[str] = set()
    allowed_credential_data_types: set[str] = set()
    allowed_platforms: set[str] = set()
    for record in members:
        for cand in drop_junk(record):
            text = str(cand.get("text", "")).strip()
            label = str(cand.get("label", "")).strip().lower()
            if not text:
                continue
            norm_text = text.casefold()
            if label == "malware or tool name":
                allowed_malware_or_tools.add(norm_text)
            elif label == "activity":
                allowed_activities.add(norm_text)
            elif label == "credential or data type":
                allowed_credential_data_types.add(norm_text)
            elif label == "platform or application":
                allowed_platforms.add(norm_text)
    cluster.malware_or_tools = [
        v
        for v in cluster.malware_or_tools
        if v.strip() and v.strip().casefold() in allowed_malware_or_tools
    ]
    cluster.activities = [
        v
        for v in cluster.activities
        if v.strip() and v.strip().casefold() in allowed_activities
    ]
    cluster.credential_data_types = [
        v
        for v in cluster.credential_data_types
        if v.strip() and v.strip().casefold() in allowed_credential_data_types
    ]
    cluster.platforms = [
        v
        for v in cluster.platforms
        if v.strip() and v.strip().casefold() in allowed_platforms
    ]


def norm_fieldname(field_name: str) -> str:
    return field_name.strip().lower()


def norm_timestamp(value: str) -> str:
    value = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()
