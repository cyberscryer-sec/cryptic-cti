from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from pathlib import Path
from typing import Any

from cryptic.file_utils import write_jsonl


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_record_id(stable_text: str, index: int) -> str:
    return f"stix_{index:03d}_{content_hash(stable_text)[:12]}"


def fetch_bundle_text(bundle_url_or_file: str | Path) -> tuple[str, str]:
    value = str(bundle_url_or_file)
    if value.startswith(("http://", "https://")):
        with urllib.request.urlopen(value, timeout=20) as response:
            return response.read().decode("utf-8", errors="replace"), value
    path = Path(value)
    return path.read_text(encoding="utf-8"), path.stem


def load_stix_bundle(bundle_url_or_file: str | Path) -> tuple[dict[str, Any], str]:
    text, source_name = fetch_bundle_text(bundle_url_or_file)
    bundle = json.loads(text)
    if bundle.get("type") != "bundle":
        raise ValueError("STIX input must be a bundle object")
    if not isinstance(bundle.get("objects"), list):
        raise ValueError("STIX bundle must contain an objects list")
    return bundle, source_name


def index_objects(bundle: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        obj["id"]: obj
        for obj in bundle.get("objects", [])
        if isinstance(obj, dict) and isinstance(obj.get("id"), str)
    }


def related_object_ids(stix_id: str, objects: list[dict[str, Any]]) -> set[str]:
    related: set[str] = set()
    for obj in objects:
        if obj.get("type") == "relationship":
            if obj.get("source_ref") == stix_id and isinstance(obj.get("target_ref"), str):
                related.add(obj["target_ref"])
            if obj.get("target_ref") == stix_id and isinstance(obj.get("source_ref"), str):
                related.add(obj["source_ref"])
        if obj.get("type") == "note" and stix_id in obj.get("object_refs", []):
            related.add(obj["id"])
    return related


def parse_stix_pattern(pattern: str) -> list[dict[str, Any]]:
    indicators: list[dict[str, Any]] = []
    pattern_map = [
        ("domain-name", "domain", r"domain-name:value\s*=\s*'([^']+)'"),
        ("ipv4-addr", "ipv4", r"ipv4-addr:value\s*=\s*'([^']+)'"),
        ("url", "url", r"url:value\s*=\s*'([^']+)'"),
        ("SHA256", "sha256", r"file:hashes\.'SHA256'\s*=\s*'([^']+)'"),
        ("SHA1", "sha1", r"file:hashes\.'SHA1'\s*=\s*'([^']+)'"),
        ("MD5", "md5", r"file:hashes\.'MD5'\s*=\s*'([^']+)'"),
    ]
    for _name, indicator_type, regex in pattern_map:
        for match in re.finditer(regex, pattern, flags=re.IGNORECASE):
            indicators.append({"type": indicator_type, "value": match.group(1)})
    return indicators


def candidates_from_related_objects(
    related_ids: set[str],
    object_index: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for object_id in sorted(related_ids):
        obj = object_index.get(object_id, {})
        if obj.get("type") == "malware" and obj.get("name"):
            candidates.append(
                {
                    "text": obj["name"],
                    "label": "malware or tool name",
                    "score": 1.0,
                    "source": "stix",
                }
            )
    return candidates


def raw_text_from_objects(
    stix_object: dict[str, Any],
    related_ids: set[str],
    object_index: dict[str, dict[str, Any]],
) -> str:
    parts = [
        str(stix_object.get("name", "")),
        str(stix_object.get("description", "")),
        str(stix_object.get("pattern", "")),
    ]
    for object_id in sorted(related_ids):
        obj = object_index.get(object_id, {})
        if obj.get("type") == "malware":
            parts.append(str(obj.get("name", "")))
            parts.append(str(obj.get("description", "")))
        elif obj.get("type") == "note":
            parts.append(str(obj.get("abstract", "")))
            parts.append(str(obj.get("content", "")))
    return "\n".join(part.strip() for part in parts if part and part.strip())


def indicator_record(
    stix_object: dict[str, Any],
    index: int,
    source_name: str,
    object_index: dict[str, dict[str, Any]],
    bundle_objects: list[dict[str, Any]],
) -> dict[str, Any]:
    related_ids = related_object_ids(stix_object["id"], bundle_objects)
    raw_text = raw_text_from_objects(stix_object, related_ids, object_index)
    indicators = parse_stix_pattern(str(stix_object.get("pattern", "")))
    confidence = stix_object.get("confidence")
    for indicator in indicators:
        if confidence is not None:
            indicator["confidence"] = confidence
    stable_text = stix_object.get("id") or raw_text or f"{source_name}:{index}"
    return {
        "id": stable_record_id(str(stable_text), index),
        "source": "stix",
        "source_name": source_name,
        "source_object_id": stix_object.get("id", ""),
        "stix_type": stix_object.get("type", ""),
        "title": stix_object.get("name", ""),
        "published_at": stix_object.get("created", ""),
        "raw_text": raw_text,
        "content_hash": content_hash(raw_text or str(stable_text)),
        "ingest_status": "ingested" if raw_text else "missing_content",
        "confidence": confidence,
        "indicators": indicators,
        "gliner_candidates": candidates_from_related_objects(related_ids, object_index),
    }


def malware_record(stix_object: dict[str, Any], index: int, source_name: str) -> dict[str, Any]:
    raw_text = "\n".join(
        part
        for part in [str(stix_object.get("name", "")), str(stix_object.get("description", ""))]
        if part.strip()
    )
    stable_text = stix_object.get("id") or raw_text or f"{source_name}:{index}"
    candidates = []
    if stix_object.get("name"):
        candidates.append(
            {
                "text": stix_object["name"],
                "label": "malware or tool name",
                "score": 1.0,
                "source": "stix",
            }
        )
    return {
        "id": stable_record_id(str(stable_text), index),
        "source": "stix",
        "source_name": source_name,
        "source_object_id": stix_object.get("id", ""),
        "stix_type": stix_object.get("type", ""),
        "title": stix_object.get("name", ""),
        "published_at": stix_object.get("created", ""),
        "raw_text": raw_text,
        "content_hash": content_hash(raw_text or str(stable_text)),
        "ingest_status": "ingested" if raw_text else "missing_content",
        "confidence": stix_object.get("confidence"),
        "indicators": [],
        "gliner_candidates": candidates,
    }


def records_from_stix_bundle(
    bundle: dict[str, Any],
    source_name: str = "stix_bundle",
) -> list[dict[str, Any]]:
    objects = [obj for obj in bundle.get("objects", []) if isinstance(obj, dict)]
    object_index = index_objects(bundle)
    records: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") == "indicator":
            records.append(
                indicator_record(obj, len(records) + 1, source_name, object_index, objects)
            )
        elif obj.get("type") == "malware":
            records.append(malware_record(obj, len(records) + 1, source_name))
    return records


def ingest_stix_bundle(bundle_url_or_file: str | Path, output_path: str | Path) -> Path:
    bundle, source_name = load_stix_bundle(bundle_url_or_file)
    records = records_from_stix_bundle(bundle, source_name)
    output_path = Path(output_path)
    write_jsonl(output_path, records)
    return output_path
