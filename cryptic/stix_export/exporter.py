from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any

from cryptic.file_utils import OUTPUT_DIR, PROJECT_ROOT, read_jsonl, utc_now_iso

DEFAULT_STIX_CONFIG = Path(__file__).resolve().parent / "configs" / "ctier_stix_export.json"
STIX_NAMESPACE = uuid.UUID("c2d842b5-09cd-4d87-8f7f-bf7ef2d71989")


def load_stix_export_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path is not None else DEFAULT_STIX_CONFIG
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    required = {
        "producer_name",
        "identity_class",
        "tlp",
        "default_confidence",
        "labels",
        "indicator_fields",
        "malware_fields",
        "activity_fields",
        "source_field",
    }
    missing = required - set(config)
    if missing:
        raise ValueError(f"STIX export config missing required keys: {sorted(missing)}")
    return config


def stix_id(stix_type: str, stable_value: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, stix_type + ':' + stable_value)}"


def first_present(record: dict[str, Any], fields: list[str]) -> list[Any]:
    values: list[Any] = []
    for field in fields:
        value = record.get(field)
        if isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    return values


def dedupe_objects(objects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for obj in objects:
        key = obj.get("id", json.dumps(obj, sort_keys=True))
        if key not in seen:
            seen.add(key)
            out.append(obj)
    return out


def clean_label(value: str) -> str:
    return re.sub(r"\s+", "-", value.strip().lower())


def confidence_for(record: dict[str, Any], config: dict[str, Any]) -> int:
    value = record.get("confidence")
    if value is None:
        value = record.get("classifier_confidence")
    if value is None:
        return int(config["default_confidence"])
    try:
        confidence = int(round(float(value)))
    except (TypeError, ValueError):
        return int(config["default_confidence"])
    return max(0, min(100, confidence))


def observable_pattern(indicator: dict[str, Any]) -> str | None:
    value = str(indicator.get("value", "")).strip()
    indicator_type = str(indicator.get("type") or indicator.get("indicator_type") or "").lower()
    if not value:
        return None
    if indicator_type in {"ipv4", "ip", "ipv4_addr", "ipv4-addr"}:
        return f"[ipv4-addr:value = '{value}']"
    if indicator_type in {"ipv6", "ipv6_addr", "ipv6-addr"}:
        return f"[ipv6-addr:value = '{value}']"
    if indicator_type in {"domain", "domain_name", "domain-name"}:
        return f"[domain-name:value = '{value}']"
    if indicator_type in {"email", "email_addr", "email-addr"}:
        return f"[email-addr:value = '{value}']"
    if indicator_type in {"url", "uri"}:
        return f"[url:value = '{value}']"
    if indicator_type in {"md5", "sha1", "sha256"}:
        hash_name = indicator_type.upper()
        return f"[file:hashes.'{hash_name}' = '{value}']"
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return f"[ipv4-addr:value = '{value}']"
    if re.match(r"^[A-Fa-f0-9]{64}$", value):
        return f"[file:hashes.'SHA256' = '{value}']"
    return None


def indicator_objects_from_record(
    record: dict[str, Any],
    config: dict[str, Any],
    created_by_ref: str,
) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for raw_indicator in first_present(record, list(config["indicator_fields"])):
        if not isinstance(raw_indicator, dict):
            continue
        pattern = observable_pattern(raw_indicator)
        if pattern is None:
            continue
        value = str(raw_indicator.get("value", "")).strip()
        indicator_type = str(
            raw_indicator.get("type") or raw_indicator.get("indicator_type") or "indicator"
        )
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": stix_id("indicator", f"{indicator_type}:{value}"),
                "created": utc_now_iso(),
                "modified": utc_now_iso(),
                "created_by_ref": created_by_ref,
                "name": f"{indicator_type}: {value}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": raw_indicator.get("first_seen") or utc_now_iso(),
                "labels": sorted(set(config["labels"] + ["technical-indicator"])),
                "confidence": raw_indicator.get("confidence") or confidence_for(record, config),
            }
        )
    return objects


def malware_objects_from_record(
    record: dict[str, Any],
    config: dict[str, Any],
    created_by_ref: str,
) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for value in first_present(record, list(config["malware_fields"])):
        if not isinstance(value, str) or not value.strip():
            continue
        name = value.strip()
        objects.append(
            {
                "type": "malware",
                "spec_version": "2.1",
                "id": stix_id("malware", name.casefold()),
                "created": utc_now_iso(),
                "modified": utc_now_iso(),
                "created_by_ref": created_by_ref,
                "name": name,
                "is_family": False,
                "labels": sorted(set(config["labels"] + ["malware-or-tool"])),
                "confidence": confidence_for(record, config),
            }
        )
    return objects


def note_from_record(
    record: dict[str, Any],
    config: dict[str, Any],
    created_by_ref: str,
    object_refs: list[str],
) -> dict[str, Any] | None:
    raw_text = str(record.get("raw_text") or record.get("representative_text") or "").strip()
    activities = [
        str(v)
        for v in first_present(record, list(config["activity_fields"]))
        if str(v).strip()
    ]
    label = record.get("classifier_predicted_label") or record.get("classification")
    if not raw_text and not activities and not label:
        return None
    abstract_parts = []
    if label:
        abstract_parts.append(f"classification={label}")
    if activities:
        abstract_parts.append(f"activities={', '.join(activities)}")
    if raw_text:
        abstract_parts.append(raw_text[:500])
    return {
        "type": "note",
        "spec_version": "2.1",
        "id": stix_id("note", str(record.get("id", "")) + raw_text[:80]),
        "created": utc_now_iso(),
        "modified": utc_now_iso(),
        "created_by_ref": created_by_ref,
        "abstract": "Cryptic CTI normalized context",
        "content": "\n".join(abstract_parts),
        "object_refs": object_refs,
    }


def relationship(
    source_ref: str,
    target_ref: str,
    rel_type: str,
    confidence: int,
) -> dict[str, Any]:
    return {
        "type": "relationship",
        "spec_version": "2.1",
        "id": stix_id("relationship", f"{source_ref}:{rel_type}:{target_ref}"),
        "created": utc_now_iso(),
        "modified": utc_now_iso(),
        "relationship_type": rel_type,
        "source_ref": source_ref,
        "target_ref": target_ref,
        "confidence": confidence,
    }


def records_to_stix_bundle(
    records: list[dict[str, Any]],
    config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = config or load_stix_export_config()
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": stix_id("identity", str(config["producer_name"])),
        "created": utc_now_iso(),
        "modified": utc_now_iso(),
        "name": config["producer_name"],
        "identity_class": config["identity_class"],
    }
    marking = {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": stix_id("marking-definition", str(config["tlp"])),
        "created": utc_now_iso(),
        "definition_type": "statement",
        "definition": {"statement": str(config["tlp"])},
    }
    objects: list[dict[str, Any]] = [identity, marking]
    for record in records:
        malware_objects = malware_objects_from_record(record, config, identity["id"])
        indicator_objects = indicator_objects_from_record(record, config, identity["id"])
        record_objects = malware_objects + indicator_objects
        object_refs = [obj["id"] for obj in record_objects]
        for indicator in indicator_objects:
            for malware in malware_objects:
                record_objects.append(
                    relationship(
                        indicator["id"],
                        malware["id"],
                        "indicates",
                        confidence_for(record, config),
                    )
                )
        note = note_from_record(record, config, identity["id"], object_refs)
        if note:
            record_objects.append(note)
        for obj in record_objects:
            if obj["type"] not in {"identity", "marking-definition", "relationship"}:
                obj.setdefault("object_marking_refs", [marking["id"]])
        objects.extend(record_objects)
    bundle_id = stix_id("bundle", json.dumps([r.get("id", "") for r in records], sort_keys=True))
    return {"type": "bundle", "id": bundle_id, "objects": dedupe_objects(objects)}


def export_stix_bundle(
    input_path: str | Path,
    output_path: str | Path | None = None,
    config_path: str | Path | None = None,
) -> Path:
    input_path = Path(input_path)
    if not input_path.is_absolute():
        input_path = PROJECT_ROOT / input_path
    output_path = Path(output_path) if output_path else OUTPUT_DIR / "ctier_stix_bundle.json"
    config = load_stix_export_config(config_path)
    bundle = records_to_stix_bundle(read_jsonl(input_path), config)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(bundle, f, ensure_ascii=False, indent=2)
    return output_path
