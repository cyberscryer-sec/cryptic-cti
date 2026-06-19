from __future__ import annotations

from cryptic.output.indicator_obj import Indicator
from cryptic.output.out_utils import dedupe_list
from cryptic.output.output_obj import Output
from cryptic.output.scoring_utils import meta_score

TECHNICAL_INDICATOR_TYPES = {
    "domain",
    "email",
    "ipv4",
    "ipv6",
    "md5",
    "sha1",
    "sha256",
    "url",
}


def dedupe_indicators(indicators: list[Indicator]) -> list[Indicator]:
    seen: set[tuple[str, str]] = set()
    out: list[Indicator] = []
    for indicator in indicators:
        key = (indicator.type, indicator.value.casefold())
        if key not in seen:
            seen.add(key)
            out.append(indicator)
    return out


def raw_indicator_to_obj(raw_indicator: dict, source_id: str) -> Indicator | None:
    indicator_type = str(
        raw_indicator.get("type") or raw_indicator.get("indicator_type") or ""
    ).strip()
    value = str(raw_indicator.get("value") or "").strip()
    if not indicator_type or not value:
        return None
    confidence = raw_indicator.get("confidence")
    if confidence is not None:
        confidence = int(confidence)
    tags = raw_indicator.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    if indicator_type.lower() in TECHNICAL_INDICATOR_TYPES:
        tags = list(tags) + ["technical-indicator"]
    return Indicator(
        type=indicator_type,
        value=value,
        source_id=str(raw_indicator.get("source_id") or source_id),
        confidence=confidence,
        tags=tags,
        is_detection_ioc=bool(raw_indicator.get("is_detection_ioc", True)),
    )


def record_to_indicators(record: dict) -> list[Indicator]:
    source_id = record.get("id", "")
    iocs = []
    normed_meta = record.get("meta") or record.get("normed_meta", {})
    for raw_indicator in record.get("indicators", []):
        if isinstance(raw_indicator, dict):
            indicator = raw_indicator_to_obj(raw_indicator, source_id)
            if indicator is not None:
                iocs.append(indicator)
    for val in record.get("n_malware_or_tools", []):
        iocs.append(Indicator(
            type="malware_or_tool",
            value=val,
            source_id=source_id,
            confidence=meta_score(normed_meta, "n_malware_or_tools", val),
            tags = ["normalized", "ctier", "malware", "tool"],
        ))
    for val in record.get("n_apps", []):
        iocs.append(Indicator(
            type="platform_or_app",
            value=val,
            source_id=source_id,
            confidence=meta_score(normed_meta, "n_apps", val),
            tags = ["normalized", "ctier", "platform", "app"],
        ))
    for val in record.get("n_activity", []):
        iocs.append(Indicator(
            type="activity",
            value=val,
            source_id=source_id,
            confidence=meta_score(normed_meta, "n_activity", val),
            tags = ["normalized", "ctier", "activity"],
        ))
    for val in record.get("n_data_types") or record.get("n_credential_or_data_types", []):
        iocs.append(Indicator(
            type="credential_or_data_type",
            value=val,
            source_id=source_id,
            confidence=meta_score(normed_meta, "n_data_types", val),
            tags = ["normalized", "ctier", "credential", "data"],
        ))
    return dedupe_indicators(iocs)


def records_to_indicators(records: list[dict]) -> list[Indicator]:
    out = []
    for record in records:
        out.extend(record_to_indicators(record))
    return dedupe_list(out)


def create_indicator_list(indicators: list[Indicator]) -> Output:
    if not indicators:
        raise ValueError("list cannot be empty")
    confidences = [ind.confidence for ind in indicators if ind.confidence is not None]
    overall_confidence = round(sum(confidences) / len(confidences)) if confidences else None
    return Output(
        type="indicator_list",
        producer="ctier_pipeline",
        source_ids=[ind.source_id for ind in indicators],
        tags=["ctier", "normalized", "indicator"],
        confidence=overall_confidence,
        payload={"indicators": [ind.to_dict() for ind in indicators]})
