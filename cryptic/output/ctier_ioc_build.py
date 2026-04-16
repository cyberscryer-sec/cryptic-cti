from __future__ import annotations
from cryptic.output.out_utils import dedupe_list
from cryptic.output.output_obj import Output
from cryptic.output.indicator_obj import Indicator
from cryptic.output.scoring_utils import meta_score


def record_to_indicators(record: dict) -> list[Indicator]:
    source_id = record.get("id", "")
    iocs = []
    normed_meta = record.get("normed_meta", {})
    for val in record.get("n_malware_or_tools", []):
        iocs.append(Indicator(
            type="malware_or_tool",
            value=val,
            sourced_from=source_id,
            confidence=meta_score(normed_meta, "n_malware_or_tools", val),
            tags = ["normalized", "ctier", "malware", "tool"],
        ))
    for val in record.get("n_apps", []):
        iocs.append(Indicator(
            type="platform_or_app",
            value=val,
            sourced_from=source_id,
            confidence=meta_score(normed_meta, "n_apps", val),
            tags = ["normalized", "ctier", "platform", "app"],
        ))
    for val in record.get("n_activity", []):
        iocs.append(Indicator(
            type="activity",
            value=val,
            sourced_from=source_id,
            confidence=meta_score(normed_meta, "n_activity", val),
            tags = ["normalized", "ctier", "activity"],
        ))
    for val in record.get("n_credential_or_data_types", []):
        iocs.append(Indicator(
            type="credential_or_data_type",
            value=val,
            sourced_from=source_id,
            confidence=meta_score(normed_meta, "n_credential_or_data_types", val),
            tags = ["normalized", "ctier", "credential", "data"],
        ))
    return iocs


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
        source_ids=[ind.sourced_from for ind in indicators],
        tags=["ctier", "normalized", "indicator"],
        confidence=overall_confidence,
        payload={"indicators": [ind.to_dict() for ind in indicators]},
    )