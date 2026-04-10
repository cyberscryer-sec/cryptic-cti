from __future__ import annotations
from collections_workflow.cryptic.output.out_utils import dedupe_list
from collections_workflow.cryptic.output.output_objects import OUTPUT
from cryptic.output.ioc import IOCItem

def record_iocs(record: dict) -> list[IOCItem]:
    source_id = record.get("id", "")
    iocs = []
    confidence = None
    for val in record.get("n_malware_or_tools"):
        iocs.append(IOCItem(
            indicator_type="malware_or_tool",
            value=val,
            sourced_from=source_id,
            confidence=confidence,
            tags = ["normalized", "ctier", "malware", "tool"],
        ))
    for val in record.get("n_apps"):
        iocs.append(IOCItem(
            indicator_type="platform_or_app",
            value=val,
            sourced_from=source_id,
            confidence=confidence,
            tags = ["normalized", "ctier", "platform", "app"],
        ))
    for val in record.get("n_activity"):
        iocs.append(IOCItem(
            indicator_type="activity",
            value=val,
            sourced_from=source_id,
            confidence=confidence,
            tags = ["normalized", "ctier", "activity"],
        ))
    for val in record.get("n_credential_or_data_types"):
        iocs.append(IOCItem(
            indicator_type="credential_or_data_type",
            value=val,
            sourced_from=source_id,
            confidence=confidence,
            tags = ["normalized", "ctier", "credential", "data"],
        ))
    return iocs

def records_iocs(records: list[dict]) -> list[IOCItem]:
    out = []
    for record in records:
        out.extend(record_iocs(record))
    return dedupe_list(out)

def create_ioc_list(ioc_list: list[IOCItem]) -> OUTPUT:
    confidences = [ioc.confidence for ioc in ioc_list if ioc.confidence is not None]
    overall_confidence = round(sum(confidences) / len(confidences)) if confidences else None
    if ioc_list == [] or ioc_list is None:
        raise ValueError("ioc_list cannot be empty")
    return OUTPUT(
        type="ioc_list",
        producer="ctier_pipeline",
        source_ids=[ioc.sourced_from for ioc in ioc_list],
        tags=["ctier", "normalized", "ioc"],
        confidence=overall_confidence,
        payload={"iocs": [ioc.to_dict() for ioc in ioc_list]},
    )