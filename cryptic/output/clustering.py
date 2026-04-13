from __future__ import annotations
from typing import Any
from uuid import uuid4

from cryptic.output.out_utils import choose_rep, clean_cluster_entities
from cryptic.output.ctier_ioc_builder import record_to_indicators
from cryptic.output.cluster_obj import Cluster


ALLOWED_ENTITY_FIELDS = {"n_malware_or_tools", "n_activity", "n_credential_or_data_types", "n_apps"}

def create_cluster(record: dict[str, Any]) -> Cluster:
    record_id = str(record.get("id", "")).strip()
    if not record_id:
        raise ValueError("Record must have a non-empty id")
    source = str(record.get("source", "")).strip()
    print(f"Creating new cluster with record ID {record_id}")
    cluster = Cluster(id=f"clu_{str(uuid4())[:6]}_{source.strip().lower()}", record_ids=[record_id])
    if source:
        cluster.source = source
    lang = str(record.get("spacy", {}).get("lang", "")).strip()
    if lang:
        cluster.add_str("languages", lang)
    raw_text = str(record.get("raw_text", "")).strip()
    if raw_text:
        cluster.add_str("raw_texts", raw_text)
    cluster.add_str("malware_or_tools", record.get("n_malware_or_tools", []))
    cluster.add_str("activities", record.get("n_activity", []))
    cluster.add_str("credential_data_types", record.get("n_credential_or_data_types", []))
    cluster.add_str("platforms", record.get("n_apps", []))
    cluster.add_indicators(record_to_indicators(record))
    return cluster

def merge_into_cluster(cluster: Cluster, record: dict[str, Any]) -> None:
    record_source = str(record.get("source", "")).strip()
    if cluster.source and record_source and cluster.source != record_source:
        raise ValueError(f"Cannot merge record from source {record_source!r} into cluster with source {cluster.source!r}")
    if not cluster.source and record_source:
        cluster.source = record_source
    cluster.add_str("record_ids", str(record.get("id", "")))
    cluster.add_str("languages", str(record.get("spacy", {}).get("lang", "")))
    cluster.add_str("raw_texts", str(record.get("raw_text", "")))
    cluster.add_str("malware_or_tools", record.get("n_malware_or_tools", []))
    cluster.add_str("activities", record.get("n_activity", []))
    cluster.add_str("credential_data_types", record.get("n_credential_or_data_types", []))
    cluster.add_str("platforms", record.get("n_apps", []))
    cluster.add_indicators(record_to_indicators(record))


def record_entity_set(record: dict[str, Any], field_name: str | None) -> set[str]:
    values: set[str] = set()
    if field_name is not None:
        if field_name not in ALLOWED_ENTITY_FIELDS:
            raise ValueError(f"Field '{field_name}' currently undefined.")
        fields = [field_name]
    else:
        fields = list(ALLOWED_ENTITY_FIELDS)
    for field in fields:
        for val in record.get(field, []):
            if isinstance(val, str):
                cleaned = val.strip().casefold()
                if cleaned:
                    values.add(cleaned)
    return values


def is_overlap(record_a: dict[str, Any], record_b: dict[str, Any], field_name: str | None) -> bool:
    source_a = str(record_a.get("source", "")).strip().casefold()
    source_b = str(record_b.get("source", "")).strip().casefold()
    if source_a != source_b:
        return False
    entities_a = record_entity_set(record_a, field_name)
    entities_b = record_entity_set(record_b, field_name)
    return bool(entities_a & entities_b)


def build_clusters(records: list[dict[str, Any]]) -> list[Cluster]:
    clusters: list[Cluster] = []
    cluster_records: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        matched_cluster = None
        for cluster in clusters:
            members = cluster_records[cluster.id]
            if any(is_overlap(record, member) for member in members):
                matched_cluster = cluster
                break
        if matched_cluster is None:
            new_cluster = create_cluster(record)
            clusters.append(new_cluster)
            cluster_records[new_cluster.id] = [record]
        else:
            merge_into_cluster(matched_cluster, record)
            cluster_records[matched_cluster.id].append(record)
    for cluster in clusters:
        members = cluster_records[cluster.id]
        clean_cluster_entities(cluster, members)
        cluster.representative_text = choose_rep(members)
    return clusters
