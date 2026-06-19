from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cryptic.enrichment.cache import EnrichmentCache, cache_key
from cryptic.enrichment.providers import ProviderResponse, enrich_with_provider
from cryptic.file_utils import PROJECT_ROOT, read_jsonl, write_jsonl

DEFAULT_ENRICHMENT_CONFIG = (
    Path(__file__).resolve().parent / "configs" / "indicator_enrichment.json"
)


def resolve_project_path(path: str | Path) -> Path:
    path = Path(path)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def load_enrichment_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path is not None else DEFAULT_ENRICHMENT_CONFIG
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    required = {"cache_path", "timeout_seconds", "providers"}
    missing = required - set(config)
    if missing:
        raise ValueError(f"Enrichment config missing required keys: {sorted(missing)}")
    config["cache_path"] = str(resolve_project_path(config["cache_path"]))
    return config


def indicator_enrichment_key(indicator: dict[str, Any]) -> str:
    indicator_type = str(indicator.get("type", "")).strip().lower()
    value = str(indicator.get("value", "")).strip()
    return f"{indicator_type}:{value.casefold()}"


def provider_response_from_cache(record: dict[str, Any]) -> ProviderResponse:
    return ProviderResponse(
        provider=record["provider"],
        indicator_type=record["indicator_type"],
        value=record["indicator_value"],
        queried_at=record["queried_at"],
        status=record["status"],
        summary=record.get("summary", {}),
        risk_signals=record.get("risk_signals", []),
        raw=record.get("raw"),
    )


def enrich_indicator(
    indicator: dict[str, Any],
    config: dict[str, Any],
    cache: EnrichmentCache,
    providers: list[str] | None = None,
    offline_cache_only: bool = False,
) -> dict[str, Any]:
    indicator_type = str(indicator.get("type", "")).lower()
    value = str(indicator.get("value", "")).strip()
    provider_configs = config.get("providers", {})
    selected = providers or [name for name, item in provider_configs.items() if item.get("enabled")]
    provider_results: dict[str, Any] = {}
    for provider in selected:
        provider_config = provider_configs.get(provider, {})
        key = cache_key(provider, indicator_type, value)
        cached = cache.get(key)
        if cached is not None:
            provider_results[provider] = provider_response_from_cache(cached).public_dict(key)
            provider_results[provider]["status"] = f"cached_{provider_results[provider]['status']}"
            continue
        if offline_cache_only:
            provider_results[provider] = {
                "provider": provider,
                "queried_at": None,
                "status": "cache_miss_offline",
                "summary": {},
                "risk_signals": [],
            }
            continue
        try:
            response = enrich_with_provider(
                provider,
                indicator,
                provider_config,
                int(config.get("timeout_seconds", 20)),
            )
        except Exception as e:
            provider_results[provider] = {
                "provider": provider,
                "queried_at": None,
                "status": "error",
                "summary": {"error": str(e)},
                "risk_signals": [],
            }
            continue
        if response.raw is not None:
            cache.set(key, response.cache_record(key))
        provider_results[provider] = response.public_dict(key if response.raw is not None else None)
    return {
        "indicator": {"type": indicator_type, "value": value},
        "providers": provider_results,
    }


def enrich_record(
    record: dict[str, Any],
    config: dict[str, Any],
    cache: EnrichmentCache,
    providers: list[str] | None = None,
    offline_cache_only: bool = False,
) -> dict[str, Any]:
    enriched = dict(record)
    indicators = [item for item in record.get("indicators", []) if isinstance(item, dict)]
    if not indicators:
        enriched["indicator_enrichment"] = {}
        enriched["enrichment_status"] = "skipped_no_indicators"
        return enriched
    enrichment: dict[str, Any] = {}
    statuses: list[str] = []
    for indicator in indicators:
        key = indicator_enrichment_key(indicator)
        if not key.startswith(":"):
            enrichment[key] = enrich_indicator(
                indicator,
                config,
                cache,
                providers,
                offline_cache_only,
            )
            statuses.extend(
                provider_result.get("status", "")
                for provider_result in enrichment[key]["providers"].values()
            )
    enriched["indicator_enrichment"] = enrichment
    if not enrichment:
        enriched["enrichment_status"] = "skipped_no_supported_indicators"
    elif any(status == "error" for status in statuses):
        enriched["enrichment_status"] = "partial"
    else:
        enriched["enrichment_status"] = "enriched"
    return enriched


def enrich_records(
    records: list[dict[str, Any]],
    config: dict[str, Any],
    providers: list[str] | None = None,
    offline_cache_only: bool = False,
) -> list[dict[str, Any]]:
    cache = EnrichmentCache(config["cache_path"])
    enriched = [
        enrich_record(record, config, cache, providers, offline_cache_only) for record in records
    ]
    cache.flush()
    return enriched


def enrich_file(
    input_path: str | Path,
    output_path: str | Path,
    config_path: str | Path | None = None,
    providers: list[str] | None = None,
    offline_cache_only: bool = False,
) -> Path:
    config = load_enrichment_config(config_path)
    records = read_jsonl(Path(input_path))
    output_path = Path(output_path)
    write_jsonl(output_path, enrich_records(records, config, providers, offline_cache_only))
    return output_path
