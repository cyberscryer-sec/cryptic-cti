from __future__ import annotations

import json
import shutil
from pathlib import Path

from cryptic.enrichment import providers as provider_module
from cryptic.enrichment.cache import EnrichmentCache, cache_key
from cryptic.enrichment.engine import enrich_record, enrich_records, load_enrichment_config
from cryptic.file_utils import PROJECT_ROOT

SCRATCH = PROJECT_ROOT / ".test_enrichment_tmp"


def reset_scratch() -> Path:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH


def test_enrichment_config_resolves_project_relative_cache_path():
    config = load_enrichment_config()
    assert Path(config["cache_path"]).is_absolute()


def test_missing_api_key_skips_provider_without_failure(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    scratch = reset_scratch()
    config = {
        "cache_path": str(scratch / "cache.jsonl"),
        "timeout_seconds": 1,
        "providers": {
            "virustotal": {
                "enabled": True,
                "api_key_env": "VT_API_KEY",
                "supports": ["domain"],
            }
        },
    }
    enriched = enrich_record(
        {"id": "r1", "indicators": [{"type": "domain", "value": "bad.example"}]},
        config,
        EnrichmentCache(config["cache_path"]),
    )
    vt = enriched["indicator_enrichment"]["domain:bad.example"]["providers"]["virustotal"]
    assert vt["status"] == "skipped_missing_api_key"
    shutil.rmtree(scratch, ignore_errors=True)


def test_provider_response_is_normalized_and_cached(monkeypatch):
    scratch = reset_scratch()
    monkeypatch.setenv("VT_API_KEY", "test-token")

    def fake_request_json(url, headers=None, timeout=20, basic_auth=None):
        return 200, {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 2, "suspicious": 1},
                    "reputation": -4,
                    "country": "US",
                }
            }
        }

    monkeypatch.setattr(provider_module, "request_json", fake_request_json)
    config = {
        "cache_path": str(scratch / "cache.jsonl"),
        "timeout_seconds": 1,
        "providers": {
            "virustotal": {
                "enabled": True,
                "api_key_env": "VT_API_KEY",
                "supports": ["domain"],
            }
        },
    }
    enriched = enrich_records(
        [{"id": "r1", "indicators": [{"type": "domain", "value": "bad.example"}]}],
        config,
    )
    vt = enriched[0]["indicator_enrichment"]["domain:bad.example"]["providers"]["virustotal"]
    assert vt["status"] == "http_200"
    assert "virustotal_malicious:2" in vt["risk_signals"]
    cache_lines = (scratch / "cache.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(cache_lines) == 1
    assert json.loads(cache_lines[0])["raw"]["data"]["attributes"]["reputation"] == -4
    shutil.rmtree(scratch, ignore_errors=True)


def test_offline_cache_only_marks_misses_and_uses_hits():
    scratch = reset_scratch()
    cache_path = scratch / "cache.jsonl"
    key = cache_key("virustotal", "domain", "cached.example")
    cache_path.write_text(
        json.dumps(
            {
                "cache_key": key,
                "provider": "virustotal",
                "indicator_type": "domain",
                "indicator_value": "cached.example",
                "queried_at": "2026-06-18T00:00:00+00:00",
                "status": "http_200",
                "summary": {"reputation": 1},
                "risk_signals": [],
                "raw": {"cached": True},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    config = {
        "cache_path": str(cache_path),
        "timeout_seconds": 1,
        "providers": {
            "virustotal": {
                "enabled": True,
                "api_key_env": "VT_API_KEY",
                "supports": ["domain"],
            }
        },
    }
    enriched = enrich_records(
        [
            {"id": "r1", "indicators": [{"type": "domain", "value": "cached.example"}]},
            {"id": "r2", "indicators": [{"type": "domain", "value": "miss.example"}]},
        ],
        config,
        offline_cache_only=True,
    )
    hit = enriched[0]["indicator_enrichment"]["domain:cached.example"]["providers"]["virustotal"]
    miss = enriched[1]["indicator_enrichment"]["domain:miss.example"]["providers"]["virustotal"]
    assert hit["status"] == "cached_http_200"
    assert miss["status"] == "cache_miss_offline"
    shutil.rmtree(scratch, ignore_errors=True)
