from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from cryptic.file_utils import utc_now_iso


@dataclass(slots=True)
class ProviderResponse:
    provider: str
    indicator_type: str
    value: str
    queried_at: str
    status: str
    summary: dict[str, Any]
    risk_signals: list[str]
    raw: dict[str, Any] | None = None

    def public_dict(self, raw_ref: str | None = None) -> dict[str, Any]:
        out = {
            "provider": self.provider,
            "queried_at": self.queried_at,
            "status": self.status,
            "summary": self.summary,
            "risk_signals": self.risk_signals,
        }
        if raw_ref:
            out["raw_ref"] = raw_ref
        return out

    def cache_record(self, key: str) -> dict[str, Any]:
        return {
            "cache_key": key,
            "provider": self.provider,
            "indicator_type": self.indicator_type,
            "indicator_value": self.value,
            "queried_at": self.queried_at,
            "status": self.status,
            "summary": self.summary,
            "risk_signals": self.risk_signals,
            "raw": self.raw,
        }


def urlsafe_vt_url_id(value: str) -> str:
    encoded = base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def request_json(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 20,
    basic_auth: tuple[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request_headers = dict(headers or {})
    if basic_auth is not None:
        userpass = f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
        token = base64.b64encode(userpass).decode("ascii")
        request_headers["Authorization"] = f"Basic {token}"
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.status, json.loads(body) if body else {}


def skipped_response(
    provider: str,
    indicator_type: str,
    value: str,
    status: str,
    reason: str,
) -> ProviderResponse:
    return ProviderResponse(
        provider=provider,
        indicator_type=indicator_type,
        value=value,
        queried_at=utc_now_iso(),
        status=status,
        summary={"reason": reason},
        risk_signals=[],
        raw=None,
    )


def virustotal_endpoint(indicator_type: str, value: str) -> str:
    base = "https://www.virustotal.com/api/v3"
    if indicator_type in {"ipv4", "ipv6"}:
        return f"{base}/ip_addresses/{urllib.parse.quote(value)}"
    if indicator_type == "domain":
        return f"{base}/domains/{urllib.parse.quote(value)}"
    if indicator_type == "url":
        return f"{base}/urls/{urlsafe_vt_url_id(value)}"
    if indicator_type in {"md5", "sha1", "sha256"}:
        return f"{base}/files/{urllib.parse.quote(value)}"
    raise ValueError(f"VirusTotal does not support {indicator_type}")


def summarize_virustotal(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    summary = {
        "last_analysis_stats": stats,
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "categories": attrs.get("categories"),
    }
    risk = []
    if malicious:
        risk.append(f"virustotal_malicious:{malicious}")
    if suspicious:
        risk.append(f"virustotal_suspicious:{suspicious}")
    return summary, risk


def summarize_greynoise(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    summary = {
        "noise": raw.get("noise"),
        "riot": raw.get("riot"),
        "classification": raw.get("classification"),
        "name": raw.get("name"),
        "link": raw.get("link"),
    }
    risk = []
    if raw.get("noise"):
        risk.append("greynoise_noise")
    if raw.get("classification") and raw.get("classification") != "unknown":
        risk.append(f"greynoise_{raw['classification']}")
    return summary, risk


def summarize_censys(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    result = raw.get("result", raw)
    services = result.get("services") or []
    summary = {
        "service_count": len(services),
        "location": result.get("location"),
        "autonomous_system": result.get("autonomous_system"),
        "last_updated_at": result.get("last_updated_at"),
        "names": result.get("names"),
    }
    return summary, [f"censys_services:{len(services)}"] if services else []


def summarize_ipinfo(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    summary = {
        "asn": raw.get("asn"),
        "as_name": raw.get("as_name"),
        "as_domain": raw.get("as_domain"),
        "country_code": raw.get("country_code"),
        "country": raw.get("country"),
    }
    return summary, []


def summarize_urlscan(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    results = raw.get("results") or []
    first = results[0] if results else {}
    summary = {
        "total": raw.get("total"),
        "result_count": len(results),
        "first_result": {
            "task": first.get("task"),
            "page": first.get("page"),
            "verdicts": first.get("verdicts"),
        }
        if first
        else None,
    }
    risk = []
    verdicts = first.get("verdicts", {}) if first else {}
    if verdicts.get("overall", {}).get("malicious"):
        risk.append("urlscan_malicious")
    return summary, risk


def enrich_with_provider(
    provider: str,
    indicator: dict[str, Any],
    provider_config: dict[str, Any],
    timeout: int,
) -> ProviderResponse:
    indicator_type = str(indicator.get("type", "")).lower()
    value = str(indicator.get("value", "")).strip()
    supports = set(provider_config.get("supports", []))
    if indicator_type not in supports:
        return skipped_response(provider, indicator_type, value, "skipped_unsupported_type", "")
    if provider == "censys":
        api_id = os.getenv(str(provider_config.get("api_id_env", "")))
        api_secret = os.getenv(str(provider_config.get("api_secret_env", "")))
        if not api_id or not api_secret:
            return skipped_response(provider, indicator_type, value, "skipped_missing_api_key", "")
        url = f"https://search.censys.io/api/v2/hosts/{urllib.parse.quote(value)}"
        status, raw = request_json(url, timeout=timeout, basic_auth=(api_id, api_secret))
        summary, risk = summarize_censys(raw)
    else:
        api_key = os.getenv(str(provider_config.get("api_key_env", "")))
        if not api_key:
            return skipped_response(provider, indicator_type, value, "skipped_missing_api_key", "")
        if provider == "virustotal":
            url = virustotal_endpoint(indicator_type, value)
            status, raw = request_json(url, headers={"x-apikey": api_key}, timeout=timeout)
            summary, risk = summarize_virustotal(raw)
        elif provider == "greynoise":
            url = f"https://api.greynoise.io/v3/community/{urllib.parse.quote(value)}"
            status, raw = request_json(url, headers={"key": api_key}, timeout=timeout)
            summary, risk = summarize_greynoise(raw)
        elif provider == "ipinfo":
            url = f"https://api.ipinfo.io/lite/{urllib.parse.quote(value)}?token={api_key}"
            status, raw = request_json(url, timeout=timeout)
            summary, risk = summarize_ipinfo(raw)
        elif provider == "urlscan":
            query = f"domain:{value}" if indicator_type == "domain" else f'page.url:"{value}"'
            url = "https://urlscan.io/api/v1/search/?" + urllib.parse.urlencode({"q": query})
            status, raw = request_json(url, headers={"API-Key": api_key}, timeout=timeout)
            summary, risk = summarize_urlscan(raw)
        else:
            return skipped_response(provider, indicator_type, value, "skipped_unknown_provider", "")
    return ProviderResponse(
        provider=provider,
        indicator_type=indicator_type,
        value=value,
        queried_at=utc_now_iso(),
        status=f"http_{status}",
        summary=summary,
        risk_signals=risk,
        raw=raw,
    )
