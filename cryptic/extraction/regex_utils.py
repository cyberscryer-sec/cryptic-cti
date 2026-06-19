from __future__ import annotations

import ipaddress
import re
from typing import Any

from cryptic.extraction.base import ExtractionRunner

URL_RE = re.compile(r"\b(?:hxxps?|https?)://[^\s<>'\"]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
DOMAIN_RE = re.compile(
    r"\b(?!(?:\d{1,3}\.){3}\d{1,3}\b)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[a-f0-9]{1,4}:){2,}[a-f0-9:]{1,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")


def refang_text(text: str) -> str:
    replacements = {
        "hxxps://": "https://",
        "hxxp://": "http://",
        "hxxps[:]//": "https://",
        "hxxp[:]//": "http://",
        "[.]": ".",
        "(.)": ".",
        "{.}": ".",
        "[:]": ":",
    }
    out = text
    for old, new in replacements.items():
        out = out.replace(old, new)
        out = out.replace(old.upper(), new)
    return out


def strip_trailing_punctuation(value: str) -> str:
    return value.rstrip(".,;:!?)\\]}")


def indicator_key(indicator: dict[str, Any]) -> tuple[str, str]:
    indicator_type = str(indicator.get("type", "")).strip().lower()
    value = str(indicator.get("value", "")).strip()
    if indicator_type in {"domain", "email", "url"}:
        value = value.lower()
    return indicator_type, value


def dedupe_indicators(indicators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    out: list[dict[str, Any]] = []
    for indicator in indicators:
        key = indicator_key(indicator)
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        out.append(indicator)
    return out


def is_valid_ip(value: str, version: int) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == version


def hash_type(value: str) -> str:
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    raise ValueError(f"Unsupported hash length: {length}")


def make_indicator(
    indicator_type: str,
    value: str,
    raw_value: str | None = None,
    confidence: int = 90,
) -> dict[str, Any]:
    value = strip_trailing_punctuation(value.strip())
    raw_value = strip_trailing_punctuation(raw_value.strip()) if raw_value else value
    indicator = {
        "type": indicator_type,
        "value": value,
        "confidence": confidence,
        "tags": ["regex", "technical-indicator"],
    }
    if raw_value != value:
        indicator["raw_value"] = raw_value
    return indicator


def extract_indicators(text: str) -> list[dict[str, Any]]:
    if not text:
        return []
    refanged = refang_text(text)
    indicators: list[dict[str, Any]] = []
    for match in URL_RE.finditer(text):
        raw_value = strip_trailing_punctuation(match.group(0))
        value = strip_trailing_punctuation(refang_text(raw_value))
        indicators.append(make_indicator("url", value, raw_value=raw_value, confidence=92))
    for match in URL_RE.finditer(refanged):
        value = strip_trailing_punctuation(match.group(0))
        indicators.append(make_indicator("url", value, confidence=92))
    for match in EMAIL_RE.finditer(refanged):
        value = match.group(0)
        indicators.append(make_indicator("email", value, confidence=88))
    for match in HASH_RE.finditer(refanged):
        value = match.group(0)
        indicators.append(make_indicator(hash_type(value), value.lower(), confidence=95))
    for match in IPV4_RE.finditer(refanged):
        value = match.group(0)
        if is_valid_ip(value, 4):
            indicators.append(make_indicator("ipv4", value, confidence=93))
    for match in IPV6_RE.finditer(refanged):
        value = strip_trailing_punctuation(match.group(0))
        if is_valid_ip(value, 6):
            indicators.append(make_indicator("ipv6", value.lower(), confidence=93))
    for match in DOMAIN_RE.finditer(refanged):
        value = strip_trailing_punctuation(match.group(0)).lower()
        indicators.append(make_indicator("domain", value, confidence=86))
    return dedupe_indicators(indicators)


def merge_indicator_lists(*indicator_lists: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    for indicators in indicator_lists:
        if not indicators:
            continue
        merged.extend(indicator for indicator in indicators if isinstance(indicator, dict))
    return dedupe_indicators(merged)


class RegexRunner(ExtractionRunner):
    def extract(self, text: str) -> dict[str, list[dict[str, Any]]]:
        return {"indicators": extract_indicators(text)}
