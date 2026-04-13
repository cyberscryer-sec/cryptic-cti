from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

from cryptic.output.indicator_obj import Indicator
from cryptic.output.out_utils import dedupe_list, norm_timestamp, utc_now_iso


@dataclass(slots=True)
class Cluster:
    id: str
    record_ids: list[str] = field(default_factory=list)
    source: str = ""
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    languages: list[str] = field(default_factory=list)
    raw_texts: list[str] = field(default_factory=list)
    representative_text: str = ""
    malware_or_tools: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    credential_data_types: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    confidence: int | None = None
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.id = self.id.strip()
        self.source = self.source.strip()
        self.record_ids = dedupe_list([v.strip() for v in self.record_ids if v.strip()])
        self.languages = dedupe_list([v.strip() for v in self.languages if v.strip()])
        self.raw_texts = dedupe_list([v.strip() for v in self.raw_texts if v.strip()])
        self.malware_or_tools = dedupe_list([v.strip() for v in self.malware_or_tools if v.strip()])
        self.activities = dedupe_list([v.strip() for v in self.activities if v.strip()])
        self.credential_data_types = dedupe_list([v.strip() for v in self.credential_data_types if v.strip()])
        self.platforms = dedupe_list([v.strip() for v in self.platforms if v.strip()])
        self.notes = dedupe_list([v.strip() for v in self.notes if v.strip()])
        self.first_seen = norm_timestamp(self.first_seen)
        self.last_seen = norm_timestamp(self.last_seen)
        if self.confidence is not None and not (0 <= self.confidence <= 100):
            raise ValueError("confidence must be between 0 and 100")
        if not self.id.strip():
            raise ValueError("Cluster must have ID")
        if not self.record_ids:
            raise ValueError("record_ids cannot be empty")
        self.indicators = self._dedupe_indicators(self.indicators)
        if not self.representative_text and self.raw_texts:
            self.representative_text = max(self.raw_texts, key=len)

    def _dedupe_indicators(self, indicators: list[Indicator]) -> list[Indicator]:
        seen: set[tuple[str, str]] = set()
        deduped: list[Indicator] = []
        for item in indicators:
            key = (item.type, item.value.casefold())
            if key not in seen:
                seen.add(key)
                deduped.append(item)
        return deduped

    def add_str(self, field_name: str, values: str | list[str]) -> None:
        allowed = {"malware_or_tools", "activities", "credential_data_types", "platforms", "record_ids", "languages", "raw_texts", "notes"}
        if field_name not in allowed:
            raise ValueError(f"Invalid field name for string-list add: {field_name}")
        current = getattr(self, field_name)
        if isinstance(values, str):
            cleaned = values.strip()
            if cleaned:
                current.append(cleaned)
        else:
            cleaned_values = [v.strip() for v in values if isinstance(v, str) and v.strip()]
            current.extend(cleaned_values)
        setattr(self, field_name, dedupe_list(current))

    def add_indicators(self, items: Indicator | list[Indicator]) -> None:
        if isinstance(items, Indicator):
            self.indicators.append(items)
        else:
            self.indicators.extend(items)
        self.indicators = self._dedupe_indicators(self.indicators)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "record_ids": self.record_ids,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "languages": self.languages,
            "raw_texts": self.raw_texts,
            "representative_text": self.representative_text,
            "malware_or_tools": self.malware_or_tools,
            "activities": self.activities,
            "credential_data_types": self.credential_data_types,
            "platforms": self.platforms,
            "indicators": [indicator.to_dict() for indicator in self.indicators],
            "confidence": self.confidence,
            "notes": self.notes}