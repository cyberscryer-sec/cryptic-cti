from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass(slots=True)
class Summary:
    cluster_id: str
    text: str
    method: str
    record_ids: list[str]
    source: str
    lang: list[str]
    representative_text: str
    malware_or_tools: list[str]
    activities: list[str]
    credential_data_types: list[str]
    platforms: list[str]
    indicator_count: int
    gaps: list[str] = field(default_factory=list)
    confidence: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
    def dedupe(self, fieldname: str) -> None:
        if fieldname not in self.__dataclass_fields__:
            raise ValueError(f"Invalid field name: {fieldname}")
        values = getattr(self, fieldname)
        if not isinstance(values, list):
            raise ValueError("Not a list, cannot dedupe")
        out = []
        for value in values:
            if value not in out:
                out.append(value)
        setattr(self, fieldname, out)

    def __post_init__(self) -> None:
        self.cluster_id = self.cluster_id.strip()
        self.source = self.source.strip()
        self.text = self.summary_text.strip()
        self.method = self.method.strip()
        self.representative_text = self.representative_text.strip()
        self.record_ids = list(dict.fromkeys(v.strip() for v in self.record_ids if v.strip()))
        self.lang = list(dict.fromkeys(v.strip() for v in self.lang if v.strip()))
        self.malware_or_tools = list(dict.fromkeys(v.strip() for v in self.malware_or_tools if v.strip()))
        self.activities = list(dict.fromkeys(v.strip() for v in self.activities if v.strip()))
        self.credential_data_types = list(dict.fromkeys(v.strip() for v in self.credential_data_types if v.strip()))
        self.platforms = list(dict.fromkeys(v.strip() for v in self.platforms if v.strip()))
        self.gaps = list(dict.fromkeys(v.strip() for v in self.gaps if v.strip()))
        if self.confidence is not None and not (0 <= self.confidence <= 100):
            raise ValueError("confidence must be between 0 and 100")