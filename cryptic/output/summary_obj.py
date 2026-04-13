from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any

from sqlalchemy import values

@dataclass(slots=True)
class Summary:
    cluster_id: str
    text: str
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