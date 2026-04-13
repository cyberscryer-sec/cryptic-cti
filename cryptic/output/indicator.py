from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any
from cryptic.output.out_utils import dedupe_list, norm_fieldname, norm_timestamp, utc_now_iso

@dataclass(slots=True)
class Indicator:
    type: str
    value: str
    sourced_from: str
    confidence: int | None = None
    tags: list[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utc_now_iso)
    last_seen: str = field(default_factory=utc_now_iso)
    valid_til: str | None = None
    is_detection_ioc: bool = True

    def __post_init__(self) -> None:
        self.type = norm_fieldname(self.type)
        self.value = self.value.strip()
        self.tags = self.dedupe("tags")
        self.sourced_from = self.sourced_from.strip()
        self.first_seen = norm_timestamp(self.first_seen)
        self.last_seen = norm_timestamp(self.last_seen)
        if self.valid_til is not None:
            self.valid_til = norm_timestamp(self.valid_til)
        if not self.type:
            raise ValueError("indicator type cannot be empty")
        if not self.value:
            raise ValueError("value cannot be empty")
        if self.confidence is not None and not (0 <= self.confidence <= 100):
            raise ValueError("confidence must be between 0 and 100")
    
    def dedupe(self, field_name: str) -> list[Any]:
        field_name = norm_fieldname(field_name)
        if field_name not in self.__dataclass_fields__:
            raise ValueError(f"Invalid field name: {field_name}")
        values = getattr(self, field_name)
        return dedupe_list(values)

    def set_field(self, field_name: str, value: Any) -> None:
        field_name = norm_fieldname(field_name)
        if field_name not in self.__dataclass_fields__:
            raise ValueError(f"Invalid field name: {field_name}")
        elif field_name == "tags":
            raise TypeError(f"use .add_tag() to add values to {field_name}")
        elif field_name == "confidence" and value is not None and not (0 <= value <= 100):
            raise ValueError("confidence must be between 0 and 100")
        else:
            if field_name in {"first_seen", "last_seen", "valid_til"}:
                if value is not None:
                    value = norm_timestamp(value)
            setattr(self, field_name, value)

    def add_tag(self, values: str | list[str]) -> None:
        if isinstance(values, str):
            tag = values.strip()
            if tag and tag not in self.tags:
                self.tags.append(tag)
        if isinstance(values, list):
            for v in values:
                v = v.strip()
            self.tags.extend(values)
        self.tags = self.dedupe("tags")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

