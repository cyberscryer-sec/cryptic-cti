from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any
from uuid import uuid4

from cryptic.file_utils import utc_now_iso
from cryptic.output.out_utils import dedupe_list, norm_fieldname


@dataclass(slots=True)
class Relationship:
    type: str
    target_id: str
    description: str = ""
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass(slots=True)
class Output:
    id: str = field(default_factory=lambda: str(uuid4()))
    type: str = ""
    generated_at: str = field(default_factory=utc_now_iso)
    producer: str = ""
    source_ids: list[str] = field(default_factory=list)
    confidence: int | None = None
    tlp: str = "TLP:CLEAR"
    tags: list[str] = field(default_factory=list)
    relationships: list[Relationship] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    allowed_tlp = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:RED"}
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.confidence is not None and not (0 <= self.confidence <= 100):
            raise ValueError("confidence must be between 0 and 100")
        self.source_ids = self.dedupe("source_ids")
        self.tags = self.dedupe("tags")
        if self.tlp not in self.allowed_tlp:
            raise ValueError(
                f"tlp must be one of {sorted(self.allowed_tlp)}, got {self.tlp!r}")

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
        elif value is None:
            raise ValueError(f"Value for {field_name} cannot be empty")
        elif field_name in {"source_ids", "tags", "relationships"}:
            raise TypeError(f"use .add_to() to add values to {field_name}")
        elif field_name == "confidence" and not (0 <= value <= 100):
            raise ValueError("confidence must be between 0 and 100")
        elif field_name == "tlp" and value not in self.allowed_tlp:
            raise ValueError(f"tlp must be one of {sorted(self.allowed_tlp)}, got {value!r}")
        else:
            setattr(self, field_name, value)

    def add_to(self, field_name: str, value: Any) -> None:
        field_name = norm_fieldname(field_name)
        if field_name not in self.__dataclass_fields__:
            raise ValueError(f"Invalid field name: {field_name}")
        current_value = getattr(self, field_name)
        if not isinstance(current_value, list):
            raise ValueError(f"Field {field_name} is not a list, use .set_field() instead")
        elif field_name == "relationships":
            if isinstance(value, list):
                if not all(isinstance(item, Relationship) for item in value):
                    raise TypeError(f"All items in {field_name} must be of type Relationship")
            elif not isinstance(value, Relationship):
                raise TypeError(f"relationships must be of type Relationship, got {type(value)}")
        elif field_name == "notes":
            if isinstance(value, list):
                if not all(isinstance(item, str) for item in value):
                    raise TypeError(f"All items in {field_name} must be of type str")
            elif not isinstance(value, str):
                raise TypeError(f"notes must be of type str, got {type(value)}")
        if isinstance(value, list):
            current_value.extend(value)
        else:
            current_value.append(value)
        current_value[:] = self.dedupe(field_name)
        
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "generated_at": self.generated_at,
            "producer": self.producer,
            "source_ids": self.source_ids,
            "confidence": self.confidence,
            "tlp": self.tlp,
            "tags": self.tags,
            "relationships": [rel.to_dict() for rel in self.relationships],
            "notes": self.notes,
            "payload": self.payload,
        }