from __future__ import annotations

import json
from pathlib import Path


def load_variant_map(path: Path) -> dict[str, str]:
    with path.open("r", encoding="utf-8") as f:
        map = json.load(f)
    lookup: dict[str, str] = {}
    for canonical, meta in map.items():
        variants = meta.get("variants", [])
        lookup[canonical.lower()] = canonical
        for variant in variants:
            lookup[variant.lower()] = canonical
    return lookup


def canonicalize_value(text: str, lookup: dict[str, str]) -> tuple[str, bool]:
    normalized = text.strip().lower()
    if normalized in lookup:
        return lookup[normalized], True
    return text, False


PROJECT_ROOT = Path(__file__).resolve().parents[2]
UNMAPPED_PATH = (PROJECT_ROOT / "data" / "processed" / "unmapped_activities.jsonl")
_seen_unmapped: set[tuple[str, str]] = set()

def track_unmapped(text: str, label: str, category: str, source: str = "ctier") -> None:
    key = (text.lower(), label)
    if key in _seen_unmapped:
        return
    _seen_unmapped.add(key)
    record = {
        "text": text,
        "normalized": text.lower(),
        "label": label,
        "category": category,
        "source": source,
        "canonical_match": None}
    UNMAPPED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with UNMAPPED_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")