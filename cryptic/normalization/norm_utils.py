from __future__ import annotations


def normalize_key(value: str) -> str:
    return " ".join(value.strip().lower().split())

def normalize_value(value: str, mapping: dict[str, str]) -> tuple[str, bool]:
    cleaned = value.strip()
    key = normalize_key(cleaned)
    if key in mapping:
        return mapping[key], True
    return cleaned, False


def dedupe_preserve_order(values: list) -> list:
    seen = set()
    out = []
    for v in values:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out