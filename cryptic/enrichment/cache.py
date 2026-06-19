from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def cache_key(provider: str, indicator_type: str, value: str) -> str:
    return f"{provider}:{indicator_type.lower()}:{value.casefold()}"


class EnrichmentCache:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.entries = self._load()
        self.dirty_keys: set[str] = set()

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        entries: dict[str, dict[str, Any]] = {}
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                key = record.get("cache_key")
                if key:
                    entries[str(key)] = record
        return entries

    def get(self, key: str) -> dict[str, Any] | None:
        return self.entries.get(key)

    def set(self, key: str, record: dict[str, Any]) -> None:
        self.entries[key] = record
        self.dirty_keys.add(key)

    def flush(self) -> None:
        if not self.dirty_keys:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            for key in sorted(self.dirty_keys):
                f.write(json.dumps(self.entries[key], ensure_ascii=False) + "\n")
        self.dirty_keys.clear()
