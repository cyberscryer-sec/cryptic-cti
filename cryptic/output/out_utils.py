from datetime import datetime, timezone
from typing import Any
import csv
from pathlib import Path


JUNK_CANDIDATES = {"mw", "is", "n"}

def drop_junk(record: dict[str, Any], min_score: float = 0.35) -> int:
    seen: set[tuple[str, str]] = set()
    usable = 0
    for cand in record.get("gliner_candidates", []):
        text = str(cand.get("text", "")).strip()
        label = str(cand.get("label", "")).strip().lower()
        score = float(cand.get("score", 0.0))
        if not text:
            continue
        if score < min_score:
            continue
        norm_text = text.casefold()
        if norm_text in JUNK_CANDIDATES:
            continue
        if len(norm_text) < 3:
            continue
        key = (label, norm_text)
        if key in seen:
            continue
        seen.add(key)
        usable += 1
    return usable

def choose_rep(records: list[dict[str, Any]]) -> str:
    best_text = ""
    best_score: tuple[int, int] = (-1, -1)
    for r in records:
        text = str(r.get("raw_text", "")).strip()
        if not text:
            continue
        usable_count = drop_junk(r)
        text_len = len(text)
        score = (usable_count, text_len)
        if score > best_score:
            best_score = score
            best_text = text
    return best_text


def norm_fieldname(field_name: str) -> str:
    return field_name.strip().lower()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def norm_timestamp(value: str) -> str:
    value = value.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()

def dedupe_list(values: list[Any]) -> list[Any]:
    if not isinstance(values, list):
        raise ValueError("Not a list, cannot dedupe")
        out = []
        for value in values:
            if value and value not in out:
                out.append(value)
        return out

def write_ioc_dict_rows(output_obj) -> list[dict]:
    payload = output_obj.payload or {}
    iocs = payload.get("iocs", [])
    rows = []
    for ioc in iocs:
        rows.append(
            {
                "indicator_type": ioc.get("indicator_type", ""),
                "value": ioc.get("value", ""),
                "sourced_from": ioc.get("sourced_from", ""),
                "confidence": ioc.get("confidence", ""),
                "tags": "|".join(ioc.get("tags", [])),
                "first_seen": ioc.get("first_seen", ""),
                "last_seen": ioc.get("last_seen", ""),
                "valid_til": ioc.get("valid_til", ""),
                "is_detection_ioc": ioc.get("is_detection_ioc", ""),
            }
        )
    return rows


def write_ioc_csv(output_obj, output_path: Path | str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = write_ioc_dict_rows(output_obj)
    fieldnames = [
        "indicator_type",
        "value",
        "sourced_from",
        "confidence",
        "tags",
        "first_seen",
        "last_seen",
        "valid_til",
        "is_detection_ioc",
    ]
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return output_path

