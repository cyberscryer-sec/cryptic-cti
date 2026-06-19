from __future__ import annotations

import json
from pathlib import Path

CHUNKS_PATH = Path("data/processed/ctier_chunks_2026-04-05.jsonl")
LABELS_PATH = Path("data/labels/ctier_training_labels.jsonl")
OUT_PATH = Path("data/processed/ctier_labelled_records.jsonl")


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSONL in {path} at line {line_no}: {e}") from e
    return rows


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    chunk_rows = read_jsonl(CHUNKS_PATH)
    label_rows = read_jsonl(LABELS_PATH)
    chunks_by_id = {row["id"]: row for row in chunk_rows}
    seen_ids = set()
    joined_rows = []

    for label_row in label_rows:
        record_id = label_row["id"]
        if record_id in seen_ids:
            raise ValueError(f"Duplicate labeled id: {record_id}")
        seen_ids.add(record_id)
        if record_id not in chunks_by_id:
            raise ValueError(f"Labeled id not found in chunks file: {record_id}")
        chunk = chunks_by_id[record_id]
        joined_rows.append(
            {
                "id": record_id,
                "raw_text": chunk["raw_text"],
                "label": label_row["label"],
                "split": label_row["split"],
            }
        )
    write_jsonl(OUT_PATH, joined_rows)
    print(f"Wrote {len(joined_rows)} labeled rows to {OUT_PATH}")


if __name__ == "__main__":
    main()