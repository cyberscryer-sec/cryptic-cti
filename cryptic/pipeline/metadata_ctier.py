import re
import sys
from datetime import date
from hashlib import sha256
from pathlib import Path

from cryptic.file_utils import CORPUS_DIR, write_jsonl


def detect_format(entry: str) -> str:
    s = entry.strip()
    if not s:
        raise ValueError("Empty entry.")
    has_many_brackets = s.count("[") >= 4 and s.count("]") >= 4
    has_pattern = bool(re.search(r"\[\d+,\s*\d+\]", s))
    starts_like = s.startswith("[") or s.startswith("['") or s.startswith('["')
    if starts_like and (has_many_brackets or has_pattern):
        return "nested_list"
    return "text_block"


def split_entries(text: str) -> list[str]:
    parts = text.split("-----")
    return [part.strip() for part in parts if part.strip()]


def build_record_id(source: str, filename: Path, entry_index: int) -> str:
    return f"{source}_{filename.name.replace('.', '')}_{entry_index:03d}"


def parse_corpus(corpus_dir: Path) -> list[dict]:
    records: list[dict] = []
    files = sorted(corpus_dir.glob("*"))
    print(f"Matched {len(files)} files in {corpus_dir.resolve()}: {[f.name for f in files]}")
    for f in files:
        try:
            text = f.read_text(encoding="utf-8")
        except Exception as e:
            records.append(
                {
                    "id": f"ctier_{f.name.replace('.', '')}_ERROR",
                    "source": "ctier",
                    "source_file": f.name,
                    "entry_index": None,
                    "raw_entry": None,
                    "raw_text": None,
                    "format": None,
                    "parse_status": f"error_reading_file: {e}",
                    "content_hash": None,
                }
            )
            continue
        entries = split_entries(text)
        for entry_index, entry in enumerate(entries, start=1):
            try:
                record = {
                    "id": build_record_id("ctier", f, entry_index),
                    "source": "ctier",
                    "source_file": f.name,
                    "entry_index": entry_index,
                    "raw_entry": entry,
                    "raw_text": entry,  # same for now; may diverge for future functionality
                    "format": detect_format(entry),
                    "parse_status": "parsed",
                    "content_hash": sha256(entry.encode("utf-8")).hexdigest(),
                }
            except Exception as e:
                record = {
                    "id": build_record_id("ctier", f, entry_index),
                    "source": "ctier",
                    "source_file": f.name,
                    "entry_index": entry_index,
                    "raw_entry": entry,
                    "raw_text": entry,
                    "format": None,
                    "parse_status": f"error_parsing_entry: {e}",
                    "content_hash": sha256(entry.encode("utf-8")).hexdigest(),
                }
            records.append(record)
    return records


def run_metadata_parser(input_dir: Path, out_file: Path | None = None) -> Path:
    print(f"[run_metadata_parser] START input={input_dir}", flush=True)
    print(f"Parsing corpus in {input_dir} ...")
    records = parse_corpus(input_dir)
    output_path = (
        Path(out_file)
        if out_file is not None
        else Path(f"data/processed/ctier_records_{date.today()}.jsonl")
    )
    write_jsonl(output_path, records)
    print(f"Wrote {len(records)} records to {output_path}")
    return output_path


def main() -> None:
    corpus_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else CORPUS_DIR / "ctier"
    run_metadata_parser(corpus_dir)


if __name__ == "__main__":
    main()
