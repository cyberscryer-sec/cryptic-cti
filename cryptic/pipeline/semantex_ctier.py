from __future__ import annotations
from pathlib import Path
import sys

from cryptic.extraction.engine import ExtractionEngine
from cryptic.file_utils import latest_matching_file, default_jsonl_outpath, read_jsonl, write_jsonl, PROCESSED_DIR

IN_STAGE = "ctier_records"
OUT_STAGE = "ctier_semantic_candidates"

def enrich_record(record: dict, engine: ExtractionEngine) -> dict:
    raw_text = record.get("raw_text") or record.get("raw_entry") or ""
    raw_text = raw_text.strip()
    if not raw_text:
        enriched = dict(record)
        enriched["semantic_status"] = "empty_text"
        enriched["spacy"] = {}
        enriched["gliner_candidates"] = []
        return enriched
    extraction_results = engine.run(raw_text)
    enriched["spacy"] = extraction_results["spacy"]
    enriched["gliner_candidates"] = extraction_results["gliner"]
    enriched = dict(record)
    enriched["semantic_status"] = "extracted"
    return enriched


def run_semantex(i: Path, o: Path | None = None) -> Path:
    print(f"[run_semantex] START input={i}", flush=True)
    input_path = Path(i)
    output_path = Path(o) if o is not None else default_jsonl_outpath(input_path, IN_STAGE, OUT_STAGE)
    print(f"Performing semantic extraction on {input_path}...")
    records = read_jsonl(input_path)
    enriched_records = []
    engine = ExtractionEngine()
    for index, record in enumerate(records, start=1):
        try:
            enriched_records.append(enrich_record(record, engine))
        except Exception as e:
            failed = dict(record)
            failed["semantic_status"] = f"error: {e}"
            failed["spacy"] = {}
            failed["gliner_candidates"] = []
            enriched_records.append(failed)
        if index % 25 == 0:
            print(f"Processed {index}/{len(records)} records")
    write_jsonl(output_path, enriched_records)
    print(f"Wrote {len(enriched_records)} records to {output_path}")
    return output_path

def main() -> None:
    if len(sys.argv) > 1:
        INPUT_PATH = Path(sys.argv[1])
    else:
        INPUT_PATH = latest_matching_file(PROCESSED_DIR, "ctier_records_*.jsonl")
    run_semantex(INPUT_PATH)

if __name__ == "__main__":
    main()