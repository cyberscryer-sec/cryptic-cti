from __future__ import annotations
import sys
from pathlib import Path
from cryptic.normalization.normalize import normalize_candidates
from cryptic.file_utils import default_jsonl_outpath, latest_matching_file, read_jsonl, write_jsonl, PROCESSED_DIR


IN_STAGE = "ctier_classified"
OUT_STAGE = "ctier_normalized"


def run_normalizer(i: Path, o: Path | None = None) -> Path:
    print(f"[run_normalizer] START input={i}", flush=True)
    input_path = Path(i)
    output_path = Path(o) if o is not None else default_jsonl_outpath(input_path, IN_STAGE, OUT_STAGE)
    print(f"Normalizing {input_path} ...")
    records = read_jsonl(input_path)
    normalized_rows = []
    for i, record in enumerate(records, start=1):
        try:
            normalized_rows.append(normalize_candidates(record))
        except Exception as e:
            failed = dict(record)
            failed["norm_status"] = f"error: {e}"
            normalized_rows.append(failed)
        if i % 25 == 0:
            print(f"Processed {i}/{len(records)} records")
    write_jsonl(output_path, normalized_rows)
    print(f"Wrote {len(normalized_rows)} records to {output_path}")
    return output_path

def main() -> None:
    if len(sys.argv) > 1:
        input_path = Path(sys.argv[1])
    else:
        input_path = latest_matching_file(PROCESSED_DIR, "ctier_classified*.jsonl")
    run_normalizer(input_path)
    

if __name__ == "__main__":
    main()