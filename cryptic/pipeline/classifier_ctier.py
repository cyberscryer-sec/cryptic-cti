from __future__ import annotations
import sys
from pathlib import Path
from setfit import SetFitModel
from cryptic.file_utils import latest_matching_file, read_jsonl, write_jsonl
from cryptic.classification.utils import load_model

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # adjust as needed based on your repository structure
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
MODEL_DIR = PROJECT_ROOT / "models" / "setfit_ctier_v1"


def default_output_path(input_path: Path) -> Path:
    if "ctier_semantic_candidates" in input_path.name:
        output_name = input_path.name.replace("ctier_semantic_candidates", "ctier_classified")
    else:
        output_name = f"{input_path.stem}_classified{input_path.suffix}"
    return input_path.with_name(output_name)


def classify_record(record: dict, model: SetFitModel) -> dict:
    raw_text = (record.get("raw_text") or "").strip()
    enriched = dict(record)
    if not raw_text:
        enriched["setfit_predicted_label"] = None
        enriched["classification_status"] = "empty_text"
        return enriched
    predicted_label = model.predict([raw_text])[0]
    enriched["setfit_predicted_label"] = predicted_label
    enriched["classification_status"] = "classified"
    return enriched


def run_classifier(i: Path, o: Path | None = None) -> Path:
    print(f"[run_classifier] START input={i}", flush=True)
    input_path = Path(i)
    output_path = Path(o) if o is not None else default_output_path(input_path)
    print("Loading semantic CTIER records...")
    records = read_jsonl(input_path)
    print("Loading SetFit model...")
    model = load_model(MODEL_DIR)
    classified_records: list[dict] = []
    print("Running SetFit classification...")
    for index, record in enumerate(records, start=1):
        try:
            classified_records.append(classify_record(record, model))
        except Exception as e:
            failed = dict(record)
            failed["setfit_predicted_label"] = None
            failed["classification_status"] = f"error: {e}"
            classified_records.append(failed)
        if index % 25 == 0:
            print(f"Processed {index}/{len(records)} records...")
    write_jsonl(output_path, classified_records)
    print(f"Wrote {len(classified_records)} records to {output_path}")
    return output_path

def main() -> None:
    if len(sys.argv) > 1:
        input_path = Path(sys.argv[1])
    else:
        input_path = latest_matching_file(PROCESSED_DIR, "ctier_semantic_candidates_*.jsonl")
    run_classifier(input_path)

if __name__ == "__main__":
    main()