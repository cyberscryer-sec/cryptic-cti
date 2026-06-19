from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from cryptic.classification.utils import (
    build_classifier_text,
    load_classifier_config,
    load_sklearn_classifier,
)
from cryptic.file_utils import (
    PROCESSED_DIR,
    default_jsonl_outpath,
    latest_matching_file,
    read_jsonl,
    write_jsonl,
)

IN_STAGE = "ctier_normalized"
OUT_STAGE = "ctier_classified"


def _predict_label(classifier: Any, embeddings: Any) -> str:
    prediction = classifier.predict(embeddings)
    if isinstance(prediction, list):
        return str(prediction[0])
    return str(prediction[0])


def classify_record(record: dict, model_bundle: dict, config: dict) -> dict:
    enriched = dict(record)
    prediction_field = config["prediction_field"]
    status_field = config["status_field"]
    classifier_text = build_classifier_text(
        record,
        text_fields=config.get("classifier_text_fields"),
    )
    enriched["classifier_text"] = classifier_text
    enriched["classifier_model"] = model_bundle.get("model_path")
    enriched["embedding_model"] = model_bundle.get("embedding_model")
    if not classifier_text:
        enriched[prediction_field] = None
        enriched[status_field] = "empty_text"
        return enriched
    embedder = model_bundle["embedder"]
    embeddings = embedder.encode(
        [classifier_text],
        show_progress_bar=bool(config.get("progress_bar", False)),
    )
    enriched[prediction_field] = _predict_label(model_bundle["classifier"], embeddings)
    enriched[status_field] = "classified"
    return enriched


def run_classifier(
    i: Path,
    o: Path | None = None,
    config_path: Path | None = None,
) -> Path:
    print(f"[run_classifier] START input={i}", flush=True)
    input_path = Path(i)
    output_path = (
        Path(o)
        if o is not None
        else default_jsonl_outpath(input_path, IN_STAGE, OUT_STAGE)
    )
    print("Loading normalized CTIER records...", flush=True)
    records = read_jsonl(input_path)
    print("Loading sklearn classifier...", flush=True)
    config = load_classifier_config(config_path)
    model_bundle = load_sklearn_classifier(config)
    classified_records: list[dict] = []
    print("Running sklearn classification...", flush=True)
    for index, record in enumerate(records, start=1):
        try:
            classified_records.append(classify_record(record, model_bundle, config))
        except Exception as e:
            failed = dict(record)
            failed[config["prediction_field"]] = None
            failed[config["status_field"]] = f"error: {e}"
            failed["classifier_model"] = model_bundle.get("model_path")
            failed["embedding_model"] = model_bundle.get("embedding_model")
            classified_records.append(failed)
        if index % 25 == 0:
            print(f"Processed {index}/{len(records)} records...", flush=True)
    write_jsonl(output_path, classified_records)
    print(f"Wrote {len(classified_records)} records to {output_path}", flush=True)
    return output_path


def main() -> None:
    args = sys.argv[1:]
    input_path = None
    config_path = None
    for arg in args:
        if arg.startswith("--config="):
            config_path = Path(arg.split("=", 1)[1])
        elif input_path is None:
            input_path = Path(arg)
    if input_path is None:
        input_path = latest_matching_file(PROCESSED_DIR, "ctier_normalized_*.jsonl")
    run_classifier(input_path, config_path=config_path)


if __name__ == "__main__":
    main()
