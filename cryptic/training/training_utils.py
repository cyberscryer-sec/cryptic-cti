from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cryptic.classification.utils import build_classifier_text, prepare_classifier_record
from cryptic.file_utils import PROJECT_ROOT, read_jsonl

MODEL_ALIASES = {
    "paraphrase-multilingual-MiniLM-L12-v2": "miniLM",
}

CLASSIFIER_ALIASES = {
    "LogisticRegression": "lr",
    "LinearSVC": "svc",
}

RUNS_PATH = PROJECT_ROOT / "trained_models" / "runs.jsonl"


def build_chunk_lookup(chunk_path: Path) -> dict[str, dict]:
    chunks = read_jsonl(chunk_path)
    return {chunk["id"]: chunk for chunk in chunks}


def load_training_rows(labels_path: Path, chunk_path: Path) -> list[dict]:
    labels = read_jsonl(labels_path)
    chunk_lookup = build_chunk_lookup(chunk_path)
    rows = []
    for label_row in labels:
        chunk = chunk_lookup.get(label_row["id"])
        if chunk is None:
            continue
        rows.append(
            {
                "id": label_row["id"],
                "text": chunk["raw_text"],
                "label": label_row["label"],
                "split": label_row["split"],
            }
        )
    return rows


def prepare_training_examples(
    labels_path: Path,
    chunk_path: Path,
) -> tuple[list[str], list[str], list[str]]:
    rows = load_training_rows(labels_path, chunk_path)
    texts = []
    labels = []
    splits = []
    for row in rows:
        processed = prepare_classifier_record({"text": row["text"]})
        text = build_classifier_text(processed)
        if not text:
            continue
        texts.append(text)
        labels.append(row["label"])
        splits.append(row["split"])
    return texts, labels, splits


def default_model_outpath(embedding_model: str, classifier_name: str) -> Path:
    embedding = MODEL_ALIASES.get(embedding_model, embedding_model)
    classifier = CLASSIFIER_ALIASES.get(classifier_name, classifier_name.lower())
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    filename = (f"cti_{classifier}_{embedding}_{date}.joblib")
    return PROJECT_ROOT / "trained_models" / filename


def save_run_record(record: dict, runs_path: Path | None = None) -> Path:
    output_path = Path(runs_path) if runs_path is not None else RUNS_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    run_record = dict(record)
    run_record.setdefault("created_at", datetime.now(timezone.utc).isoformat())
    with output_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(run_record, ensure_ascii=False) + "\n")
    return output_path
