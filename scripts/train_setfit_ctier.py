from __future__ import annotations

import json
from pathlib import Path

from datasets import Dataset
from setfit import SetFitModel, Trainer
from sklearn.metrics import accuracy_score, classification_report

DATA_PATH = Path("data/processed/ctier_labelled_records.jsonl")
MODEL_NAME = "sentence-transformers/distiluse-base-multilingual-cased-v2"
OUT_DIR = Path("models/setfit_ctier_v1")


def read_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def normalize_label(label: str) -> str:
    return label.strip().lower().replace(" ", "-")


def main() -> None:
    print("Loading data...")
    rows = read_jsonl(DATA_PATH)
    train_rows = [r for r in rows if r["split"] == "train"]
    dev_rows = [r for r in rows if r["split"] == "dev"]

    train_dataset = Dataset.from_dict(
        {
            "text": [r["raw_text"] for r in train_rows],
            "label": [normalize_label(r["label"]) for r in train_rows],
        }
    )

    dev_texts = [r["raw_text"] for r in dev_rows]
    dev_labels = [normalize_label(r["label"]) for r in dev_rows]
    print("Loading model...")
    model = SetFitModel.from_pretrained(MODEL_NAME)
    trainer = Trainer(
        model=model,
        train_dataset=train_dataset,
        batch_size=8,
        num_iterations=5,
        num_epochs=1,
    )
    trainer.train()
    preds = model(dev_texts)
    print("\nDEV EXAMPLES\n")
    for row, pred in zip(dev_rows, preds):
        preview = row["raw_text"][:200].replace("\n", " ")
        print(f"ID:        {row['id']}")
        print(f"TRUE:      {row['label']}")
        print(f"PRED:      {pred}")
        print(f"TEXT:      {preview}")
        print("-" * 80)
    print("Accuracy:", accuracy_score(dev_labels, preds))
    print(classification_report(dev_labels, preds, zero_division=0))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(OUT_DIR))


if __name__ == "__main__":
    main()
