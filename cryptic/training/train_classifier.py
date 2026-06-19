from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
from sklearn.metrics import ConfusionMatrixDisplay, classification_report, confusion_matrix
from sklearn.svm import LinearSVC

from cryptic.classification.utils import embed_texts
from cryptic.file_utils import PROJECT_ROOT, latest_matching_file
from cryptic.training.training_utils import (
    default_model_outpath,
    prepare_training_examples,
    save_run_record,
)

# Set your labels file here
DEFAULT_LABELS_PATH = PROJECT_ROOT / "data/training/ctier_training_labels.jsonl"
# Set your models here
EMBEDDING_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"
CLASSIFIER_TYPE = LinearSVC
CLASSIFIER_KWARGS = {"class_weight": "balanced"}
# CLASSIFIER_TYPE = LogisticRegression
# CLASSIFIER_KWARGS = {"max_iter": 1000}

def train_classifier(
    labels_path: Path,
    chunk_path: Path,
    classifier,
    embedding_model: str,
    output_path: Path | None = None,
) -> Path:
    texts, labels, splits = prepare_training_examples(labels_path, chunk_path)
    embeddings = embed_texts(texts, embedding_model)
    X_train = []
    y_train = []
    X_dev = []
    y_dev = []
    for embedding, label, split in zip(embeddings, labels, splits):
        if split == "train":
            X_train.append(embedding)
            y_train.append(label)
        elif split == "dev":
            X_dev.append(embedding)
            y_dev.append(label)
    classifier.fit(X_train, y_train)
    predictions = classifier.predict(X_dev)
    matrix = confusion_matrix(y_dev, predictions, normalize='true')
    display = ConfusionMatrixDisplay(confusion_matrix=matrix, display_labels=classifier.classes_)
    try:
        import matplotlib.pyplot as plt

        display.plot()
        plt.show()
    except ImportError:
        print("matplotlib is not installed; skipping confusion matrix display.")
    report = classification_report(y_dev, predictions, output_dict=True, zero_division=0)
    print(classification_report(y_dev, predictions, zero_division=0))
    if output_path is None:
        output_path = default_model_outpath(embedding_model, classifier.__class__.__name__)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "classifier": classifier,
            "embedding_model": embedding_model,
            "classifier_type": classifier.__class__.__name__,
        },
        output_path,
    )
    metrics_path = output_path.with_name(output_path.stem + "_metrics.json")
    metrics = {
        "classifier": classifier.__class__.__name__,
        "embedding_model": embedding_model,
        "accuracy": report.get("accuracy"),
        "macro_f1": report.get("macro avg", {}).get("f1-score"),
        "weighted_f1": report.get("weighted avg", {}).get("f1-score"),
        "model_path": str(output_path),
        "labels_path": str(labels_path),
        "chunk_path": str(chunk_path),
    }
    metrics_path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    save_run_record(metrics)
    print(f"Saved classifier to {output_path}")
    print(f"Saved metrics to {metrics_path}")
    return output_path


def main() -> None:
    labels_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_LABELS_PATH
    chunk_path = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else latest_matching_file(PROJECT_ROOT / "data/training", "ctier_chunks*.jsonl")
    )
    output_path = Path(sys.argv[3]) if len(sys.argv) > 3 else None
    train_classifier(
        labels_path,
        chunk_path,
        CLASSIFIER_TYPE(**CLASSIFIER_KWARGS),
        EMBEDDING_MODEL,
        output_path,
    )


if __name__ == "__main__":
    main()
