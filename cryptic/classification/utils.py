from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
from sentence_transformers import SentenceTransformer

from cryptic.file_utils import PROJECT_ROOT
from cryptic.normalization.normalize import normalize_candidates

DEFAULT_CLASSIFIER_CONFIG = (
    PROJECT_ROOT / "cryptic" / "classification" / "configs" / "ctier_classifier.json"
)

REQUIRED_CLASSIFIER_CONFIG_KEYS = {
    "model_path",
    "embedding_model",
    "classifier_text_fields",
    "prediction_field",
    "status_field",
    "progress_bar",
}


_models: dict[str, SentenceTransformer] = {}
_extractor = None


def _resolve_project_path(value: str | Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def load_classifier_config(path: Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path is not None else DEFAULT_CLASSIFIER_CONFIG
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    missing = sorted(REQUIRED_CLASSIFIER_CONFIG_KEYS - set(config))
    if missing:
        raise ValueError(f"Classifier config missing required keys: {missing}")
    config["config_path"] = str(config_path)
    config["model_path"] = str(_resolve_project_path(config["model_path"]))
    return config


def load_sklearn_classifier(config: dict[str, Any]) -> dict[str, Any]:
    model_path = Path(config["model_path"])
    if not model_path.exists():
        raise FileNotFoundError(f"Classifier model artifact not found: {model_path}")
    artifact = joblib.load(model_path)
    if not isinstance(artifact, dict):
        raise ValueError("Classifier model artifact must be a dict")
    if "classifier" not in artifact:
        raise ValueError("Classifier model artifact missing required key: classifier")
    embedding_model_name = artifact.get("embedding_model") or config["embedding_model"]
    return {
        "classifier": artifact["classifier"],
        "embedding_model": embedding_model_name,
        "classifier_type": artifact.get(
            "classifier_type",
            artifact["classifier"].__class__.__name__,
        ),
        "model_path": str(model_path),
        "embedder": load_embedding_model(embedding_model_name),
    }

def load_embedding_model(model_name: str) -> SentenceTransformer:
    if model_name not in _models:
        _models[model_name] = SentenceTransformer(model_name)
    return _models[model_name]


def embed_texts(texts: list[str], model_name: str, show_progress_bar: bool = True):
    model = load_embedding_model(model_name)
    return model.encode(texts, show_progress_bar=show_progress_bar)


def prepare_classifier_record(record: dict) -> dict:
    global _extractor
    if _extractor is None:
        from cryptic.extraction.engine import ExtractionEngine

        _extractor = ExtractionEngine()
    # print(f"this is the record {record}")
    extracted = _extractor.run(record)
    # print(f"this is extracted: {extracted}")
    return normalize_candidates(extracted)


def build_classifier_text(record: dict, text_fields: list[str] | None = None) -> str:
    parts: list[str] = []
    # Original raw/source text
    raw_text = (record.get("text") or record.get("raw_text") or record.get("content") or "").strip()
    if raw_text:
        parts.append(raw_text)
    # Canonical normalized entities
    normalized_fields = text_fields or [
        "n_activity",
        "n_malware_or_tools",
        "n_data_types",
        "n_apps",
    ]
    for field in normalized_fields:
        values = record.get(field)
        if not values:
            continue
        if isinstance(values, str):
            parts.append(values)
        else:
            parts.extend(values)
    return " ".join(parts)
