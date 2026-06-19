from __future__ import annotations

import json
from pathlib import Path

import joblib
import pytest

from cryptic.classification import utils as classifier_utils
from cryptic.classification.utils import (
    build_classifier_text,
    load_classifier_config,
    load_sklearn_classifier,
)
from cryptic.file_utils import PROJECT_ROOT, default_jsonl_outpath
from cryptic.pipeline import classifier_ctier, normalize_ctier
from cryptic.pipeline.classifier_ctier import classify_record
from cryptic.training.training_utils import default_model_outpath


class FakeClassifier:
    def predict(self, embeddings):
        return ["credential-theft-or-infostealer"]


class FakeEmbedder:
    def encode(self, texts, show_progress_bar=False):
        return [[len(texts[0])]]


def test_build_classifier_text_uses_raw_text_and_normalized_fields():
    record = {
        "raw_text": "RedLine stealer advertised browser logs.",
        "n_activity": ["credential_theft"],
        "n_malware_or_tools": ["RedLine"],
        "n_data_types": ["browser credentials"],
        "n_apps": ["Chrome"],
    }
    text = build_classifier_text(record)
    assert "RedLine stealer advertised browser logs." in text
    assert "credential_theft" in text
    assert "RedLine" in text
    assert "browser credentials" in text
    assert "Chrome" in text


def test_load_classifier_config_resolves_project_relative_model_path(monkeypatch):
    config = {
        "model_path": "trained_models/example.joblib",
        "embedding_model": "example-embedding",
        "classifier_text_fields": ["n_activity"],
        "prediction_field": "classifier_predicted_label",
        "status_field": "classification_status",
        "progress_bar": False,
    }
    monkeypatch.setattr(json, "load", lambda _file: config)
    monkeypatch.setattr(Path, "open", lambda self, *args, **kwargs: open(__file__, *args, **kwargs))
    loaded = load_classifier_config(Path("fake_config.json"))
    assert Path(loaded["model_path"]) == PROJECT_ROOT / "trained_models" / "example.joblib"


def test_load_sklearn_classifier_rejects_missing_and_malformed_artifacts(monkeypatch):
    config = {"model_path": "missing.joblib", "embedding_model": "mini"}
    with pytest.raises(FileNotFoundError):
        load_sklearn_classifier(config)

    monkeypatch.setattr(Path, "exists", lambda _self: True)
    monkeypatch.setattr(joblib, "load", lambda _path: {"embedding_model": "mini"})
    with pytest.raises(ValueError, match="classifier"):
        load_sklearn_classifier({"model_path": "malformed.joblib", "embedding_model": "mini"})


def test_load_sklearn_classifier_returns_bundle_with_config_embedding(monkeypatch):
    monkeypatch.setattr(Path, "exists", lambda _self: True)
    monkeypatch.setattr(
        joblib,
        "load",
        lambda _path: {"classifier": FakeClassifier(), "classifier_type": "FakeClassifier"},
    )
    monkeypatch.setattr(classifier_utils, "load_embedding_model", lambda _name: FakeEmbedder())
    bundle = load_sklearn_classifier(
        {"model_path": "model.joblib", "embedding_model": "example-embedding"}
    )
    assert isinstance(bundle["classifier"], FakeClassifier)
    assert bundle["embedding_model"] == "example-embedding"
    assert isinstance(bundle["embedder"], FakeEmbedder)


def test_classify_record_uses_fake_embedding_and_classifier():
    record = {
        "raw_text": "Lumma logs for sale.",
        "n_activity": ["credential_theft"],
        "n_malware_or_tools": ["Lumma"],
    }
    model_bundle = {
        "classifier": FakeClassifier(),
        "embedder": FakeEmbedder(),
        "embedding_model": "fake-embedding",
        "model_path": "fake.joblib",
    }
    config = {
        "classifier_text_fields": ["n_activity", "n_malware_or_tools"],
        "prediction_field": "classifier_predicted_label",
        "status_field": "classification_status",
        "progress_bar": False,
    }
    classified = classify_record(record, model_bundle, config)
    assert classified["classifier_predicted_label"] == "credential-theft-or-infostealer"
    assert classified["classification_status"] == "classified"
    assert classified["classifier_model"] == "fake.joblib"
    assert classified["embedding_model"] == "fake-embedding"


def test_pipeline_stage_output_names_are_aligned():
    normalized = default_jsonl_outpath(
        Path("ctier_semantic_candidates_2026-06-18.jsonl"),
        normalize_ctier.IN_STAGE,
        normalize_ctier.OUT_STAGE,
    )
    classified = default_jsonl_outpath(
        Path("ctier_normalized_2026-06-18.jsonl"),
        classifier_ctier.IN_STAGE,
        classifier_ctier.OUT_STAGE,
    )
    assert normalized.name == "ctier_normalized_2026-06-18.jsonl"
    assert classified.name == "ctier_classified_2026-06-18.jsonl"


def test_default_model_outpath_aliases_linearsvc_to_svc():
    path = default_model_outpath("paraphrase-multilingual-MiniLM-L12-v2", "LinearSVC")
    assert path.name.startswith("cti_svc_miniLM_")
    assert path.suffix == ".joblib"
