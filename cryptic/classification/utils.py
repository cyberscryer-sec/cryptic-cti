from __future__ import annotations
from pathlib import Path
from sentence_transformers import SentenceTransformer

MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"
model = SentenceTransformer(MODEL_NAME)


def embed_texts(texts: list[str]):
    return model.encode(texts)

