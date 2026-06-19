from __future__ import annotations

from cryptic.extraction.base import ExtractionRunner
from cryptic.models.gliner_model import get_gliner_model
from cryptic.preprocessing.chunking import chunk_block_w_offsets, dedupe_entities

model_name = "urchade/gliner_medium-v2.1"

labels = [
    "malware or tool name",
    "credential theft activity",
    "credential or data type",
    "platform or application",
    "actor or group name",
]

def extract_candidates(text: str) -> list[dict]:
    model = get_gliner_model()
    chunks = chunk_block_w_offsets(text)
    # print(f"[extract_candidates] {len(chunks)} chunks | text len={len(text)}")
    all_entities = []
    for chunk in chunks:
        results = model.predict_entities(chunk["text"], labels)
        for result in results:
            all_entities.append({
                "text": result["text"],
                "label": result["label"],
                "score": float(result["score"]),
                "start": chunk["start"] + result["start"],
                "end": chunk["start"] + result["end"]
            })
    return dedupe_entities(all_entities)


class GlinerRunner(ExtractionRunner):
    def __init__(self):
        self.model = get_gliner_model()
        self.labels = labels
    def extract(self, text: str) -> list[dict]:
        return {"gliner_candidates": extract_candidates(text)}

