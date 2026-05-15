from __future__ import annotations
import spacy
import re

from cryptic.extraction.base import ExtractionRunner

nlp = spacy.load("en_core_web_sm")

def has_chinese(text: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", text))

def has_latin(text: str) -> bool:
    return bool(re.search(r"[A-Za-z]", text))

def detect_lang(text: str) -> str:
    zh = has_chinese(text)
    en = has_latin(text)
    if zh and not en:
        return "zh"
    elif en and not zh:
        return "en"
    elif zh and en:
        return "mixed"
    return "unknown"

def spacy_prepare(text: str) -> dict:
    doc = nlp(text)
    sentences = list(doc.sents)
    return {"lang": detect_lang(text), "sentence_count": len(sentences), "token_count": len(doc), "sentences": [sent.text.strip() for sent in sentences if sentences]}


class SpacyRunner(ExtractionRunner):
    def extract(self, text: str) -> dict:
        return spacy_prepare(text)