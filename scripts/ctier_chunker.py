from __future__ import annotations

import re
import sys
from datetime import date
from hashlib import sha256
from pathlib import Path

import spacy

import cryptic.extraction.spacy_utils as sputils
from cryptic.file_utils import write_jsonl

out_path = Path(f"data/processed/ctier_chunks_{date.today()}.jsonl")

_nlp = None


def get_nlp():
    global _nlp
    if _nlp is None:
        _nlp = spacy.load("en_core_web_sm")
    return _nlp


def iter_path(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return [f for f in sorted(path.glob("*")) if f.is_file()]
    raise ValueError(f"Path does not exist or is not usable: {path}")


def find_id_hint(text: str) -> str | None:
    m = re.search(r"(?:^|\s|\[|\()(\d{2,6}):", text)
    return m.group(1) if m else None


def split_on_ids(text: str) -> list[str]:
    pattern = r"(?=(?:^|\n)\s*(?:\[\s*)?[\"']?\d{2,6}:)"
    parts = re.split(pattern, text, flags=re.MULTILINE)
    parts = [p.strip() for p in parts if p.strip()]
    return parts if len(parts) > 1 else [text.strip()]


def sentence_chunks(text: str, target_chars: int = 900, overlap_sentences: int = 1) -> list[str]:
    nlp = get_nlp()
    doc = nlp(text)
    sentences = [sent.text.strip() for sent in doc.sents if sent.text.strip()]
    if not sentences:
        stripped = text.strip()
        return [stripped] if stripped else []
    chunks: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(sentences):
        current = []
        current_len = 0
        start_i = i
        while i < len(sentences):
            sentence = sentences[i]
            projected = current_len + len(sentence) + (1 if current else 0)
            if current and projected > target_chars:
                break
            current.append(sentence)
            current_len = projected
            i += 1
        chunk = " ".join(current).strip()
        if chunk:
            chunks.append(chunk)
        if i >= len(sentences):
            break
        i = max(start_i + 1, i - overlap_sentences)
    return chunks


def char_chunks(text: str, target_chars: int = 900, overlap_chars: int = 150) -> list[str]:
    text = text.strip()
    if not text:
        return []
    chunks = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + target_chars, n)
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= n:
            break
        start = max(end - overlap_chars, start + 1)
    return chunks


def chunk_block(block: str) -> list[str]:
    block = block.strip()
    if not block:
        return []
    if len(block) <= 1200:
        return [block]
    try:
        return sentence_chunks(block, target_chars=900, overlap_sentences=1)
    except Exception as e:
        print(f"Error during sentence chunking: {e}")
        return char_chunks(block, target_chars=900, overlap_chars=150)


def build_chunk_id(source_file: Path, chunk_index: int) -> str:
    record_name = source_file.name.replace(".", "")
    return f"{record_name}_chunk_{chunk_index:04d}"


def chunk_raw_ctier(raw_dir: Path) -> list[dict]:
    records: list[dict] = []
    for f in iter_path(raw_dir):
        if not f.is_file():
            continue
        print(f"Reading {f.name} ...")
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"Error reading {f.name}: {e}")
            continue
        blocks = split_on_ids(text)
        print(f"{f.name}: {len(blocks)} coarse blocks")
        chunk_index = 0
        for block in blocks:
            chunks = chunk_block(block)
            for chunk in chunks:
                chunk_index += 1
                records.append(
                    {
                        "id": build_chunk_id(f, chunk_index),
                        "source": "ctier",
                        "source_file": f.name,
                        "chunk_index": chunk_index,
                        "chunk_method": "id_split_then_chunking",
                        "source_record_id": find_id_hint(chunk),
                        "language": sputils.detect_lang(chunk),
                        "raw_text": chunk,
                        "content_hash": sha256(chunk.encode("utf-8")).hexdigest(),
                    }
                )
        print(f"{f.name}: emitted {chunk_index} chunks")
    return records


def main() -> None:
    if len(sys.argv) > 1:
        raw_dir = Path(sys.argv[1])
    else:
        raise ValueError("Enter raw CTIER file/directory as a command-line argument.")
    records = chunk_raw_ctier(raw_dir)
    write_jsonl(out_path, records)
    print(f"Wrote {len(records)} chunks to {out_path}")


if __name__ == "__main__":
    main()

