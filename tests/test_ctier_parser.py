import shutil
from pathlib import Path

from cryptic.pipeline.metadata_ctier import parse_corpus


def write_batch(corpus_dir: Path, batch_name: str, entries: list[str]) -> Path:
    batch_file = corpus_dir / batch_name
    joined = "\n\n".join(f"-----\n{entry.strip()}" for entry in entries)
    batch_file.write_text(joined, encoding="utf-8")
    return batch_file


def test_batch_read():
    scratch = Path(".test_ctier_parser_tmp")
    try:
        corpus_dir = scratch / "corpus"
        corpus_dir.mkdir(parents=True)
        write_batch(
            corpus_dir,
            "batch.1",
            [
                '3356: Proofpoint observed a spear-phishing campaign spreading Vega Stealer.',
                (
                    """['11345: "follow.user steals data and credentials"', """
                    """[['follow.user', [1, 2], 'MW']]]"""
                ),
            ],
        )
        records = parse_corpus(corpus_dir=corpus_dir)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    assert len(records) == 2
    assert records[0]["id"] == "ctier_batch1_001"
    assert records[0]["source"] == "ctier"
    assert records[0]["source_file"] == "batch.1"
    assert records[0]["entry_index"] == 1
    assert records[0]["format"] == "text_block"
    assert records[1]["id"] == "ctier_batch1_002"
    assert records[1]["format"] == "nested_list"
    assert records[1]["source_file"] == "batch.1"
    assert records[1]["entry_index"] == 2
