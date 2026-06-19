import pytest

from cryptic.pipeline.metadata_ctier import build_record_id, detect_format, split_entries

sample = """
-----
entry one

-----
entry two

-----
entry three
"""


def test_detect_format_nested_list():
    entry = """['3356: "Vega Stealer..."', [['Vega Stealer', [10, 12], 'MW']]]"""
    assert detect_format(entry) == "nested_list"


def test_detect_format_text_block():
    entry = "3356: Proofpoint observed a spear-phishing campaign spreading Vega Stealer."
    assert detect_format(entry) == "text_block"


def test_detect_format_empty_raises():
    with pytest.raises(ValueError):
        detect_format("   ")


def test_split_entries_basic():
    text = sample
    entries = split_entries(text)
    assert entries == ["entry one", "entry two", "entry three"]


def test_split_entries_ignores_empty_blocks():
    text = sample + "\n-----\n   \n-----\n"
    entries = split_entries(text)
    assert entries == ["entry one", "entry two", "entry three"]


def test_build_record_id():
    from pathlib import Path
    record_id = build_record_id("ctier", Path("data/corpus/batch.1"), 3)
    assert record_id == "ctier_batch1_003"