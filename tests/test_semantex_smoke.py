from __future__ import annotations

import os

import pytest

if not os.environ.get("CRYPTIC_RUN_GLINER_SMOKE"):
    pytest.skip(
        "Set CRYPTIC_RUN_GLINER_SMOKE=1 to run GLiNER model smoke test",
        allow_module_level=True,
    )

from cryptic.extraction.gliner_utils import extract_candidates


def test_gliner_extract_returns_list():
    text = (
        "Vega Stealer can steal login credentials and credit card credentials "
        "from Chrome and Firefox."
    )
    results = extract_candidates(text)
    assert isinstance(results, list)
    if results:
        assert "text" in results[0]
        assert "label" in results[0]
        assert "score" in results[0]
