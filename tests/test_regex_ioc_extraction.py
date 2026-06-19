from __future__ import annotations

from cryptic.extraction.engine import ExtractionEngine
from cryptic.extraction.regex_utils import RegexRunner, extract_indicators
from cryptic.output.cluster_build import is_overlap
from cryptic.output.ctier_ioc_build import record_to_indicators
from cryptic.pipeline.semantex_ctier import enrich_record
from cryptic.stix_export.exporter import records_to_stix_bundle


def by_type(indicators: list[dict], indicator_type: str) -> set[str]:
    return {item["value"] for item in indicators if item["type"] == indicator_type}


def test_regex_extracts_and_refangs_common_iocs():
    text = (
        "Panel hxxps://bad[.]example/login resolved to 8.8.8.8 and "
        "2001:4860:4860::8888. Contact ops@example.com. "
        "MD5 d41d8cd98f00b204e9800998ecf8427e "
        "SHA1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
        "SHA256 e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855."
    )
    indicators = extract_indicators(text)
    assert "https://bad.example/login" in by_type(indicators, "url")
    assert "bad.example" in by_type(indicators, "domain")
    assert "8.8.8.8" in by_type(indicators, "ipv4")
    assert "2001:4860:4860::8888" in by_type(indicators, "ipv6")
    assert "ops@example.com" in by_type(indicators, "email")
    assert "d41d8cd98f00b204e9800998ecf8427e" in by_type(indicators, "md5")
    assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" in by_type(indicators, "sha1")
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        in by_type(indicators, "sha256")
    )
    url_indicator = next(item for item in indicators if item["type"] == "url")
    assert url_indicator["raw_value"] == "hxxps://bad[.]example/login"


def test_regex_avoids_obvious_ipv4_false_positives_and_dedupes():
    indicators = extract_indicators("Version 999.2.3.4 is invalid, but 8.8.8.8 and 8.8.8.8 are.")
    assert by_type(indicators, "ipv4") == {"8.8.8.8"}


def test_extraction_engine_merges_existing_and_regex_indicators():
    engine = ExtractionEngine.__new__(ExtractionEngine)
    engine.runners = {"regex": RegexRunner()}
    record = {
        "raw_text": "Visit hxxp://evil[.]example",
        "indicators": [{"type": "ipv4", "value": "8.8.8.8", "confidence": 70}],
    }
    result = engine.run(record)
    assert "8.8.8.8" in by_type(result["indicators"], "ipv4")
    assert "http://evil.example" in by_type(result["indicators"], "url")


def test_semantex_preserves_indicators_from_engine():
    class FakeEngine:
        def run(self, record):
            return {
                "spacy": {"lang": "en"},
                "gliner_candidates": [],
                "indicators": [{"type": "domain", "value": "bad.example"}],
            }

    enriched = enrich_record({"id": "r1", "raw_text": "bad.example"}, FakeEngine())
    assert enriched["indicators"] == [{"type": "domain", "value": "bad.example"}]


def test_record_indicators_feed_outputs_cluster_overlap_and_stix():
    record = {
        "id": "r1",
        "source": "demo",
        "indicators": [{"type": "domain", "value": "bad.example", "confidence": 90}],
        "n_data_types": ["credentials"],
        "meta": {"n_data_types": {"credentials": {"best_score": 0.9, "supports": [{}]}}},
    }
    indicators = record_to_indicators(record)
    assert {item.type for item in indicators} >= {"domain", "credential_or_data_type"}
    assert is_overlap(
        record,
        {
            "id": "r2",
            "source": "demo",
            "indicators": [{"type": "domain", "value": "bad.example"}],
        },
    )
    bundle = records_to_stix_bundle([record])
    assert any(obj["type"] == "indicator" for obj in bundle["objects"])
