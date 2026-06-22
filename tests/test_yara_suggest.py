from __future__ import annotations

import json
import shutil
from pathlib import Path

from cryptic.file_utils import PROJECT_ROOT, write_jsonl
from cryptic.yara_check.validator import validate_yara_rules
from cryptic.yara_suggest.cli import main as yara_suggest_main
from cryptic.yara_suggest.generator import generate_yara_suggestions, write_yara_suggestions

SCRATCH = PROJECT_ROOT / ".test_yara_suggest_tmp"


def reset_scratch() -> Path:
    shutil.rmtree(SCRATCH, ignore_errors=True)
    SCRATCH.mkdir(parents=True, exist_ok=True)
    return SCRATCH


def sample_records() -> list[dict]:
    return [
        {
            "id": "r1",
            "n_malware_or_tools": ["Lumma Stealer"],
            "n_activity": ["log_sale"],
            "n_data_types": ["cookies"],
            "n_apps": ["Telegram"],
            "indicators": [{"type": "domain", "value": "lumma-demo.example"}],
        },
        {
            "id": "r2",
            "n_malware_or_tools": ["Lumma Stealer"],
            "n_activity": ["credential_theft"],
            "n_data_types": ["browser credentials"],
            "n_apps": ["Chrome"],
            "indicators": [
                {
                    "type": "sha256",
                    "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                }
            ],
        },
    ]


def test_yara_suggestion_generates_validator_compatible_draft_rule():
    scratch = reset_scratch()
    rule_path = scratch / "suggested.yar"
    report_path = scratch / "suggested.json"
    result = generate_yara_suggestions(
        sample_records(),
        generated_date="2026-06-19",
        generated_at="2026-06-19T00:00:00+00:00",
    )
    write_yara_suggestions(result, rule_path, report_path)
    rule_text = rule_path.read_text(encoding="utf-8")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    validation = validate_yara_rules(rule_path, run_syntax=False)
    assert validation.passed
    assert report["rule_count"] == 1
    assert "rule Cryptic_Draft_Lumma_Stealer_Hunt" in rule_text
    assert "status = \"draft\"" in rule_text
    assert "generated_by = \"cryptic-cti\"" in rule_text
    assert "attack.t1555" in rule_text
    assert "2 of ($ioc_*)" in rule_text
    shutil.rmtree(scratch, ignore_errors=True)


def test_yara_suggestion_skips_low_signal_groups():
    result = generate_yara_suggestions(
        [
            {
                "id": "weak",
                "n_malware_or_tools": ["Unknown Tool"],
                "n_activity": ["log_sale"],
                "n_data_types": [],
                "n_apps": [],
                "indicators": [],
            }
        ],
        generated_date="2026-06-19",
    )
    assert result.rules == []
    assert result.skipped[0]["reason"] == "insufficient_signal"
    assert "No rules generated" in result.rules_text


def test_yara_suggest_cli_writes_rule_and_report_files():
    scratch = reset_scratch()
    input_path = scratch / "records.jsonl"
    rule_path = scratch / "suggested.yar"
    report_path = scratch / "suggested.json"
    write_jsonl(input_path, sample_records())
    yara_suggest_main(
        [
            str(input_path),
            "--out",
            str(rule_path),
            "--report",
            str(report_path),
            "--date",
            "2026-06-19",
        ]
    )
    assert rule_path.exists()
    assert report_path.exists()
    assert json.loads(report_path.read_text(encoding="utf-8"))["rule_count"] == 1
    shutil.rmtree(scratch, ignore_errors=True)
