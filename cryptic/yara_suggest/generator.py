from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptic.file_utils import OUTPUT_DIR

DEFAULT_RULE_PATH = OUTPUT_DIR / "suggested_yara_rules.yar"
DEFAULT_REPORT_PATH = OUTPUT_DIR / "suggested_yara_rules.json"
DEFAULT_ATTACK_TAGS = ["attack.t1555"]
CONTEXT_FIELDS = ["n_malware_or_tools", "n_activity", "n_data_types", "n_apps"]
TECHNICAL_INDICATOR_TYPES = {
    "domain",
    "email",
    "ipv4",
    "ipv6",
    "md5",
    "sha1",
    "sha256",
    "url",
}


@dataclass(slots=True)
class YaraDraftRule:
    rule_name: str
    threat_name: str
    record_ids: list[str]
    attack_tags: list[str]
    indicators: list[dict[str, str]]
    context_values: list[str]
    condition: str
    generated_date: str
    status: str = "draft"

    def to_report_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "threat_name": self.threat_name,
            "record_ids": self.record_ids,
            "attack_tags": self.attack_tags,
            "indicator_count": len(self.indicators),
            "context_count": len(self.context_values),
            "condition": self.condition,
            "status": self.status,
        }


@dataclass(slots=True)
class YaraSuggestionResult:
    rules_text: str
    rules: list[YaraDraftRule] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    input_record_count: int = 0
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "input_record_count": self.input_record_count,
            "rule_count": len(self.rules),
            "rules": [rule.to_report_dict() for rule in self.rules],
            "skipped": self.skipped,
        }


def utc_date() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def dedupe_preserve_order(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for value in values:
        key = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def clean_signal_value(value: Any) -> str:
    cleaned = " ".join(str(value or "").strip().split())
    if len(cleaned) > 160:
        cleaned = cleaned[:160].rstrip()
    return cleaned


def yara_string_literal(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def metadata_string(value: Any) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', "'").replace("\n", " ").strip()


def rule_slug(value: str) -> str:
    parts = re.findall(r"[A-Za-z0-9]+", value)
    if not parts:
        return "Unknown"
    slug = "_".join(part[:1].upper() + part[1:] for part in parts)
    return slug[:56].strip("_") or "Unknown"


def rule_name_for(threat_name: str) -> str:
    return f"Cryptic_Draft_{rule_slug(threat_name)}_Hunt"


def record_ids(records: list[dict[str, Any]]) -> list[str]:
    ids = [str(record.get("id", "")).strip() for record in records if record.get("id")]
    return dedupe_preserve_order(ids)


def group_records_by_malware(
    records: list[dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    skipped: list[dict[str, Any]] = []
    for record in records:
        malware_values = []
        for value in record.get("n_malware_or_tools", []):
            cleaned = clean_signal_value(value)
            if cleaned:
                malware_values.append(cleaned)
        if not malware_values:
            skipped.append(
                {
                    "record_id": record.get("id", ""),
                    "reason": "missing_n_malware_or_tools",
                }
            )
            continue
        for malware in malware_values:
            groups.setdefault(malware, []).append(record)
    return groups, skipped


def collect_indicators(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    for record in records:
        for item in record.get("indicators", []):
            if not isinstance(item, dict):
                continue
            indicator_type = str(item.get("type", "")).strip().lower()
            value = clean_signal_value(item.get("value", ""))
            if indicator_type not in TECHNICAL_INDICATOR_TYPES or len(value) < 4:
                continue
            indicators.append({"type": indicator_type, "value": value})
    return dedupe_preserve_order(indicators)


def collect_context(records: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for record in records:
        for context_field in CONTEXT_FIELDS:
            field_values = record.get(context_field, [])
            if not isinstance(field_values, list):
                continue
            values.extend(clean_signal_value(value) for value in field_values)
    return [value for value in dedupe_preserve_order(values) if len(value) >= 3]


def choose_condition(
    indicators: list[dict[str, str]],
    context_values: list[str],
    records: list[dict[str, Any]],
) -> str | None:
    if len(indicators) >= 2:
        return "2 of ($ioc_*)"
    if len(indicators) == 1 and context_values:
        return "$ioc_001 and any of ($ctx_*)"
    if len(indicators) == 0 and len(context_values) >= 3 and len(records) >= 2:
        return "2 of ($ctx_*)"
    return None


def attack_tags_for(context_values: list[str]) -> list[str]:
    normalized = {value.lower() for value in context_values}
    tags = list(DEFAULT_ATTACK_TAGS)
    if "cookies" in normalized or "browser credentials" in normalized:
        tags.append("attack.t1539")
    return dedupe_preserve_order(tags)


def render_rule(rule: YaraDraftRule) -> str:
    tags = " ".join(dedupe_preserve_order(rule.attack_tags + ["cryptic", "draft", "hunt"]))
    lines = [
        f"rule {rule.rule_name} : {tags}",
        "{",
        "    meta:",
        (
            "        description = "
            + yara_string_literal(
                f"Draft hunt rule for {rule.threat_name} indicators from cryptic-cti records"
            )
        ),
        '        author = "cryptic-cti"',
        f"        date = {yara_string_literal(rule.generated_date)}",
        f"        threat_name = {yara_string_literal(metadata_string(rule.threat_name))}",
        '        status = "draft"',
        '        generated_by = "cryptic-cti"',
        f"        record_ids = {yara_string_literal(','.join(rule.record_ids))}",
        "    strings:",
    ]
    for index, indicator in enumerate(rule.indicators, start=1):
        lines.append(
            f"        $ioc_{index:03d} = {yara_string_literal(indicator['value'])} nocase"
        )
    for index, value in enumerate(rule.context_values, start=1):
        lines.append(f"        $ctx_{index:03d} = {yara_string_literal(value)} nocase")
    lines.extend(
        [
            "    condition:",
            f"        {rule.condition}",
            "}",
        ]
    )
    return "\n".join(lines)


def render_rules_file(rules: list[YaraDraftRule]) -> str:
    header = [
        "// Generated by cryptic-cti.",
        "// Status: draft hunt rules for analyst review.",
        "// These rules are not production detection logic.",
    ]
    if not rules:
        header.append(
            "// No rules generated because no record group met the minimum signal threshold."
        )
        return "\n".join(header) + "\n"
    rules_body = "\n\n".join(render_rule(rule) for rule in rules)
    return "\n".join(header) + "\n\n" + rules_body + "\n"


def generate_yara_suggestions(
    records: list[dict[str, Any]],
    generated_date: str | None = None,
    generated_at: str | None = None,
) -> YaraSuggestionResult:
    generated_date = generated_date or utc_date()
    generated_at = generated_at or utc_timestamp()
    groups, skipped = group_records_by_malware(records)
    rules: list[YaraDraftRule] = []
    for malware, group in sorted(groups.items()):
        indicators = collect_indicators(group)
        context_values = collect_context(group)
        condition = choose_condition(indicators, context_values, group)
        if condition is None:
            skipped.append(
                {
                    "group": malware,
                    "record_ids": record_ids(group),
                    "reason": "insufficient_signal",
                    "indicator_count": len(indicators),
                    "context_count": len(context_values),
                }
            )
            continue
        rules.append(
            YaraDraftRule(
                rule_name=rule_name_for(malware),
                threat_name=malware,
                record_ids=record_ids(group),
                attack_tags=attack_tags_for(context_values),
                indicators=indicators,
                context_values=context_values,
                condition=condition,
                generated_date=generated_date,
            )
        )
    rules_text = render_rules_file(rules)
    return YaraSuggestionResult(
        rules_text=rules_text,
        rules=rules,
        skipped=skipped,
        input_record_count=len(records),
        generated_at=generated_at,
    )


def write_yara_suggestions(
    result: YaraSuggestionResult,
    rule_path: str | Path | None = None,
    report_path: str | Path | None = None,
) -> tuple[Path, Path]:
    rule_path = Path(rule_path) if rule_path else DEFAULT_RULE_PATH
    report_path = Path(report_path) if report_path else DEFAULT_REPORT_PATH
    rule_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    rule_path.write_text(result.rules_text, encoding="utf-8")
    with report_path.open("w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
    return rule_path, report_path
