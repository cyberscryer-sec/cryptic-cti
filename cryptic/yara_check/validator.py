from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptic.file_utils import OUTPUT_DIR, PROJECT_ROOT

DEFAULT_YARA_CONFIG = Path(__file__).resolve().parent / "configs" / "default_yara_lint.json"


@dataclass(slots=True)
class CheckFinding:
    level: str
    code: str
    message: str
    file: str = ""
    rule: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "file": self.file,
            "rule": self.rule,
        }


@dataclass(slots=True)
class YaraValidationReport:
    rule_path: str
    passed: bool
    checks: list[dict[str, Any]]
    findings: list[CheckFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_path": self.rule_path,
            "passed": self.passed,
            "checks": self.checks,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def resolve_project_path(path: str | Path) -> Path:
    path = Path(path)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def load_yara_lint_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path is not None else DEFAULT_YARA_CONFIG
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    required_keys = {
        "required_metadata",
        "rule_name_regex",
        "attack_tag_regex",
        "require_attack_tag",
        "positive_dir",
        "negative_dir",
    }
    missing = required_keys - set(config)
    if missing:
        raise ValueError(f"YARA lint config missing required keys: {sorted(missing)}")
    return config


def parse_rule_blocks(rule_text: str) -> list[dict[str, Any]]:
    rule_re = re.compile(
        r"rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*(?P<tags>[^{]+))?\s*\{(?P<body>.*?)\}",
        re.DOTALL,
    )
    meta_re = re.compile(
        r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*="
        r"\s*(?P<value>\"[^\"]*\"|\d+|true|false)"
    )
    blocks: list[dict[str, Any]] = []
    for match in rule_re.finditer(rule_text):
        body = match.group("body")
        meta_text = ""
        meta_match = re.search(r"meta\s*:(?P<meta>.*?)(?:strings|condition)\s*:", body, re.DOTALL)
        if meta_match:
            meta_text = meta_match.group("meta")
        metadata = {
            m.group("key"): m.group("value").strip('"') for m in meta_re.finditer(meta_text)
        }
        tags = (match.group("tags") or "").split()
        blocks.append({"name": match.group("name"), "tags": tags, "metadata": metadata})
    return blocks


def validate_yara_syntax(rule_path: Path) -> list[CheckFinding]:
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError("Install cryptic-cti[yara] to enable YARA syntax validation") from e
    try:
        yara.compile(filepath=str(rule_path))
    except Exception as e:  # yara-python raises its own error classes.
        return [
            CheckFinding(
                level="error",
                code="syntax_error",
                message=str(e),
                file=str(rule_path),
            )
        ]
    return []


def lint_rule_structure(
    rule_text: str,
    rule_path: Path,
    config: dict[str, Any],
) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    blocks = parse_rule_blocks(rule_text)
    if not blocks:
        return [
            CheckFinding(
                level="error",
                code="no_rules_found",
                message="No YARA rule blocks were found",
                file=str(rule_path),
            )
        ]
    name_re = re.compile(str(config["rule_name_regex"]))
    attack_re = re.compile(str(config["attack_tag_regex"]))
    required_metadata = list(config["required_metadata"])
    for block in blocks:
        rule_name = block["name"]
        if not name_re.match(rule_name):
            findings.append(
                CheckFinding(
                    level="error",
                    code="bad_rule_name",
                    message=f"Rule name does not match {config['rule_name_regex']}",
                    file=str(rule_path),
                    rule=rule_name,
                )
            )
        metadata = block["metadata"]
        for key in required_metadata:
            if key not in metadata or not str(metadata[key]).strip():
                findings.append(
                    CheckFinding(
                        level="error",
                        code="missing_metadata",
                        message=f"Missing required metadata field: {key}",
                        file=str(rule_path),
                        rule=rule_name,
                    )
                )
        tags = block["tags"]
        attack_tags = [tag for tag in tags if attack_re.match(tag)]
        if config.get("require_attack_tag") and not attack_tags:
            findings.append(
                CheckFinding(
                    level="error",
                    code="missing_attack_tag",
                    message="Rule must include at least one ATT&CK tag such as attack.t1059",
                    file=str(rule_path),
                    rule=rule_name,
                )
            )
    return findings


def iter_sample_files(sample_dir: Path) -> list[Path]:
    if not sample_dir.exists():
        return []
    return [p for p in sample_dir.rglob("*") if p.is_file()]


def run_sample_checks(
    rule_path: Path,
    sample_root: Path,
    config: dict[str, Any],
) -> list[CheckFinding]:
    try:
        import yara  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError("Install cryptic-cti[yara] to enable sample testing") from e
    rules = yara.compile(filepath=str(rule_path))
    findings: list[CheckFinding] = []
    positive_dir = sample_root / str(config["positive_dir"])
    negative_dir = sample_root / str(config["negative_dir"])
    for sample in iter_sample_files(positive_dir):
        matches = rules.match(str(sample))
        if not matches:
            findings.append(
                CheckFinding(
                    level="error",
                    code="positive_sample_missed",
                    message=f"Expected at least one match for positive sample {sample}",
                    file=str(sample),
                )
            )
    for sample in iter_sample_files(negative_dir):
        matches = rules.match(str(sample))
        if matches:
            findings.append(
                CheckFinding(
                    level="error",
                    code="negative_sample_matched",
                    message=f"Expected no matches for negative sample {sample}",
                    file=str(sample),
                )
            )
    return findings


def validate_yara_rules(
    rule_path: str | Path,
    config_path: str | Path | None = None,
    sample_root: str | Path | None = None,
    run_syntax: bool = True,
) -> YaraValidationReport:
    rule_path = resolve_project_path(rule_path)
    config = load_yara_lint_config(config_path)
    rule_text = rule_path.read_text(encoding="utf-8")
    findings: list[CheckFinding] = []
    checks: list[dict[str, Any]] = []
    if run_syntax:
        syntax_findings = validate_yara_syntax(rule_path)
        findings.extend(syntax_findings)
        checks.append({"name": "syntax", "passed": not syntax_findings})
    structure_findings = lint_rule_structure(rule_text, rule_path, config)
    findings.extend(structure_findings)
    checks.append({"name": "metadata_and_conventions", "passed": not structure_findings})
    if sample_root is not None:
        sample_findings = run_sample_checks(rule_path, resolve_project_path(sample_root), config)
        findings.extend(sample_findings)
        checks.append({"name": "samples", "passed": not sample_findings})
    passed = not any(finding.level == "error" for finding in findings)
    return YaraValidationReport(str(rule_path), passed, checks, findings)


def render_markdown_report(report: YaraValidationReport) -> str:
    status = "PASS" if report.passed else "FAIL"
    lines = [
        f"# YARA Validation Report: {status}",
        "",
        f"- Rule path: `{report.rule_path}`",
        f"- Findings: {len(report.findings)}",
        "",
        "## Checks",
    ]
    for check in report.checks:
        check_status = "PASS" if check["passed"] else "FAIL"
        lines.append(f"- {check['name']}: {check_status}")
    if report.findings:
        lines.extend(["", "## Findings"])
        for finding in report.findings:
            target = f" ({finding.rule})" if finding.rule else ""
            lines.append(f"- [{finding.level}] {finding.code}{target}: {finding.message}")
    return "\n".join(lines) + "\n"


def write_reports(
    report: YaraValidationReport,
    output_json: str | Path | None = None,
    output_md: str | Path | None = None,
) -> tuple[Path, Path]:
    json_path = Path(output_json) if output_json else OUTPUT_DIR / "yara_validation_report.json"
    md_path = Path(output_md) if output_md else OUTPUT_DIR / "yara_validation_report.md"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.parent.mkdir(parents=True, exist_ok=True)
    with json_path.open("w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    return json_path, md_path
