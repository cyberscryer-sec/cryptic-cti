from __future__ import annotations

import argparse

from cryptic.yara_check.validator import validate_yara_rules, write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate YARA rules for CTI portfolio workflows")
    parser.add_argument("rule_path", help="Path to a .yar/.yara rule file")
    parser.add_argument("--config", default=None, help="Optional lint config JSON path")
    parser.add_argument("--samples", default=None, help="Optional sample test root")
    parser.add_argument("--json-out", default=None, help="JSON report path")
    parser.add_argument("--md-out", default=None, help="Markdown report path")
    parser.add_argument(
        "--skip-syntax",
        action="store_true",
        help="Run naming/metadata lint without yara-python syntax validation",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        report = validate_yara_rules(
            args.rule_path,
            config_path=args.config,
            sample_root=args.samples,
            run_syntax=not args.skip_syntax,
        )
        json_path, md_path = write_reports(report, args.json_out, args.md_out)
    except Exception as e:
        raise SystemExit(f"YARA validation failed: {e}") from e
    print(f"Wrote YARA validation reports: {json_path}, {md_path}")
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
