from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from cryptic.file_utils import read_jsonl
from cryptic.yara_suggest.generator import generate_yara_suggestions, write_yara_suggestions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate conservative draft YARA hunt rules from normalized "
            "Cryptic CTI records"
        )
    )
    parser.add_argument(
        "input_path",
        help="Path to normalized/classified CTI records in JSONL format",
    )
    parser.add_argument("--out", default=None, help="Output .yar path")
    parser.add_argument("--report", default=None, help="Output JSON generation report path")
    parser.add_argument(
        "--date",
        default=None,
        help="Rule metadata date override in YYYY-MM-DD format",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        records = read_jsonl(Path(args.input_path))
        result = generate_yara_suggestions(records, generated_date=args.date)
        rule_path, report_path = write_yara_suggestions(result, args.out, args.report)
    except Exception as e:
        raise SystemExit(f"YARA suggestion failed: {e}") from e
    print(
        "Wrote YARA draft suggestions: "
        f"{rule_path}, {report_path} ({len(result.rules)} rules)"
    )


if __name__ == "__main__":
    main()
