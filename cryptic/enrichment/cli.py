from __future__ import annotations

import argparse

from cryptic.enrichment.engine import enrich_file


def parse_providers(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Enrich Cryptic indicators with external CTI APIs")
    parser.add_argument("input_path", help="Input JSONL records with indicators")
    parser.add_argument("--out", required=True, help="Output enriched JSONL path")
    parser.add_argument("--config", default=None, help="Optional enrichment config JSON path")
    parser.add_argument("--providers", default=None, help="Comma-separated provider names")
    parser.add_argument(
        "--offline-cache-only",
        action="store_true",
        help="Use cached provider results only and do not make network calls",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        output_path = enrich_file(
            args.input_path,
            args.out,
            args.config,
            parse_providers(args.providers),
            args.offline_cache_only,
        )
    except Exception as e:
        raise SystemExit(f"Indicator enrichment failed: {e}") from e
    print(f"Wrote enriched records: {output_path}")


if __name__ == "__main__":
    main()
