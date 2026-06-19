from __future__ import annotations

import argparse

from cryptic.rss_ingest.adapter import ingest_feed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ingest RSS/Atom CTI feed items as Cryptic records"
    )
    parser.add_argument("feed", help="RSS/Atom feed URL or local XML file")
    parser.add_argument("--out", required=True, help="Output JSONL path")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        output_path = ingest_feed(args.feed, args.out)
    except Exception as e:
        raise SystemExit(f"RSS ingestion failed: {e}") from e
    print(f"Wrote RSS records: {output_path}")


if __name__ == "__main__":
    main()
