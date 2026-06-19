from __future__ import annotations

import argparse

from cryptic.stix_ingest.adapter import ingest_stix_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ingest STIX bundle objects as Cryptic records")
    parser.add_argument("bundle", help="STIX bundle JSON URL or local file")
    parser.add_argument("--out", required=True, help="Output JSONL path")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        output_path = ingest_stix_bundle(args.bundle, args.out)
    except Exception as e:
        raise SystemExit(f"STIX ingestion failed: {e}") from e
    print(f"Wrote STIX records: {output_path}")


if __name__ == "__main__":
    main()
