from __future__ import annotations

import argparse

from cryptic.stix_export.exporter import export_stix_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export Cryptic CTI JSONL records as a STIX 2.1 bundle"
    )
    parser.add_argument("input_path", help="Normalized/classified/cluster JSONL input path")
    parser.add_argument("--out", default=None, help="Output STIX bundle path")
    parser.add_argument("--config", default=None, help="Optional STIX export config JSON path")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        output_path = export_stix_bundle(args.input_path, args.out, args.config)
    except Exception as e:
        raise SystemExit(f"STIX export failed: {e}") from e
    print(f"Wrote STIX bundle: {output_path}")


if __name__ == "__main__":
    main()
