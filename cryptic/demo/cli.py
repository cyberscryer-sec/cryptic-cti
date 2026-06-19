from __future__ import annotations

import argparse

from cryptic.demo.runner import run_demo


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a fast deterministic Cryptic CTI demo")
    parser.add_argument("--sample", default="infostealer", help="Bundled demo sample name")
    parser.add_argument("--out", default=None, help="Output directory for demo artifacts")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        output_dir = run_demo(args.sample, args.out)
    except Exception as e:
        raise SystemExit(f"Cryptic demo failed: {e}") from e
    print(f"Cryptic demo artifacts written to: {output_dir}")


if __name__ == "__main__":
    main()
