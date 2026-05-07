from __future__ import annotations
import sys
from pathlib import Path
from scripts.run_ctier_pipeline import run_ctier_pipeline

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CORPUS_DIR = PROJECT_ROOT / "data" / "corpus" / "ctier"


def main() -> None:
    """
    Root entry point for cryptic-cti workflows.

    Current supported workflow:
    - ctier pipeline
    """
    input_dir = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else DEFAULT_CORPUS_DIR
    )
    run_ctier_pipeline(input_dir)


if __name__ == "__main__":
    main()