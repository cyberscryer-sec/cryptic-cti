from __future__ import annotations
import os
import warnings 

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
# warnings.filterwarnings("ignore", category=UserWarning)
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"

import sys
from pathlib import Path
import uuid

from cryptic.pipeline.metadata_ctier import run_metadata_parser
from cryptic.pipeline.semantex_ctier import run_semantex
from cryptic.pipeline.classifier_ctier import run_classifier
from cryptic.pipeline.normalize_ctier import run_normalizer


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS_DIR = PROJECT_ROOT / "data" / "corpus" / "ctier"
RUN_ID = uuid.uuid4().hex[:8]

def run_ctier_pipeline(input_dir: Path | str) -> Path:
    input_dir = Path(input_dir)
    print(f"{RUN_ID}=== Stage 1: metadata parsing ===", flush=True)
    parsed_path = run_metadata_parser(input_dir)
    print(f"{RUN_ID}=== Stage 2: semantic extraction ===", flush=True)
    semantic_path = run_semantex(parsed_path)
    print(f"{RUN_ID}=== Stage 3: classification ===", flush=True)
    classified_path = run_classifier(semantic_path)
    print(f"{RUN_ID}=== Stage 4: normalization ===", flush=True)
    normalized_path = run_normalizer(classified_path)
    print(f"{RUN_ID}Pipeline complete. Final output: {normalized_path}", flush=True)
    return normalized_path


def main() -> None:
    input_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CORPUS_DIR
    run_ctier_pipeline(input_dir)


if __name__ == "__main__":
    main()