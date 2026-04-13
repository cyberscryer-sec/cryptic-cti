from pathlib import Path
import sys
from cryptic.file_utils import default_jsonl_outpath, latest_matching_file, read_jsonl, write_jsonl, PROCESSED_DIR
from cryptic.output.clustering import build_clusters


IN_STAGE = "ctier_normalized"
OUT_STAGE = "ctier_clusters"

def export_clusters(input_path: Path, output_path: Path) -> None:
    records = read_jsonl(input_path)
    clusters = build_clusters(records)
    write_jsonl(output_path, [cluster.to_dict() for cluster in clusters])
    print(f"Wrote {len(clusters)} clusters to {output_path}")


def main() -> None:
    try:
        if len(sys.argv) > 1:
            input_path = Path(sys.argv[1])
        else:
            input_path = latest_matching_file(PROCESSED_DIR, "ctier_normalized_*.jsonl")
        if not input_path.is_file():
            print(f"No valid input file found.")
            sys.exit(1)
        output_path = default_jsonl_outpath(input_path, IN_STAGE, OUT_STAGE)
        export_clusters(input_path, output_path)
    except Exception as e:
        raise SystemExit(f"Cluster export failed: {e}") from e


if __name__ == "__main__":
    main()