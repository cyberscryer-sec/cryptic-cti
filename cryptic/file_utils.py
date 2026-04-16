from pathlib import Path
import json
from cryptic.output.output_obj import Output


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
CORPUS_DIR = DATA_DIR / "corpus"
PROCESSED_DIR = DATA_DIR / "processed"
OUTPUT_DIR = DATA_DIR / "output"


def default_jsonl_outpath(input_path: Path, in_stage: str, out_stage: str) -> Path:
    if in_stage in input_path.name:
        output_name = input_path.name.replace(in_stage, out_stage)
    else:
        output_name = f"{input_path.stem}_{out_stage}{input_path.suffix}"
    return input_path.with_name(output_name)


def default_json_outpath(input_path: Path, in_stage: str, output: Output) -> Path:
    if in_stage in input_path.name:
        output_name = input_path.name.replace(in_stage, f"{output.producer}_{output.type}")
    else:
        output_name = f"{input_path.stem}_{output.producer}_{output.type}.json"
    return input_path.with_name(output_name).with_suffix(".json")


def default_csv_outpath(json_output_path: Path) -> Path:
    return json_output_path.with_suffix(".csv")


def latest_matching_file(directory: Path, pattern: str) -> Path:
    matches = [p for p in directory.glob(pattern) if p.is_file()]
    if not matches:
        raise FileNotFoundError(f"No files found matching {pattern} in {directory}")
    return max(matches, key=lambda p: p.stat().st_mtime)


def write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            json_line = json.dumps(record, ensure_ascii=False)
            f.write(json_line + "\n")


def read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSONL in {path} at line {line_no}: {e}") from e
    return rows


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
    

