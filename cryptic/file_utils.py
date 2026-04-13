from pathlib import Path
import json
from cryptic.output.output_objects import Output

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


def latest_matching_file(directory: Path, pattern: str) -> Path:
    matches = [p for p in directory.glob(pattern) if p.is_file()]
    if not matches:
        raise FileNotFoundError(f"No files found matching {pattern} in {directory}")
    return max(matches, key=lambda p: p.stat().st_mtime)


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)
    

def write_json_output(output_obj: Output, output_path: Path | str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output_obj.to_dict(), f, ensure_ascii=False, indent=2)
    return output_path