import csv
import json
from pathlib import Path
from cryptic.output.output_obj import Output
from cryptic.output.out_utils import write_ioc_dict_rows


def outputobj_to_json(output_obj: Output, output_path: Path | str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(output_obj.to_dict(), f, ensure_ascii=False, indent=2)
    return output_path


def outputobj_to_csv(output_obj: Output, output_path: Path | str) -> Path:
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    rows = write_ioc_dict_rows(output_obj)
    fieldnames = [
        "indicator_type",
        "value",
        "sourced_from",
        "confidence",
        "tags",
        "first_seen",
        "last_seen",
        "valid_til",
        "is_detection_ioc"]
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return output_path