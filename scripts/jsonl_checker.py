import json
from pathlib import Path

path = Path("data/processed/ctier_labelled_records.jsonl")

with path.open("r", encoding="utf-8") as f:
    for i, line in enumerate(f, start=1):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            json.loads(line)
        except json.JSONDecodeError as e:
            print(f"Bad line: {i}")
            print(f"Error: {e}")
            print(line[:1000])
            break