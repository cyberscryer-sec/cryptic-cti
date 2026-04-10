from __future__ import annotations
import sys
from pathlib import Path
from cryptic.file_utils import latest_matching_file, load_json, read_jsonl, write_jsonl
from cryptic.normalization.utils import normalize_key, normalize_value, dedupe_preserve_order

PROJECT_ROOT = Path(__file__).resolve().parents[1]  # adjust as needed based on your repository structure
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
NORMALIZATION_DIR = PROJECT_ROOT / "data" / "normalization"

MALWARE_TOOL_NORMALIZATION = load_json(NORMALIZATION_DIR / "malware_tools.json")
ACTIVITY_NORMALIZATION = load_json(NORMALIZATION_DIR / "activities.json")
DATA_TYPE_NORMALIZATION = load_json(NORMALIZATION_DIR / "data_types.json")
PLATFORM_NORMALIZATION = load_json(NORMALIZATION_DIR / "apps.json")

LABEL_CONFIG = {
    "malware or tool name": {
        "mapping": MALWARE_TOOL_NORMALIZATION,
        "output_field": "n_malware_or_tools",
    },
    "credential theft activity": {
        "mapping": ACTIVITY_NORMALIZATION,
        "output_field": "n_activity",
    },
    "credential or data type": {
        "mapping": DATA_TYPE_NORMALIZATION,
        "output_field": "n_credential_or_data_types",
    },
    "platform or application": {
        "mapping": PLATFORM_NORMALIZATION,
        "output_field": "n_apps",
    },
}


def default_output_path(input_path: Path) -> Path:
    if "ctier_classified" in input_path.name:
        output_name = input_path.name.replace("ctier_classified", "ctier_normalized")
    else:
        output_name = f"{input_path.stem}_normalized{input_path.suffix}"
    return input_path.with_name(output_name)


def normalize_candidates(record: dict) -> dict:
    candidates = record.get("gliner_candidates") or []
    if not isinstance(candidates, list):
        raise TypeError("gliner_candidates must be a list")

    unmapped = []
    normalized_fields = {
        config["output_field"]: []
        for config in LABEL_CONFIG.values()
    }
    for item in candidates:
        text = (item.get("text") or "").strip()
        label = normalize_key(item.get("label") or "")
        if not text:
            continue

        config = LABEL_CONFIG.get(label)
        if not config:
            continue
        normalized, matched = normalize_value(text, config["mapping"])
        normalized_fields[config["output_field"]].append(normalized)
        if not matched:
            unmapped.append((label, text))

    enriched = dict(record)
    for field, values in normalized_fields.items():
        enriched[field] = dedupe_preserve_order(values)
    enriched["unmapped"] = dedupe_preserve_order(unmapped)
    enriched["norm_status"] = "normalized"

    return enriched


def run_normalizer(i: Path, o: Path | None = None) -> Path:
    print(f"[run_normalizer] START input={i}", flush=True)
    input_path = Path(i)
    output_path = Path(o) if o is not None else default_output_path(input_path)
    print(f"Normalizing {input_path} ...")
    records = read_jsonl(input_path)
    normalized_rows = []
    for i, record in enumerate(records, start=1):
        try:
            normalized_rows.append(normalize_candidates(record))
        except Exception as e:
            failed = dict(record)
            failed["norm_status"] = f"error: {e}"
            normalized_rows.append(failed)
        if i % 25 == 0:
            print(f"Processed {i}/{len(records)} records")
    write_jsonl(output_path, normalized_rows)
    print(f"Wrote {len(normalized_rows)} records to {output_path}")
    return output_path

def main() -> None:
    if len(sys.argv) > 1:
        input_path = Path(sys.argv[1])
    else:
        input_path = latest_matching_file(PROCESSED_DIR, "ctier_classified*.jsonl")
    run_normalizer(input_path)
    

if __name__ == "__main__":
    main()