from __future__ import annotations
import sys
from pathlib import Path
from cryptic.file_utils import default_jsonl_outpath, latest_matching_file, load_json, read_jsonl, write_jsonl, PROJECT_ROOT, PROCESSED_DIR
from cryptic.normalization.norm_utils import normalize_key, normalize_value, dedupe_preserve_order


MAPPINGS_DIR = PROJECT_ROOT / "cryptic" / "normalization" / "mappings"

MALWARE_TOOL_NORMALIZATION = load_json(MAPPINGS_DIR / "malware_tools.json")
ACTIVITY_NORMALIZATION = load_json(MAPPINGS_DIR / "activities.json")
DATA_TYPE_NORMALIZATION = load_json(MAPPINGS_DIR / "data_types.json")
PLATFORM_NORMALIZATION = load_json(MAPPINGS_DIR / "apps.json")

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

IN_STAGE = "ctier_classified"
OUT_STAGE = "ctier_normalized"

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
    output_path = Path(o) if o is not None else default_jsonl_outpath(input_path, IN_STAGE, OUT_STAGE)
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