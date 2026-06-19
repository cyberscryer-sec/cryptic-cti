from cryptic.file_utils import PROJECT_ROOT
from cryptic.normalization.canonicalize import canonicalize_value, load_variant_map, track_unmapped
from cryptic.normalization.norm_utils import dedupe_preserve_order, normalize_key

MAPPINGS_DIR = PROJECT_ROOT / "cryptic" / "normalization" / "mappings"

MALWARE_TOOL_LOOKUP = load_variant_map(MAPPINGS_DIR / "malware_tools.json")
ACTIVITY_LOOKUP = load_variant_map(MAPPINGS_DIR / "activities.json")
DATA_TYPE_LOOKUP = load_variant_map(MAPPINGS_DIR / "data_types.json")
PLATFORM_LOOKUP = load_variant_map(MAPPINGS_DIR / "apps.json")

LABEL_CONFIG = {
    "credential theft activity": {
        "lookup": ACTIVITY_LOOKUP,
        "output_field": "n_activity",
    },
    "malware or tool name": {
        "lookup": MALWARE_TOOL_LOOKUP,
        "output_field": "n_malware_or_tools",
    },
    "credential or data type": {
        "lookup": DATA_TYPE_LOOKUP,
        "output_field": "n_data_types",
    },
    "platform or application": {
        "lookup": PLATFORM_LOOKUP,
        "output_field": "n_apps",
    },
}


def normalize_candidates(record: dict) -> dict:
    candidates = record.get("gliner_candidates") or []
    if not isinstance(candidates, list):
        raise TypeError("gliner_candidates must be a list")
    unmapped = []
    normed_fields = {config["output_field"]: [] for config in LABEL_CONFIG.values()}
    normed_meta = {config["output_field"]: {} for config in LABEL_CONFIG.values()}
    for item in candidates:
        text = (item.get("text") or "").strip()
        label = normalize_key(item.get("label") or "")
        raw_score = item.get("score")
        if not text:
            continue
        config = LABEL_CONFIG.get(label)
        if not config:
            continue
        normalized, matched = canonicalize_value(text, config["lookup"])
        out_field = config["output_field"]
        normed_fields[out_field].append(normalized)
        score = float(raw_score) if raw_score is not None else None
        current = normed_meta[out_field].get(normalized)
        support= {"raw_text": text, "raw_label": label, "score": score}
        if current is None:
            normed_meta[out_field][normalized] = {"best_score": score, "supports": [support]}
        else:
            current["supports"].append(support)
            current_best = current.get("best_score")
            if score is not None and (current_best is None or score > current_best):
                current["best_score"] = score
        if not matched:
            track_unmapped(text, label, out_field)
            unmapped.append((label, text))
    enriched = dict(record)
    for field, values in normed_fields.items():
        enriched[field] = dedupe_preserve_order(values)
    enriched["unmapped"] = dedupe_preserve_order(unmapped)
    enriched["norm_status"] = "normalized"
    enriched["meta"] = normed_meta
    return enriched