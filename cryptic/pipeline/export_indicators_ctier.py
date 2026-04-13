from __future__ import annotations
import sys
from pathlib import Path
from cryptic.output.ctier_ioc_builder import create_ioc_list, records_iocs
from cryptic.file_utils import latest_matching_file, default_json_outpath, default_csv_outpath, read_jsonl, outputobj_to_json, PROCESSED_DIR
from cryptic.output.out_utils import write_ioc_csv


def parse_flags(argv: list[str]) -> list[str]:
    allowed_flags = {"-json", "-csv"}
    flags: list[str] = []
    for arg in argv:
        if arg in allowed_flags:
            flags.append(arg)
    return flags


def export_iocs(input_file: Path | str, flag_list: list[str]) -> tuple[Path, ...]:
    input_path = Path(input_file)
    allowed_flags = {"-csv", "-json"}
    invalid_flags = [f for f in flag_list if f not in allowed_flags]
    if invalid_flags:
        raise ValueError(f"Invalid flags: {invalid_flags}. Use: {allowed_flags}")
    flags = set(flag_list)
    if not flags:
        json_out = True # Default behavior: JSON only
        csv_out = False
    else:
        json_out = "-json" in flags
        csv_out = "-csv" in flags
    out_paths = []
    print(f"Loading normalized records from {input_path}", flush=True)
    n_records = read_jsonl(input_path)
    print(f"Building IOC items from {len(n_records)} records", flush=True)
    ioc_items = records_iocs(n_records)
    print(f"Creating IOC output artifact", flush=True)
    output_obj = create_ioc_list(ioc_items)
    json_output_path = default_json_outpath(input_path, "ctier_normalized", output_obj)
    csv_output_path = default_csv_outpath(json_output_path)
    if json_out:
        print(f"Writing JSON output to {json_output_path}", flush=True)
        outputobj_to_json(output_obj, json_output_path)
        out_paths.append(json_output_path)
    if csv_out:
        print(f"Writing CSV output to {csv_output_path}", flush=True)
        write_ioc_csv(output_obj, csv_output_path)
        out_paths.append(csv_output_path)
    print(
        f"Done. Generated: {out_paths}", flush=True)
    return tuple(out_paths)


def main() -> None:
    try:
        args = sys.argv[1:]
        input_path = None
        for arg in args:
            if not arg.startswith("-"):
                input_path = Path(arg)
                break
        if input_path is None:
            input_path = latest_matching_file(PROCESSED_DIR, "ctier_normalized*.jsonl")
        flags = parse_flags(args)
        export_iocs(input_path, flags)
    except Exception as e:
        raise SystemExit(f"IOC export failed: {e}")


if __name__ == "__main__":
    main()