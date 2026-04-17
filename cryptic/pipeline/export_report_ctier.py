from __future__ import annotations
import sys
from pathlib import Path
from cryptic.file_utils import PROCESSED_DIR, latest_matching_file, read_jsonl, write_text
from cryptic.output.cluster_build import build_clusters
from cryptic.output.summary_build import cluster_to_summary, summary_to_output
from cryptic.output.rendering import outputs_to_md_report


def render_report(
    input_file: Path | str,
    use_llm: bool = False,
    include_indicators: bool = True,
) -> Path:
    input_path = Path(input_file)

    print(f"Loading normalized records from {input_path}", flush=True)
    records = read_jsonl(input_path)

    print(f"Building clusters from {len(records)} records", flush=True)
    clusters = build_clusters(records)

    if use_llm:
        from cryptic.output.llm_text_utils import load_summary_model, llm_summary_text
        tokenizer, model = load_summary_model()
        text_builder = llm_summary_text(tokenizer, model)
    else:
        text_builder = None

    outputs = []

    print(f"Building summary outputs from {len(clusters)} clusters", flush=True)
    for cluster in clusters:
        if text_builder is None:
            summary = cluster_to_summary(cluster)
        else:
            summary = cluster_to_summary(cluster, text_builder=text_builder)
        outputs.append(summary_to_output(summary))

    if include_indicators:
        from cryptic.output.ctier_ioc_build import create_ioc_list, records_iocs

        print("Building indicator-list output", flush=True)
        ioc_items = records_iocs(records)
        if ioc_items:
            outputs.append(create_ioc_list(ioc_items))

    print("Rendering Markdown report", flush=True)
    report_md = outputs_to_md_report(
        outputs,
        title="CTI Collections Report",
        w_toc=True,
    )

    output_path = input_path.with_name(input_path.stem + "_report.md")
    print(f"Writing report to {output_path}", flush=True)
    write_text(output_path, report_md)

    print(f"Done. Generated: {output_path}", flush=True)
    return output_path


def parse_flags(argv: list[str]) -> tuple[bool, bool]:
    use_llm = "-llm" in argv
    include_indicators = "-no-indicators" not in argv
    return use_llm, include_indicators


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

        use_llm, include_indicators = parse_flags(args)
        render_report(input_path, use_llm=use_llm, include_indicators=include_indicators)

    except Exception as e:
        raise SystemExit(f"Report rendering failed: {e}")


if __name__ == "__main__":
    main()