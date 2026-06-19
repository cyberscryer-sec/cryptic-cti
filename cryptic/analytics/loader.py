from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from cryptic.file_utils import PROJECT_ROOT

DEFAULT_ANALYTICS_CONFIG = Path(__file__).resolve().parent / "config.json"
SQL_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def resolve_project_path(path: str | Path) -> Path:
    path = Path(path)
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def load_analytics_config(path: str | Path | None = None) -> dict[str, Any]:
    config_path = Path(path) if path is not None else DEFAULT_ANALYTICS_CONFIG
    with config_path.open("r", encoding="utf-8") as f:
        config = json.load(f)
    required = {"input_glob", "duckdb_path", "records_table"}
    missing = required - set(config)
    if missing:
        raise ValueError(f"Analytics config missing required keys: {sorted(missing)}")
    config["duckdb_path"] = str(resolve_project_path(config["duckdb_path"]))
    return config


def load_records_to_duckdb(config: dict[str, Any]) -> Path:
    table = str(config["records_table"])
    if not SQL_IDENTIFIER_RE.match(table):
        raise ValueError(f"Invalid DuckDB table name: {table!r}")
    try:
        import duckdb  # type: ignore[import-not-found]
    except ImportError as e:
        raise RuntimeError("Install cryptic-cti[analytics] to load DuckDB analytics tables") from e
    input_glob = str(resolve_project_path(config["input_glob"]))
    db_path = Path(config["duckdb_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db_path))
    try:
        con.execute(
            f"""
            CREATE OR REPLACE TABLE {table} AS
            SELECT *
            FROM read_json_auto(?, union_by_name=true)
            """,
            [input_glob],
        )
    finally:
        con.close()
    return db_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Load Cryptic CTI JSONL output into DuckDB")
    parser.add_argument("--config", default=None, help="Analytics config JSON path")
    parser.add_argument("--input-glob", default=None, help="Override input JSONL glob")
    parser.add_argument("--duckdb-path", default=None, help="Override DuckDB output path")
    parser.add_argument("--table", default=None, help="Override records table name")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        config = load_analytics_config(args.config)
        if args.input_glob:
            config["input_glob"] = args.input_glob
        if args.duckdb_path:
            config["duckdb_path"] = str(resolve_project_path(args.duckdb_path))
        if args.table:
            config["records_table"] = args.table
        db_path = load_records_to_duckdb(config)
    except Exception as e:
        raise SystemExit(f"Analytics load failed: {e}") from e
    print(f"Loaded CTI records into DuckDB: {db_path}")


if __name__ == "__main__":
    main()
