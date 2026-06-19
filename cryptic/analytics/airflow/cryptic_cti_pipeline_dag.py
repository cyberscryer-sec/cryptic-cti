"""
Example Airflow DAG for orchestrating Cryptic CTI commands.

This file is intentionally a lightweight portfolio orchestration stub. It shows how
the pipeline could be scheduled without claiming production Airflow ownership.
"""

from __future__ import annotations

from datetime import datetime

try:
    from airflow import DAG
    from airflow.operators.bash import BashOperator
except ImportError:  # pragma: no cover - this file is documentation unless Airflow is installed.
    DAG = None
    BashOperator = None


if DAG is not None:
    with DAG(
        dag_id="cryptic_cti_pipeline",
        start_date=datetime(2026, 1, 1),
        schedule=None,
        catchup=False,
        tags=["cti", "portfolio", "cryptic"],
    ) as dag:
        run_pipeline = BashOperator(
            task_id="run_pipeline",
            bash_command="cryptic data/corpus/ctier",
        )
        export_stix = BashOperator(
            task_id="export_stix",
            bash_command="cryptic-stix-export data/processed/ctier_classified_*.jsonl",
        )
        load_analytics = BashOperator(
            task_id="load_analytics",
            bash_command="cryptic-analytics-load",
        )

        run_pipeline >> export_stix >> load_analytics
