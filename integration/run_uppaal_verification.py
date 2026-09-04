#!/usr/bin/env python3
"""Intentionally run ProVerif-to-UPPAAL translation and UPPAAL verification.

This script is independent of pytest because it requires a local UPPAAL installation.
Edit VERIFYTA and SCENARIO_FILES for another machine or scenario selection.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from xml.etree import ElementTree as ET


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VERIFYTA = Path("~/Software/uppaal-5.0.0-linux64/bin/verifyta")
SHOW_VERIFYTA_OUTPUT = False
VERIFYTA_TIMEOUT_SECONDS = 3 * 60
SCENARIO_FILES = [
    Path("examples/proverif-ex/handshake.pv"),
    Path("examples/proverif-ex/nicolas_many_attacks.pv"),
    Path("examples/simple_ratchet_static.pv"),
    Path("examples/hashed_passwords_static.pv"),
    Path("examples/singularized_passwords_static.pv"),
]


@dataclass
class QueryResult:
    """The result and elapsed time of one verifyta query."""

    index: int
    formula: str
    stdout: str
    stderr: str
    returncode: int | None
    elapsed_seconds: float
    satisfied: bool
    timed_out: bool


def main() -> int:
    verifyta = VERIFYTA.expanduser().resolve()
    if not verifyta.is_file():
        print(f"verifyta binary not found: {verifyta}", file=sys.stderr)
        return 2

    failures = 0
    with tempfile.TemporaryDirectory(prefix="compareverif-uppaal-") as temporary_directory:
        output_directory = Path(temporary_directory)
        for scenario_file in SCENARIO_FILES:
            scenario_path = (REPOSITORY_ROOT / scenario_file).resolve()
            model_path = output_directory / f"{scenario_file.stem}.xml"
            print(f"\n=== {scenario_file} ===")
            translation = subprocess.run(
                [sys.executable, "proverif_to_uppaal.py", "--uppaal-out", str(model_path), str(scenario_file)],
                cwd=REPOSITORY_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            if translation.stdout:
                print("Translation output:")
                print(translation.stdout, end="" if translation.stdout.endswith("\n") else "\n")
            if translation.stderr:
                print("Translation warnings/errors:", file=sys.stderr)
                print(translation.stderr, file=sys.stderr, end="" if translation.stderr.endswith("\n") else "\n")
            if translation.returncode:
                print(f"Translation failed with exit code {translation.returncode}.", file=sys.stderr)
                failures += 1
                continue

            queries = [
                formula.text or ""
                for formula in ET.parse(model_path).getroot().findall("./queries/query/formula")
            ]
            if not queries:
                print("No UPPAAL queries generated.")
            query_results: list[QueryResult] = []
            for index, formula in enumerate(queries, start=1):
                query_path = output_directory / f"{scenario_file.stem}-query-{index}.q"
                query_path.write_text(f"{formula}\n")
                started_at = time.perf_counter()
                try:
                    verification = subprocess.run(
                        [str(verifyta), str(model_path), str(query_path)],
                        cwd=REPOSITORY_ROOT,
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=VERIFYTA_TIMEOUT_SECONDS,
                    )
                    elapsed_seconds = time.perf_counter() - started_at
                    query_results.append(
                        QueryResult(
                            index=index,
                            formula=formula,
                            stdout=verification.stdout,
                            stderr=verification.stderr,
                            returncode=verification.returncode,
                            elapsed_seconds=elapsed_seconds,
                            satisfied=verification.returncode == 0 and "Formula is satisfied." in verification.stdout,
                            timed_out=False,
                        )
                    )
                except subprocess.TimeoutExpired as error:
                    elapsed_seconds = time.perf_counter() - started_at
                    query_results.append(
                        QueryResult(
                            index=index,
                            formula=formula,
                            stdout=error.stdout or "",
                            stderr=error.stderr or "",
                            returncode=None,
                            elapsed_seconds=elapsed_seconds,
                            satisfied=False,
                            timed_out=True,
                        )
                    )

            if all(result.satisfied for result in query_results):
                for result in query_results:
                    print(f"Query {result.index}: {result.formula} - satisfied ({result.elapsed_seconds:.2f}s)")
                    if SHOW_VERIFYTA_OUTPUT:
                        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
                        if result.stderr:
                            print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
                continue

            failures += 1
            for result in query_results:
                if result.satisfied:
                    continue
                print(f"\nQuery {result.index}: {result.formula} ({result.elapsed_seconds:.2f}s)", file=sys.stderr)
                if result.timed_out:
                    print(f"verifyta timed out after {VERIFYTA_TIMEOUT_SECONDS} seconds.", file=sys.stderr)
                if result.stdout:
                    print(result.stdout, file=sys.stderr, end="" if result.stdout.endswith("\n") else "\n")
                if result.stderr:
                    print(result.stderr, file=sys.stderr, end="" if result.stderr.endswith("\n") else "\n")
                if result.returncode:
                    print(f"verifyta failed with exit code {result.returncode}.", file=sys.stderr)

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())