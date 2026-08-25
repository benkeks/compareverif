#!/usr/bin/env python3
"""Print a tree for ProVerif's labeled, let-drifted intermediate process."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from compareverif.proverif.intermediate_process import extract_let_drifted_process
from compareverif.proverif.libraries import (
    append_library_arguments,
    extract_declared_libraries_from_file,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render ProVerif's labeled, let-drifted intermediate process as a tree."
    )
    parser.add_argument("scenario_file", type=Path, help="ProVerif input file (.pv)")
    parser.add_argument(
        "--proverif", default="proverif", help="ProVerif executable (default: proverif)"
    )
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    scenario_file = args.scenario_file.resolve()
    if not scenario_file.is_file():
        print(f"Scenario file not found: {scenario_file}", file=sys.stderr)
        return 2

    command = [args.proverif]
    append_library_arguments(command, extract_declared_libraries_from_file(scenario_file))
    command.extend(["-test", scenario_file.name])
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=scenario_file.parent,
            check=False,
        )
    except FileNotFoundError:
        print(f"ProVerif executable not found: {args.proverif}", file=sys.stderr)
        return 2

    if result.returncode:
        print(result.stderr or result.stdout, file=sys.stderr, end="")
        return result.returncode

    try:
        process = extract_let_drifted_process(result.stdout)
    except ValueError as error:
        print(f"Could not extract intermediate process: {error}", file=sys.stderr)
        return 1

    print(process.render_tree())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())