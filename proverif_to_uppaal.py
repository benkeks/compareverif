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
from compareverif.proverif.process_structure import UnsupportedProcessStructureError
from compareverif.uppaal import (
    ComplexInputPatternError,
    DynamicChannelError,
    NestedReplicationError,
    TupleDataError,
    extract_global_free_names,
    render_channel_skeleton,
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render ProVerif's labeled, let-drifted intermediate process as a tree."
    )
    parser.add_argument("scenario_file", type=Path, help="ProVerif input file (.pv)")
    parser.add_argument(
        "--proverif", default="proverif", help="ProVerif executable (default: proverif)"
    )
    parser.add_argument(
        "--uppaal-out",
        type=Path,
        help="Write a blank UPPAAL model declaring the process's channels to this file",
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

    if args.uppaal_out:
        try:
            render_channel_skeleton(
                args.uppaal_out,
                process,
                global_free_names=extract_global_free_names(scenario_file.read_text()),
            )
        except (
            ComplexInputPatternError,
            DynamicChannelError,
            NestedReplicationError,
            TupleDataError,
            UnsupportedProcessStructureError,
        ) as error:
            print(f"Cannot translate to a static UPPAAL model: {error}", file=sys.stderr)
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())