#!/usr/bin/env python3
"""Print a tree for ProVerif's labeled, let-drifted intermediate process."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from compareverif.proverif.intermediate_process import extract_preferred_process
from compareverif.proverif.attack_process import extract_attack_processes
from compareverif.proverif.libraries import (
    append_library_arguments,
    extract_declared_libraries_from_file,
    read_declared_library_sources,
)
from compareverif.proverif.process_structure import UnsupportedProcessStructureError
from compareverif.uppaal import (
    ComplexInputPatternError,
    ConstructorTagOverflowError,
    GlobalNameCountWarning,
    DynamicChannelError,
    InvalidAttackerCostInputError,
    InvalidUppaalPragmaError,
    NestedReplicationError,
    ReservedTranslationNameError,
    TupleDataError,
    UnsupportedConstructorArityError,
    UnsupportedGetConditionError,
    UnsupportedSelectorRuleError,
    contains_replication,
    extract_global_free_names,
    extract_proverif_functions,
    render_channel_skeleton,
    reject_reserved_global_names,
    parse_uppaal_pragmas,
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
    parser.add_argument(
        "--wide-data",
        action="store_true",
        help=(
            "Model UPPAAL `data` as four native 16-bit ints (64 bits total) instead of one "
            "bounded int, using DATA_SHL/DATA_SHR/DATA_OR/DATA_AND helpers for packing."
        ),
    )
    parser.add_argument(
        "--show-attack-processes",
        action="store_true",
        help="Print attacker processes reconstructed from successful ProVerif attack traces",
    )
    parser.add_argument(
        "--show-process",
        action="store_true",
        help="Print ProVerif's parsed intermediate process tree",
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
    if args.show_attack_processes or args.uppaal_out:
        command.extend(["-set", "traceDisplay", "long"])
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
        process = extract_preferred_process(result.stdout)
    except ValueError as error:
        print(f"Could not extract intermediate process: {error}", file=sys.stderr)
        return 1

    if args.show_process:
        print(process.render_tree())

    source = scenario_file.read_text()
    pragmas = parse_uppaal_pragmas(source)
    attack_processes = extract_attack_processes(
        result.stdout,
        source,
        attacker_cost_channel=pragmas.attacker_cost_channel,
    )
    if args.show_attack_processes:
        for attack_process in attack_processes:
            print(f"\nAttack process for query {attack_process.query_number} ({attack_process.query}):")
            print(attack_process.render())

    if contains_replication(process):
        print("Warning: replications will be translated to loops.", file=sys.stderr)

    if args.uppaal_out:
        try:
            declaration_source = "\n".join([*read_declared_library_sources(scenario_file), source])
            reject_reserved_global_names(declaration_source)
            render_channel_skeleton(
                args.uppaal_out,
                process,
                global_free_names=extract_global_free_names(source),
                proverif_functions=extract_proverif_functions(declaration_source),
                attack_processes=attack_processes,
                input_source=declaration_source,
                non_blocking_channels=pragmas.non_blocking_channels,
                time_channels=pragmas.time_channels,
                additional_queries=pragmas.additional_queries,
                table_capacities=pragmas.table_capacities,
                attacker_resources=pragmas.attacker_resources,
                attacker_cost_channel=pragmas.attacker_cost_channel,
                wide_data=args.wide_data or pragmas.data_width == 64,
            )
        except (
            ComplexInputPatternError,
            ConstructorTagOverflowError,
            DynamicChannelError,
            InvalidAttackerCostInputError,
            NestedReplicationError,
            TupleDataError,
            UnsupportedConstructorArityError,
            UnsupportedGetConditionError,
            UnsupportedSelectorRuleError,
            InvalidUppaalPragmaError,
            ReservedTranslationNameError,
            UnsupportedProcessStructureError,
        ) as error:
            print(f"Cannot translate to a static UPPAAL model: {error}", file=sys.stderr)
            return 1
    else:
        print(
            "Warning: no UPPAAL output was generated; provide --uppaal-out <path> to write a model.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())