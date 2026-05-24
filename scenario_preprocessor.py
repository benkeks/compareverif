#!/usr/bin/env python3
"""Scenario preprocessing CLI tool for generating scenario combinations from ProVerif files and running verification."""

import argparse
import sys
import json
from pathlib import Path

from proverifbatch.scenarios import (
    ScenarioPreprocessor,
    build_manifest_scenario_entry,
)
from proverifbatch.common.formatting import print_headline

DEFAULT_TABLE_WIDTH = 60


def main() -> None:
    """Main entry point for scenario preprocessing."""
    parser = argparse.ArgumentParser(
        description=(
            "Generate scenario combinations from ProVerif files and run verification "
            "for each generated scenario."
        )
    )
    parser.add_argument(
        "input_files",
        nargs="+",
        help="Input .pv files to preprocess"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show generated-file list and detailed ProVerif status output"
    )
    parser.add_argument(
        "--check-all-scenarios",
        action="store_true",
        help="Generate and verify every capability-variant combination instead of using monotone search"
    )
    args = parser.parse_args()

    input_files = args.input_files
    all_generated_scenarios = []
    file_to_output_dir = {}
    preprocessor = ScenarioPreprocessor(
        verbose=args.verbose,
        check_all_scenarios=args.check_all_scenarios,
    )
    
    # Preprocess each input file
    for input_file in input_files:
        if not Path(input_file).exists():
            print(f"Error: File '{input_file}' not found")
            continue
        
        generated_scenarios, output_dir = preprocessor.preprocess(input_file)
        all_generated_scenarios.extend(generated_scenarios)
        file_to_output_dir[input_file] = output_dir
    
    # Run ProVerif on all generated files
    if file_to_output_dir:
        results = preprocessor.run_proverif(all_generated_scenarios)

        stats = preprocessor.get_execution_stats()
        print_headline("Scenario generation summary")
        print(f"Scenario files generated: {stats.generated_files}")
        print(f"ProVerif runs executed: {stats.proverif_runs}")
        
        # Dump manifests for each input file
        for input_file, output_dir in file_to_output_dir.items():
            scenarios = preprocessor.get_generated_scenarios(input_file)
            _dump_manifest(scenarios, results, output_dir, input_file, verbose=args.verbose)
        
        # Analyze and print minimal combinations
        analysis = preprocessor.analyze(results, input_files)
        preprocessor.print_analysis(analysis)


def _dump_manifest(
    generated_files,
    results,
    output_dir: Path,
    input_file: str,
    verbose: bool = False
) -> None:
    """Dump a manifest JSON file with information about all generated scenarios.
    
    Args:
        generated_files: List of generated scenario files
        results: List of verification results
        output_dir: Directory where manifest should be written
        input_file: Original input file name
    """
    manifest = {
        'input_file': str(input_file),
        'generated_at': None,
        'scenarios': []
    }
    
    results_map = {
        str(result.scenario.path): result
        for result in results
    }
    
    for scenario_file in generated_files:
        result = results_map.get(str(scenario_file.path))
        manifest['scenarios'].append(build_manifest_scenario_entry(scenario_file, result))
    
    # Write manifest
    manifest_path = output_dir / 'manifest.json'
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)

    if verbose:
        print(f"\nManifest written to: {manifest_path}")
        print(f"  Total scenarios: {len(manifest['scenarios'])}")
        successful = sum(1 for s in manifest['scenarios']
                        if s.get('verification', {}).get('status') == 'success')
        print(f"  Verified successfully: {successful}/{len(manifest['scenarios'])}")


if __name__ == '__main__':
    main()
