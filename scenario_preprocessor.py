#!/usr/bin/env python3
"""Scenario preprocessing CLI - refactored version using modular architecture."""

import sys
import json
from pathlib import Path

from src.scenarios import ScenarioPreprocessor
from src.common.formatting import print_headline

DEFAULT_TABLE_WIDTH = 60


def main() -> None:
    """Main entry point for scenario preprocessing."""
    if len(sys.argv) < 2:
        print("Usage: python scenario_preprocessor.py <input_file1.pv> [input_file2.pv ...]")
        print("Example: python scenario_preprocessor.py hashed_passwords.pv singularized_passwords.pv")
        sys.exit(1)
    
    input_files = sys.argv[1:]
    all_generated_scenarios = []
    file_to_scenarios = {}
    preprocessor = ScenarioPreprocessor()
    
    # Preprocess each input file
    for input_file in input_files:
        if not Path(input_file).exists():
            print(f"Error: File '{input_file}' not found")
            continue
        
        generated_scenarios, output_dir = preprocessor.preprocess(input_file)
        all_generated_scenarios.extend(generated_scenarios)
        file_to_scenarios[input_file] = (generated_scenarios, output_dir)
    
    # Run ProVerif on all generated files
    if all_generated_scenarios:
        results = preprocessor.run_proverif(all_generated_scenarios)
        
        # Dump manifests for each input file
        for input_file, (scenarios, output_dir) in file_to_scenarios.items():
            _dump_manifest(scenarios, results, output_dir, input_file)
        
        # Analyze and print minimal combinations
        analysis = preprocessor.analyze(results, input_files)
        preprocessor.print_analysis(analysis)


def _dump_manifest(
    generated_files,
    results,
    output_dir: Path,
    input_file: str
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
    
    # Create results lookup
    results_map = {}
    for result in results:
        results_map[str(result.scenario.path)] = result
    
    for scenario_file in generated_files:
        scenario_info = {
            'file': str(scenario_file.path.name),
            'path': str(scenario_file.path),
            'capabilities': [
                {
                    'name': variant.name,
                    'costs': variant.costs
                }
                for variant in scenario_file.capabilities
            ],
            'total_costs': scenario_file.costs,
            'queries': [
                {
                    'tag': query['tag'],
                    'query': query['query']
                }
                for query in scenario_file.queries
            ]
        }
        
        # Add verification results if available
        result = results_map.get(str(scenario_file.path))
        if result:
            scenario_info['verification'] = {
                'status': result.status,
                'query_results': [
                    {
                        'tag': qr['tag'],
                        'result': qr['result']
                    }
                    for qr in result.query_results
                ],
                'error_message': result.error_message
            }
        
        manifest['scenarios'].append(scenario_info)
    
    # Write manifest
    manifest_path = output_dir / 'manifest.json'
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    
    print(f"\nManifest written to: {manifest_path}")
    print(f"  Total scenarios: {len(manifest['scenarios'])}")
    successful = sum(1 for s in manifest['scenarios'] 
                    if s.get('verification', {}).get('status') == 'success')
    print(f"  Verified successfully: {successful}/{len(manifest['scenarios'])}")


if __name__ == '__main__':
    main()
