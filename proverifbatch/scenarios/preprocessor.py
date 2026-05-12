"""High-level scenario preprocessing orchestrator."""

import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from .models import ScenarioFile, ScenarioResult, AttackerCapability
from .parser import extract_attacker_capabilities
from .generator import (
    generate_scenario_combinations,
    build_scenario_content,
    extract_queries,
    create_scenario_filename,
)
from .analyzer import analyze_minimal_false_combinations
from proverifbatch.common.formatting import print_headline, print_subheading

DEFAULT_PROVERIF_TIMEOUT = 300  # 5 minutes
DEFAULT_TABLE_WIDTH = 60
DEFAULT_LABEL_WIDTH = 37
DEFAULT_COST_COLUMN_WIDTH = 13


class ScenarioPreprocessor:
    """Orchestrator for scenario generation, verification, and analysis."""
    
    def __init__(
        self,
        timeout: int = DEFAULT_PROVERIF_TIMEOUT,
        verbose: bool = False
    ):
        """Initialize the preprocessor.
        
        Args:
            timeout: Timeout for ProVerif execution in seconds
            verbose: Enable detailed logging for generated files and ProVerif status
        """
        self.timeout = timeout
        self.verbose = verbose
    
    def preprocess(
        self,
        input_file: str,
        output_dir: Optional[str] = None
    ) -> Tuple[List[ScenarioFile], Path]:
        """Preprocess a scenario file: extract capabilities, generate combinations.
        
        Args:
            input_file: Path to input .pv file
            output_dir: Output directory (defaults to _scenarios/<stem>)
            
        Returns:
            Tuple[List[ScenarioFile], Path]: Generated scenarios and output directory
        """
        print_headline(f"Processing: {input_file}")
        
        input_path = Path(input_file)
        
        # Default output directory based on input filename
        if output_dir is None:
            output_dir_path = Path('_scenarios') / input_path.stem
        else:
            output_dir_path = Path(output_dir)
        
        # Read the input file
        with open(input_file, 'r') as f:
            content = f.read()
        
        # Extract attacker capabilities from magical comments
        attacker_capabilities, content_chunks = extract_attacker_capabilities(content)
        
        if not attacker_capabilities:
            print("No magical comments for attacker capabilities found")
            return [], output_dir_path
        
        # Create output directory
        output_dir_path.mkdir(parents=True, exist_ok=True)
        
        # Print capabilities table
        self._print_capabilities_table(attacker_capabilities)
        
        # Generate all combinations
        combinations = generate_scenario_combinations(attacker_capabilities)
        
        generated_files = []
        for perm in combinations:
            # Build scenario content
            output_content, attack_variants, total_costs = build_scenario_content(
                perm, attacker_capabilities, content_chunks
            )
            
            # Extract queries
            queries = extract_queries(output_content)
            
            # Create filename
            included_names = [cap.primary_name for i, cap in enumerate(attacker_capabilities) if perm[i] > 0]
            filename = create_scenario_filename(included_names)
            
            output_path = Path(output_dir_path) / f"{filename}.pv"
            
            with open(output_path, 'w') as f:
                f.write(output_content)
            
            generated_files.append(ScenarioFile(
                path=output_path,
                capabilities=attack_variants,
                costs=total_costs,
                queries=queries
            ))
            if self.verbose:
                cost_str = ', '.join(f"{v} {k}" for k, v in total_costs.items()) if total_costs else "no cost"
                print(f"Generated: {output_path} (cost: {cost_str})")
        
        print(f"Total scenarios generated: {len(combinations)}")
        return generated_files, output_dir_path
    
    def run_proverif(self, generated_files: List[ScenarioFile]) -> List[ScenarioResult]:
        """Run ProVerif on all generated files and return results.
        
        Args:
            generated_files: List of scenario files to verify
            
        Returns:
            List[ScenarioResult]: Verification results for each file
        """
        if self.verbose:
            print_headline("Running ProVerif on generated scenarios")
        results: List[ScenarioResult] = []
        
        for file in generated_files:
            if self.verbose:
                print_subheading(f"\nVerifying: {file.path}")
            file_result = ScenarioResult(scenario=file)
            
            try:
                result = subprocess.run(
                    ['proverif', str(file.path)],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout
                )
                
                if result.returncode == 0:
                    file_result.status = 'success'
                else:
                    file_result.status = 'error'
                    error_output = result.stdout or result.stderr
                    file_result.error_message = error_output
                    print(f"✗ Failed: {file.path.name}")
                    print(f"Error output:\n{error_output}")
                
                # Parse ProVerif output for query results
                if result.stdout:
                    result_lines = [line for line in result.stdout.splitlines() if line.startswith("RESULT")]
                    for query, res_line in zip(file.queries, result_lines):
                        query_passed = res_line.endswith("true.")
                        file_result.query_results.append({
                            'tag': query["tag"],
                            'result': query_passed
                        })
                        if self.verbose:
                            value = "✓" if query_passed else "✗"
                            print(f"\t{query['tag']}: {value}")
                else:
                    # No output but success - initialize empty query results
                    for query in file.queries:
                        file_result.query_results.append({
                            'tag': query["tag"],
                            'result': None
                        })
                
            except subprocess.TimeoutExpired:
                file_result.status = 'timeout'
                file_result.error_message = 'Exceeded timeout'
                print(f"⏱ Timeout: {file.path.name} (exceeded {self.timeout} seconds)")
            except FileNotFoundError:
                file_result.status = 'exception'
                file_result.error_message = 'ProVerif command not found'
                print("Error: proverif command not found. Please ensure ProVerif is installed and in PATH.")
                results.append(file_result)
                break
            except Exception as e:
                file_result.status = 'exception'
                file_result.error_message = str(e)
                print(f"Error running proverif on {file.path.name}: {e}")
            
            results.append(file_result)
        
        return results
    
    def analyze(self, results: List[ScenarioResult], input_files: List[str]) -> Dict[str, Dict[str, List[Dict]]]:
        """Analyze results to find minimal breaking combinations.
        
        Args:
            results: Verification results
            input_files: Original input file paths
            
        Returns:
            Analysis results (minimal combinations by file and query)
        """
        return analyze_minimal_false_combinations(results, input_files)
    
    def print_analysis(self, analysis: Dict[str, Dict[str, List[Dict]]]) -> None:
        """Pretty print the analysis results."""
        print_headline("Minimal combinations to break queries")
        
        for input_file, queries in analysis.items():
            print_subheading(f"\nInput File: {input_file}")
            
            for query_tag, minimal_combos in queries.items():
                print(f"  Query: {query_tag}")
                
                if not minimal_combos:
                    print(f"    (No false results found)")
                else:
                    for i, combo in enumerate(minimal_combos, 1):
                        scenarios = combo['scenarios']
                        costs = combo['costs']
                        
                        if scenarios:
                            scenario_str = ", ".join(sorted(scenarios))
                            cost_str = ", ".join(f"{v} {k}" for k, v in sorted(costs.items())) if costs else "no cost"
                            print(f"      {{{scenario_str}}} (cost: {cost_str})")
                        else:
                            print(f"      {{}} (base scenario, no cost)")
    
    @staticmethod
    def _print_capabilities_table(capabilities: List[AttackerCapability]) -> None:
        """Print a formatted table of capabilities and their costs."""
        # Collect all unique cost dimensions
        all_dimensions = set()
        for cap in capabilities:
            for variant in cap.variants:
                all_dimensions.update(variant.costs.keys())
        all_dimensions = sorted(all_dimensions)
        
        if not all_dimensions:
            return
        
        print_subheading("Attacker capabilities with costs", width=DEFAULT_TABLE_WIDTH)
        
        # Header row
        header = "Capability".ljust(DEFAULT_LABEL_WIDTH)
        for cost_dim in all_dimensions:
            header += cost_dim[:11].rjust(DEFAULT_COST_COLUMN_WIDTH)
        print(header)
        print('-' * (DEFAULT_LABEL_WIDTH + len(all_dimensions) * DEFAULT_COST_COLUMN_WIDTH))
        
        # Data rows
        for cap in capabilities:
            for idx, variant in enumerate(cap.variants):
                label = cap.primary_name if idx == 0 else f"  - {variant.name}"
                row = label[:DEFAULT_LABEL_WIDTH - 1].ljust(DEFAULT_LABEL_WIDTH)
                for dimension in all_dimensions:
                    cost = variant.costs.get(dimension, '-')
                    row += str(cost).rjust(DEFAULT_COST_COLUMN_WIDTH)
                print(row)
        print()
