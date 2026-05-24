"""High-level scenario preprocessing orchestrator."""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Set
from .models import ScenarioFile, ScenarioResult, AttackerCapability
from .parser import extract_attacker_capabilities
from .generator import (
    generate_capability_presence_combinations,
    generate_base_capability_presence_combination,
    generate_full_capability_presence_combination,
    generate_scenario_combinations,
    generate_support_scenario_combinations,
    build_scenario_content,
    extract_queries,
    create_scenario_filename,
)
from .analyzer import analyze_minimal_false_combinations
from .serialization import format_costs
from proverifbatch.common.formatting import print_headline, print_subheading

DEFAULT_PROVERIF_TIMEOUT = 300  # 5 minutes
DEFAULT_TABLE_WIDTH = 60
DEFAULT_LABEL_WIDTH = 37
DEFAULT_COST_COLUMN_WIDTH = 13


@dataclass
class PreparedScenarioInput:
    """Parsed input file ready for eager or lazy scenario generation."""

    input_file: str
    output_dir: Path
    capabilities: List[AttackerCapability]
    content_chunks: List[Optional[str]]


@dataclass
class ScenarioExecutionStats:
    """Simple counters for generated files and executed ProVerif runs."""

    generated_files: int = 0
    proverif_runs: int = 0


class ScenarioPreprocessor:
    """Orchestrator for scenario generation, verification, and analysis."""
    
    def __init__(
        self,
        timeout: int = DEFAULT_PROVERIF_TIMEOUT,
        verbose: bool = False,
        check_all_scenarios: bool = False,
    ):
        """Initialize the preprocessor.
        
        Args:
            timeout: Timeout for ProVerif execution in seconds
            verbose: Enable detailed logging for generated files and ProVerif status
            check_all_scenarios: When True, eagerly generate and verify every
                capability-variant combination instead of using monotone search
        """
        self.timeout = timeout
        self.verbose = verbose
        self.check_all_scenarios = check_all_scenarios
        self._prepared_inputs: Dict[str, PreparedScenarioInput] = {}
        self._generated_files: Dict[str, Dict[Tuple[int, ...], ScenarioFile]] = {}
        self._result_cache: Dict[Tuple[str, Tuple[int, ...]], ScenarioResult] = {}
        self._stats = ScenarioExecutionStats()
    
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
        
        prepared_input = PreparedScenarioInput(
            input_file=input_file,
            output_dir=output_dir_path,
            capabilities=attacker_capabilities,
            content_chunks=content_chunks,
        )
        self._prepared_inputs[input_file] = prepared_input
        self._generated_files[input_file] = {}

        if self.check_all_scenarios:
            combinations = generate_scenario_combinations(attacker_capabilities)
            for combination in combinations:
                self._get_or_create_scenario(prepared_input, combination)
            print(f"Total scenarios generated: {len(combinations)}")
        else:
            combinations = generate_capability_presence_combinations(attacker_capabilities)
            for combination in generate_support_scenario_combinations(attacker_capabilities):
                self._get_or_create_scenario(prepared_input, combination)
            if self.verbose:
                print(
                    "Scenario files will be generated lazily during monotone verification "
                    f"search (up to {len(combinations)} snippet combinations)."
                )

        return self.get_generated_scenarios(input_file), output_dir_path
    
    def run_proverif(self, generated_files: List[ScenarioFile]) -> List[ScenarioResult]:
        """Run ProVerif on all generated files and return results.
        
        Args:
            generated_files: List of scenario files to verify
            
        Returns:
            List[ScenarioResult]: Verification results for each file
        """
        if self.verbose:
            print_headline("Running ProVerif on generated scenarios")

        if not self.check_all_scenarios:
            return self._run_proverif_with_monotone_search()

        return self._run_proverif_on_files(generated_files)

    def get_generated_scenarios(self, input_file: str) -> List[ScenarioFile]:
        """Return the scenarios generated so far for an input file."""
        generated = self._generated_files.get(input_file, {})
        return list(generated.values())

    def get_execution_stats(self) -> ScenarioExecutionStats:
        """Return the current generation and execution counters."""
        return ScenarioExecutionStats(
            generated_files=self._stats.generated_files,
            proverif_runs=self._stats.proverif_runs,
        )

    def _run_proverif_on_files(self, generated_files: List[ScenarioFile]) -> List[ScenarioResult]:
        """Run ProVerif on an explicit list of scenario files."""
        results: List[ScenarioResult] = []
        
        for file in generated_files:
            file_result = self._run_proverif_for_file(file)
            results.append(file_result)

            key = self._find_result_cache_key(file)
            if key is not None:
                self._result_cache[key] = file_result

        return results

    def _run_proverif_with_monotone_search(self) -> List[ScenarioResult]:
        """Run ProVerif lazily on boolean snippet combinations only."""
        for prepared_input in self._prepared_inputs.values():
            capability_count = len(prepared_input.capabilities)
            if capability_count == 0:
                continue

            base_combination = generate_base_capability_presence_combination(prepared_input.capabilities)
            full_combination = generate_full_capability_presence_combination(prepared_input.capabilities)

            base_result = self._evaluate_combination(prepared_input, base_combination)
            full_result = self._evaluate_combination(prepared_input, full_combination)
            query_count = min(len(base_result.query_results), len(full_result.query_results))

            for query_index in range(query_count):
                if self._query_is_false(base_result, query_index):
                    continue
                if not self._query_is_false(full_result, query_index):
                    continue

                self._search_minimal_failures(
                    prepared_input,
                    full_combination,
                    query_index,
                    minimal_failures=set(),
                    visited=set(),
                )

        return list(self._result_cache.values())

    def _search_minimal_failures(
        self,
        prepared_input: PreparedScenarioInput,
        combination: Tuple[int, ...],
        query_index: int,
        minimal_failures: Set[Tuple[int, ...]],
        visited: Set[Tuple[int, ...]],
    ) -> None:
        """Enumerate subset-minimal failures for one query via downward search."""
        if combination in visited:
            return
        if any(self._is_subset(minimal, combination) for minimal in minimal_failures):
            return

        visited.add(combination)
        result = self._evaluate_combination(prepared_input, combination)
        if not self._query_is_false(result, query_index):
            return

        failing_children = []
        for index, enabled in enumerate(combination):
            if not enabled:
                continue

            child = combination[:index] + (0,) + combination[index + 1:]
            if any(self._is_subset(minimal, child) for minimal in minimal_failures):
                continue

            child_result = self._evaluate_combination(prepared_input, child)
            if self._query_is_false(child_result, query_index):
                failing_children.append(child)

        if not failing_children:
            minimal_failures.add(combination)
            return

        for child in failing_children:
            self._search_minimal_failures(
                prepared_input,
                child,
                query_index,
                minimal_failures,
                visited,
            )

    def _evaluate_combination(
        self,
        prepared_input: PreparedScenarioInput,
        combination: Tuple[int, ...],
    ) -> ScenarioResult:
        """Generate and verify one boolean snippet combination exactly once."""
        cache_key = (prepared_input.input_file, combination)
        if cache_key in self._result_cache:
            return self._result_cache[cache_key]

        scenario_file = self._get_or_create_scenario(prepared_input, combination)
        result = self._run_proverif_for_file(scenario_file)
        self._result_cache[cache_key] = result
        return result

    def _get_or_create_scenario(
        self,
        prepared_input: PreparedScenarioInput,
        combination: Tuple[int, ...],
    ) -> ScenarioFile:
        """Create a scenario file for a combination if it does not exist yet."""
        cached_scenarios = self._generated_files.setdefault(prepared_input.input_file, {})
        if combination in cached_scenarios:
            return cached_scenarios[combination]

        use_primary_variants_only = not self.check_all_scenarios
        output_content, attack_variants, total_costs = build_scenario_content(
            combination,
            prepared_input.capabilities,
            prepared_input.content_chunks,
            use_primary_variants_only=use_primary_variants_only,
        )
        queries = extract_queries(output_content)
        included_names = [
            cap.primary_name
            for index, cap in enumerate(prepared_input.capabilities)
            if combination[index] > 0
        ]
        filename = create_scenario_filename(included_names)
        output_path = prepared_input.output_dir / f"{filename}.pv"

        with open(output_path, 'w') as handle:
            handle.write(output_content)

        scenario_file = ScenarioFile(
            path=output_path,
            capabilities=attack_variants,
            costs=total_costs,
            queries=queries,
            capability_names=included_names,
        )
        cached_scenarios[combination] = scenario_file
        self._stats.generated_files += 1

        if self.verbose:
            print(f"Generated: {output_path} (cost: {format_costs(total_costs)})")

        return scenario_file

    def _run_proverif_for_file(self, file: ScenarioFile) -> ScenarioResult:
        """Run ProVerif for a single scenario file."""
        if self.verbose:
            print_subheading(f"\nVerifying: {file.path}")

        file_result = ScenarioResult(scenario=file)

        try:
            self._stats.proverif_runs += 1
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
        except Exception as e:
            file_result.status = 'exception'
            file_result.error_message = str(e)
            print(f"Error running proverif on {file.path.name}: {e}")

        return file_result

    @staticmethod
    def _query_is_false(result: ScenarioResult, query_index: int) -> bool:
        """Return True only for explicit false query outcomes."""
        if query_index >= len(result.query_results):
            return False
        return result.query_results[query_index].get('result') is False

    @staticmethod
    def _is_subset(left: Tuple[int, ...], right: Tuple[int, ...]) -> bool:
        """Return whether one boolean combination is a subset of another."""
        return all(left_value <= right_value for left_value, right_value in zip(left, right))

    def _find_result_cache_key(self, file: ScenarioFile) -> Optional[Tuple[str, Tuple[int, ...]]]:
        """Map a generated scenario back to its cached input/combination key."""
        for input_file, combinations in self._generated_files.items():
            for combination, cached_file in combinations.items():
                if cached_file is file:
                    return input_file, combination

        return None
    
    def analyze(self, results: List[ScenarioResult], input_files: List[str]) -> Dict[str, Dict[str, List[Dict]]]:
        """Analyze results to find minimal breaking combinations.
        
        Args:
            results: Verification results
            input_files: Original input file paths
            
        Returns:
            Analysis results (minimal combinations by file and query)
        """
        capabilities_by_input = {
            input_file: self._prepared_inputs[input_file].capabilities
            for input_file in input_files
            if input_file in self._prepared_inputs
        }
        return analyze_minimal_false_combinations(
            results,
            input_files,
            capabilities_by_input=capabilities_by_input,
        )
    
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
                            print(f"      {{{scenario_str}}} (cost: {format_costs(costs)})")
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
