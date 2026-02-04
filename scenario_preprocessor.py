import re
from pathlib import Path
from itertools import product
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Set, Optional, Any

DEFAULT_TABLE_WIDTH = 60
DEFAULT_LABEL_WIDTH = 37
DEFAULT_COST_COLUMN_WIDTH = 13
DEFAULT_PROVERIF_TIMEOUT = 300  # 5 minutes

@dataclass
class AttackVariant:
    """Represents a cost variant of an attacker capability."""
    name: str
    costs: Dict[str, float]

@dataclass
class AttackerCapability:
    """Represents an attacker capability with multiple cost variants."""
    primary_name: str
    variants: List[AttackVariant]
    content: str

@dataclass
class ScenarioFile:
    """Result of generating a scenario file."""
    path: Path
    capabilities: List[AttackVariant]
    costs: Dict[str, float]
    queries: List[Dict[str, str]]

@dataclass
class ScenarioResult:
    """Represents the result of verifying a generated scenario file."""
    scenario: ScenarioFile
    status: Optional[str] = None
    query_results: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None

# Utility functions for pretty printing

def print_headline(title: str, char: str = '=', width: int = DEFAULT_TABLE_WIDTH) -> None:
    border = char * width
    print(f"\n{border}")
    print(title)
    print(border)

def print_subheading(title: str, char: str = '-', width: int = DEFAULT_TABLE_WIDTH) -> None:
    print(title)
    print(char * width)

# Parsing functions

def parse_costs(header_part: str) -> Dict[str, float]:
    """Extract costs from a header part like '[100 time, 10 obstime]'."""
    costs: Dict[str, float] = {}
    bracket_contents = re.findall(r'\[([^\]]+)\]', header_part)
    for content in bracket_contents:
        for item in content.split(','):
            item = item.strip()
            if not item:
                continue
            m = re.match(r'([0-9]+(?:\.[0-9]+)?)\s+(\w+)', item)
            if not m:
                continue
            quantity, dimension = m.groups()
            try:
                costs[dimension] = int(quantity)
            except ValueError:
                costs[dimension] = float(quantity)
    return costs

def parse_magical_comment(header: str) -> List[AttackVariant]:
    """Parse a magical comment header into variants.
    
    Supports syntax like 'Rainbow table attack [100 time] / Side-channel attack [10 time]'
    """
    variants: List[AttackVariant] = []
    header_parts = [part.strip() for part in header.split('/') if part.strip()]
    
    for part in header_parts:
        costs = parse_costs(part)
        clean_name = re.sub(r'\s*\[[^\]]+\]', '', part).strip()
        variants.append(AttackVariant(name=clean_name, costs=costs))
    
    return variants

def extract_attacker_capabilities(content: str) -> Tuple[List[AttackerCapability], List[Optional[str]]]:
    """Extract all attacker capabilities and base content chunks from file.
    
    Returns:
        (attacker_capabilities, content_chunks)
    """
    pattern = r'\(\*\*\*\s*(.*?)\s*\n(.*?)\*\*\*\)'
    matches = list(re.finditer(pattern, content, re.DOTALL))
    
    if not matches:
        return [], [content]
    
    capabilities: List[AttackerCapability] = []
    content_chunks: List[Optional[str]] = []
    last_pos = 0
    
    for match in matches:
        # Add base content before this match
        if match.start() > last_pos:
            content_chunks.append(content[last_pos:match.start()])
        
        # Parse capability
        header = match.group(1).strip()
        variants = parse_magical_comment(header)
        
        if variants:
            capability = AttackerCapability(
                primary_name=variants[0].name,
                variants=variants,
                content=match.group(2).strip()
            )
            capabilities.append(capability)
            content_chunks.append(None)  # Placeholder for this capability
        
        last_pos = match.end()
    
    # Add remaining base content after last match
    if last_pos < len(content):
        content_chunks.append(content[last_pos:])
    
    return capabilities, content_chunks

def print_capabilities_table(capabilities: List[AttackerCapability]) -> None:
    """Print a formatted table of capabilities and their costs."""
    # Collect all unique cost dimensions
    all_dimensions: Set[str] = set()
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

def generate_scenario_combinations(capabilities: List[AttackerCapability]) -> List[Tuple[int, ...]]:
    """Generate all possible combinations of capability variants.
    
    Returns list of tuples where each element is an index (0 = exclude, 1+ = variant index).
    """
    choices_per_capability = [list(range(len(cap.variants) + 1)) for cap in capabilities]
    return list(product(*choices_per_capability))

def build_scenario_content(
    combination: Tuple[int, ...],
    capabilities: List[AttackerCapability],
    content_chunks: List[Optional[str]]
) -> Tuple[str, List[AttackVariant], Dict[str, float]]:
    """Build output content for a scenario combination.
    
    Returns:
        (output_content, attack_variants, total_costs)
    """
    output_content = ''
    attack_variants: List[AttackVariant] = []
    total_costs: Dict[str, float] = {}
    
    # Process content chunks and insert capabilities based on combination
    cap_idx = 0
    for chunk in content_chunks:
        if chunk is None:
            # This is a capability placeholder
            if cap_idx < len(capabilities):
                choice = combination[cap_idx]
                if choice > 0:
                    variant = capabilities[cap_idx].variants[choice - 1]
                    attack_variants.append(variant)
                    output_content += capabilities[cap_idx].content
                    
                    # Accumulate costs
                    for cost_dim, cost_val in variant.costs.items():
                        total_costs[cost_dim] = total_costs.get(cost_dim, 0) + cost_val
                else:
                    output_content += f'(* No {capabilities[cap_idx].primary_name}*)'
                cap_idx += 1
        else:
            # Regular content chunk
            output_content += chunk
    
    return output_content, attack_variants, total_costs

def extract_queries(content: str) -> List[Dict[str, str]]:
    """Extract query statements and their tags from content."""
    query_pattern = r'(?:\(\*\s*([^*)]+?)\s*\*\)\s*)?query\s+.*?(?=\n|$)'
    query_matches = re.finditer(query_pattern, content, re.MULTILINE)
    queries: List[Dict[str, str]] = []
    
    for match in query_matches:
        tag = match.group(1).strip() if match.group(1) else "query"
        queries.append({
            'tag': tag,
            'query': match.group(0)
        })
    
    return queries

# Main preprocessor function

def preprocess_scenarios(input_file: str, output_dir: Optional[str] = None) -> List[ScenarioFile]:
    """
    Preprocessor that finds magical comments of the form, which represent attacker capabilities:
    (*** <Some heading> [<quantity> <cost dimension>]
      <Some source> ***)
    and generates versions of the file with different source combinations.
    
    Args:
        input_file: Path to the input .pv file
        output_dir: Output directory (defaults to _scenarios/<input_filename>)
    
    Returns:
        List[ScenarioFile]: List of generated file info (including costs per scenario)
    """
    print_headline(f"Processing: {input_file}")

    input_path = Path(input_file)
    
    # Default output directory based on input filename
    if output_dir is None:
        output_dir = Path('_scenarios') / input_path.stem
    else:
        output_dir = Path(output_dir)
    
    # Read the input file
    with open(input_file, 'r') as f:
        content = f.read()
    
    # Extract attacker capabilities from magical comments
    attacker_capabilities, content_chunks = extract_attacker_capabilities(content)
    
    if not attacker_capabilities:
        print("No magical comments for attacker capabilities found")
        return []
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect all unique cost dimensions from attacker capabilities
    all_dimensions = set()
    for cap in attacker_capabilities:
        for variant in cap.variants:
            all_dimensions.update(variant.costs.keys())
    all_dimensions = sorted(all_dimensions)
    
    # Create a table showing capabilities and their costs dimension
    if all_dimensions:
        print_subheading("Attacker capabilities with costs", width=60)
        
        # Header row with chunk names
        header = "Capability".ljust(37)
        for cost_dim in all_dimensions:
            header += cost_dim[:11].rjust(13)
        print(header)
        print('-' * (37 + len(all_dimensions) * 13))
        
        # One column per dimension showing costs
        for cap in attacker_capabilities:
            for idx, variant in enumerate(cap.variants):
                label = cap.primary_name if idx == 0 else f"  - {variant.name}"
                row = label[:36].ljust(37)
                for dimension in all_dimensions:
                    cost = variant.costs.get(dimension, '-')
                    row += str(cost).rjust(13)
                print(row)
        print()
    
    # Generate all combinations with variant choices per capability
    combinations = generate_scenario_combinations(attacker_capabilities)
    
    generated_files = []
    
    for perm in combinations:
        # Build scenario content using helper function
        output_content, attack_variants, total_costs = build_scenario_content(
            perm, attacker_capabilities, content_chunks
        )
        
        # Extract queries
        queries = extract_queries(output_content)
        
        # Create filename based on primary capability names
        included_names = [cap.primary_name for i, cap in enumerate(attacker_capabilities) if perm[i] > 0]
        if not included_names:
            filename = "base_scenario"
        else:
            filename = '+'.join(re.sub(r'[^a-zA-Z0-9_]', '_', name.lower()) 
                              for name in included_names)
        
        output_path = Path(output_dir) / f"{filename}.pv"
        
        with open(output_path, 'w') as f:
            f.write(output_content)
        
        generated_files.append(ScenarioFile(
            path=output_path,
            capabilities=attack_variants,
            costs=total_costs,
            queries=queries
        ))
        cost_str = ', '.join(f"{v} {k}" for k, v in total_costs.items()) if total_costs else "no cost"
        print(f"Generated: {output_path} (cost: {cost_str})")
    
    print(f"Total scenarios generated: {len(combinations)}")
    return generated_files

def run_proverif_on_files(generated_files: List[ScenarioFile]) -> List[ScenarioResult]:
    """Run ProVerif on all generated files and return results.
    
    Returns:
        List[ScenarioResult]: List of results, one per file, containing:
            - path: Path to the file
            - included_scenarios: List of included scenario objects
            - costs: Cost dictionary
            - status: 'success', 'error', 'timeout', or 'exception'
            - query_results: List of dicts with 'tag', 'result' (True/False), and optionally 'error'
            - error_message: Error message if status is not 'success'
    """
    print_headline("Running ProVerif on generated scenarios")
    results: List[ScenarioResult] = []
    for file in generated_files:
        print_subheading(f"\nVerifying: {file.path}")
        file_result = ScenarioResult(scenario=file)
        try:
            result = subprocess.run(
                ['proverif', str(file.path)],
                capture_output=True,
                text=True,
                timeout=DEFAULT_PROVERIF_TIMEOUT
            )
            if result.returncode == 0:
                file_result.status = 'success'
            else:
                file_result.status = 'error'
                file_result.error_message = result.stderr
                print(f"✗ Failed: {file.path.name}")
                print(f"Error output:\n{result.stderr}")
            # Parse ProVerif output for query results
            if result.stdout:
                result_lines = [line for line in result.stdout.splitlines() if line.startswith("RESULT")]
                for query, res_line in zip(file.queries, result_lines):
                    query_passed = res_line.endswith("true.")
                    file_result.query_results.append({
                        'tag': query["tag"],
                        'result': query_passed
                    })
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
            file_result.error_message = 'Exceeded 5 minute timeout'
            print(f"⏱ Timeout: {file.path.name} (exceeded 5 minutes)")
        except FileNotFoundError:
            file_result.status = 'exception'
            file_result.error_message = 'ProVerif command not found. Please ensure ProVerif is installed and in PATH.'
            print("Error: proverif command not found. Please ensure ProVerif is installed and in PATH.")
            results.append(file_result)
            break
        except Exception as e:
            file_result.status = 'exception'
            file_result.error_message = str(e)
            print(f"Error running proverif on {file.path.name}: {e}")
        results.append(file_result)
    return results

def analyze_minimal_false_combinations(
    results: List[Dict[str, Any]],
    input_files: List[str]
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Analyze results to find minimal scenario combinations that make queries false.
    
    For each input file and query, finds all minimal sets of included scenarios
    that result in a false query (where minimal means no other false-making 
    combination has pointwise lower or equal costs in all dimensions).
    
    Args:
        results: List of result dicts from run_proverif_on_files
        input_files: List of original input file paths
    
    Returns:
        Dict mapping input_file -> query_tag -> list of dicts with 'scenarios' and 'costs'
    """
    # Group results by input file
    analysis = {}
    
    for input_file in input_files:
        input_stem = Path(input_file).stem
        analysis[input_file] = {}
        
        # Find all results from this input file
        file_results = [r for r in results if input_stem in str(r.scenario.path)]
        
        if not file_results:
            continue
        
        # Get query tags from first result
        query_tags = [q['tag'] for q in file_results[0].query_results]
        
        # For each query, find false combinations
        for query_idx, query_tag in enumerate(query_tags):
            false_combinations = []
            
            for result in file_results:
                if query_idx < len(result.query_results):
                    query_result = result.query_results[query_idx]
                    # Collect false results with their costs
                    if query_result['result'] is False:
                        scenario_names = [s.name for s in result.scenario.capabilities]
                        false_combinations.append({
                            'scenarios': set(scenario_names),
                            'costs': result.scenario.costs
                        })
            
            # Find minimal combinations using pointwise cost comparison
            # A combination is minimal if no other combination has costs
            # pointwise <= in all dimensions AND strictly < in at least one
            minimal_combinations = []
            for combo in false_combinations:
                is_minimal = True
                for other_combo in false_combinations:
                    if combo == other_combo:
                        continue
                    
                    # Check if other_combo dominates combo (costs pointwise <=)
                    all_dims = set(combo['costs'].keys()) | set(other_combo['costs'].keys())
                    dominates = True
                    strictly_less = False
                    
                    for dim in all_dims:
                        combo_val = combo['costs'].get(dim, 0)
                        other_val = other_combo['costs'].get(dim, 0)
                        
                        if other_val > combo_val:
                            # other is worse in this dimension
                            dominates = False
                            break
                        elif other_val < combo_val:
                            # other is strictly better in this dimension
                            strictly_less = True
                    
                    if dominates and strictly_less:
                        # other_combo dominates combo
                        is_minimal = False
                        break
                
                if is_minimal:
                    minimal_combinations.append(combo)
            
            analysis[input_file][query_tag] = minimal_combinations
    
    return analysis

def print_analysis(analysis: Dict[str, Dict[str, List[Dict[str, Any]]]]) -> None:
    """Pretty print the minimal breaking combinations analysis."""
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

def main() -> None:
    """Main entry point supporting multiple input files."""
    if len(sys.argv) < 2:
        print("Usage: python scenario_preprocessor.py <input_file1.pv> [input_file2.pv ...]")
        print("Example: python scenario_preprocessor.py hashed_passwords.pv singularized_passwords.pv")
        sys.exit(1)
    
    input_files = sys.argv[1:]
    all_generated_scenarios: List[ScenarioFile] = []
    
    for input_file in input_files:
        if not Path(input_file).exists():
            print(f"Error: File '{input_file}' not found")
            continue
        generated_scenarios = preprocess_scenarios(input_file)
        all_generated_scenarios.extend(generated_scenarios)
    
    # Run ProVerif on all generated files and collect results
    if all_generated_scenarios:
        results = run_proverif_on_files(all_generated_scenarios)
        analysis = analyze_minimal_false_combinations(results, input_files)
        print_analysis(analysis)

if __name__ == '__main__':
    main()