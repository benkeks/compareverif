import re
from pathlib import Path
from itertools import product
import subprocess
import sys

# Some utility functions for pretty printing

def print_headline(title, char='=', width=60):
    border = char * width
    print(f"\n{border}")
    print(title)
    print(border)

def print_subheading(title, char='-', width=60):
    print(title)
    print(char * width)

# Main preprocessor function

def preprocess_scenarios(input_file, output_dir=None):
    """
    Preprocessor that finds magical comments of the form:
    (*** <Some heading> [<quantity> <cost dimension>]
      <Some source> ***)
    and generates versions of the file with different source combinations.
    
    Args:
        input_file: Path to the input .pv file
        output_dir: Output directory (defaults to _scenarios/<input_filename>)
    
    Returns:
        List[dict]: List of generated file info (including costs per scenario)
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
    
    # Pattern to match magical comments
    pattern = r'\(\*\*\*\s*(.*?)\s*\n(.*?)\*\*\*\)'
    
    # Find all magical comment blocks
    matches = list(re.finditer(pattern, content, re.DOTALL))
    
    if not matches:
        print("No magical comments found")
        return []
    
    # Build a sequence of chunks (base content or magical comments)
    chunks = []
    last_pos = 0
    
    for match in matches:
        # Add base content before this match
        if match.start() > last_pos:
            chunks.append({
                'type': 'base',
                'content': content[last_pos:match.start()]
            })
        
        # Parse heading and costs from the header
        header = match.group(1).strip()
        
        # Pattern to extract costs: [<quantity> <dimension>]
        cost_pattern = r'\[([0-9]+(?:\.[0-9]+)?)\s+(\w+)\]'
        cost_matches = re.findall(cost_pattern, header)
        
        # Build costs dictionary
        costs = {}
        for quantity, dimension in cost_matches:
            # Convert to int if possible, else float
            try:
                costs[dimension] = int(quantity)
            except ValueError:
                costs[dimension] = float(quantity)
        
        # Remove cost annotations from heading to get clean name
        clean_heading = re.sub(r'\s*\[[0-9]+(?:\.[0-9]+)?\s+\w+\]', '', header).strip()
        
        # Add the magical comment as a chunk
        chunks.append({
            'type': 'magical',
            'heading': clean_heading,
            'costs': costs,
            'content': match.group(2).strip()
        })
        
        last_pos = match.end()
    
    # Add remaining base content after last match
    if last_pos < len(content):
        chunks.append({
            'type': 'base',
            'content': content[last_pos:]
        })
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Collect all magical chunks for scenario generation
    magical_chunks = [chunk for chunk in chunks if chunk['type'] == 'magical']
    
    # Generate all combinations (2^n combinations for n magical chunks)
    # Each combinations is a tuple of booleans indicating whether to include each magical chunk
    num_scenarios = len(magical_chunks)
    combinations = list(product([False, True], repeat=num_scenarios))
    
    generated_files = []
    
    for perm in combinations:
        output_content = ''
        
        # Build filename from included scenarios and track costs
        included_names = []
        total_costs = {}
        for i, include in enumerate(perm):
            if include:
                included_names.append(magical_chunks[i]['heading'])
                # Accumulate costs from this scenario
                for cost_dim, cost_val in magical_chunks[i]['costs'].items():
                    total_costs[cost_dim] = total_costs.get(cost_dim, 0) + cost_val
        
        # Generate content based on combinations
        for chunk in chunks:
            if chunk['type'] == 'base':
                output_content += chunk['content']
            elif chunk['type'] == 'magical':
                # Find index of this magical chunk
                idx = magical_chunks.index(chunk)
                if perm[idx]:
                    output_content += chunk['content']
                else:
                    output_content += f'(* No {chunk["heading"]}*)'  # Exclude this chunk
        
        # Collect query statements and their tags
        query_pattern = r'(?:\(\*\s*([^*)]+?)\s*\*\)\s*)?query\s+.*?(?=\n|$)'
        query_matches = re.finditer(query_pattern, output_content, re.MULTILINE)
        queries_with_tags = []
        for match in query_matches:
            tag = match.group(1).strip() if match.group(1) else "query"
            queries_with_tags.append({
                'tag': tag,
                'query': match.group(0)
            })

        # Create filename
        if not included_names:
            filename = "base_scenario"
        else:
            filename = '+'.join(re.sub(r'[^a-zA-Z0-9_]', '_', name.lower()) 
                              for name in included_names)
        
        output_path = Path(output_dir) / f"{filename}.pv"

        with open(output_path, 'w') as f:
            f.write(output_content)
        
        generated_files.append({
            'path': output_path,
            'included_scenarios': included_names,
            'costs': total_costs,
            'queries': queries_with_tags
        })
        cost_str = ', '.join(f"{v} {k}" for k, v in total_costs.items()) if total_costs else "no cost"
        print(f"Generated: {output_path} (cost: {cost_str})")
    
    print(f"Total scenarios generated: {len(combinations)}")
    return generated_files

def run_proverif_on_files(generated_files):
    """Run ProVerif on all generated files and return results.
    
    Returns:
        List[dict]: List of results, one per file, containing:
            - path: Path to the file
            - included_scenarios: List of included scenario names
            - status: 'success', 'error', 'timeout', or 'exception'
            - query_results: List of dicts with 'tag', 'result' (True/False), and optionally 'error'
            - error_message: Error message if status is not 'success'
    """
    print_headline("Running ProVerif on generated scenarios")
    results = []
    
    for file in generated_files:
        file_path = file['path']
        print_subheading(f"\nVerifying: {file_path}")
        
        file_result = {
            'path': file_path,
            'included_scenarios': file['included_scenarios'],
            'status': None,
            'query_results': [],
            'error_message': None
        }
        
        try:
            result = subprocess.run(
                ['proverif', str(file_path)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per file
            )
            
            if result.returncode == 0:
                file_result['status'] = 'success'
            else:
                file_result['status'] = 'error'
                file_result['error_message'] = result.stderr
                print(f"✗ Failed: {file_path.name}")
                print(f"Error output:\n{result.stderr}")
            
            # Parse ProVerif output for query results
            if result.stdout:
                result_lines = [line for line in result.stdout.splitlines() if line.startswith("RESULT")]
                for query, res_line in zip(file['queries'], result_lines):
                    query_passed = res_line.endswith("true.")
                    file_result['query_results'].append({
                        'tag': query["tag"],
                        'result': query_passed
                    })
                    value = "✓" if query_passed else "✗"
                    print(f"\t{query['tag']}: {value}")
            else:
                # No output but success - initialize empty query results
                for query in file['queries']:
                    file_result['query_results'].append({
                        'tag': query["tag"],
                        'result': None
                    })
                
        except subprocess.TimeoutExpired:
            file_result['status'] = 'timeout'
            file_result['error_message'] = 'Exceeded 5 minute timeout'
            print(f"⏱ Timeout: {file_path.name} (exceeded 5 minutes)")
        except FileNotFoundError:
            file_result['status'] = 'exception'
            file_result['error_message'] = 'ProVerif command not found. Please ensure ProVerif is installed and in PATH.'
            print("Error: proverif command not found. Please ensure ProVerif is installed and in PATH.")
            results.append(file_result)
            break
        except Exception as e:
            file_result['status'] = 'exception'
            file_result['error_message'] = str(e)
            print(f"Error running proverif on {file_path.name}: {e}")
        
        results.append(file_result)
    
    return results

def analyze_minimal_false_combinations(results, input_files):
    """Analyze results to find minimal scenario combinations that make queries false.
    
    For each input file and query, finds all minimal sets of included scenarios
    that result in a false query (where minimal means no other false-making 
    combination is a strict subset).
    
    Args:
        results: List of result dicts from run_proverif_on_files
        input_files: List of original input file paths
    
    Returns:
        Dict mapping input_file -> query_tag -> list of minimal scenario sets
    """
    # Group results by input file
    analysis = {}
    
    for input_file in input_files:
        input_stem = Path(input_file).stem
        analysis[input_file] = {}
        
        # Find all results from this input file
        file_results = [r for r in results if input_stem in str(r['path'])]
        
        if not file_results:
            continue
        
        # Get query tags from first result
        query_tags = [q['tag'] for q in file_results[0]['query_results']]
        
        # For each query, find false combinations
        for query_idx, query_tag in enumerate(query_tags):
            false_combinations = []
            
            for result in file_results:
                if query_idx < len(result['query_results']):
                    query_result = result['query_results'][query_idx]
                    # Collect false results
                    if query_result['result'] is False:
                        false_combinations.append(set(result['included_scenarios']))
            
            # Find minimal combinations (no subset relationships)
            minimal_combinations = []
            for combo in false_combinations:
                is_minimal = True
                for other_combo in false_combinations:
                    if other_combo < combo:  # other_combo is strict subset
                        is_minimal = False
                        break
                if is_minimal:
                    minimal_combinations.append(combo)
            
            # Remove duplicates
            minimal_combinations = list({frozenset(c): c for c in minimal_combinations}.values())
            
            analysis[input_file][query_tag] = minimal_combinations
    
    return analysis

def print_analysis(analysis):
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
                    if combo:
                        scenario_str = ", ".join(sorted(combo))
                        print(f"      {{{scenario_str}}}")
                    else:
                        print(f"      {{}} (base scenario)")

def main():
    """Main entry point supporting multiple input files."""
    if len(sys.argv) < 2:
        print("Usage: python scenario_preprocessor.py <input_file1.pv> [input_file2.pv ...]")
        print("Example: python scenario_preprocessor.py hashed_passwords.pv singularized_passwords.pv")
        sys.exit(1)
    
    input_files = sys.argv[1:]
    all_generated_files = []
    
    for input_file in input_files:
        if not Path(input_file).exists():
            print(f"Error: File '{input_file}' not found")
            continue
        generated_files = preprocess_scenarios(input_file)
        all_generated_files.extend(generated_files)
    
    # Run ProVerif on all generated files and collect results
    if all_generated_files:
        results = run_proverif_on_files(all_generated_files)
        analysis = analyze_minimal_false_combinations(results, input_files)
        print_analysis(analysis)

if __name__ == '__main__':
    main()