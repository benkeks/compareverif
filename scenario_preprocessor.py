import re
from pathlib import Path
from itertools import product
import subprocess

def preprocess_scenarios(input_file='hashed_passwords_singularized.pv', output_dir='_scenarios'):
    """
    Preprocessor that finds magical comments of the form:
    (*** <Some heading>
      <Some source> ***)
    and generates versions of the file with different source combinations.
    
    Returns:
        List[Path]: List of generated file paths
    """
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
        
        # Add the magical comment as a chunk
        chunks.append({
            'type': 'magical',
            'heading': match.group(1).strip(),
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
    Path(output_dir).mkdir(exist_ok=True)
    
    # Collect all magical chunks for scenario generation
    magical_chunks = [chunk for chunk in chunks if chunk['type'] == 'magical']
    
    # Generate all permutations (2^n combinations for n magical chunks)
    # Each permutation is a tuple of booleans indicating whether to include each magical chunk
    num_scenarios = len(magical_chunks)
    permutations = list(product([False, True], repeat=num_scenarios))
    
    generated_files = []
    
    for perm in permutations:
        output_content = ''
        
        # Build filename from included scenarios
        included_names = []
        for i, include in enumerate(perm):
            if include:
                included_names.append(magical_chunks[i]['heading'])
        
        # Generate content based on permutation
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
            'queries': queries_with_tags
        })
        print(f"Generated: {output_path}")
    
    print(f"Total scenarios generated: {len(permutations)}")
    return generated_files

# Generate all scenario files
generated_files = preprocess_scenarios()

# Run ProVerif on all generated files
print("\n--- Running ProVerif on generated scenarios ---")
for file in generated_files:
    file_path = file['path']
    print(f"\nVerifying: {file_path}")
    try:
        result = subprocess.run(
            ['proverif', str(file_path)],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per file
        )
        
        if result.returncode == 0:
            # silent success
            pass
        else:
            print(f"✗ Failed: {file_path.name}")
            print(f"Error output:\n{result.stderr}")
        
        # Optionally print ProVerif output
        if result.stdout:
            result_list = (line for line in result.stdout.splitlines() if line.startswith("RESULT"))
            result_presentations = []
            for query, res in zip(file['queries'], result_list):
                value = "✓" if res.endswith("true.") else "✗"
                result_presentations.append(
                    f'{query['tag']}: {value}'
                )
            print("\t".join(result_presentations))
            
    except subprocess.TimeoutExpired:
        print(f"⏱ Timeout: {file_path.name} (exceeded 5 minutes)")
    except FileNotFoundError:
        print("Error: proverif command not found. Please ensure ProVerif is installed and in PATH.")
        break
    except Exception as e:
        print(f"Error running proverif on {file_path.name}: {e}")