# OrangeProject

Formal verification of password authentication protocols using ProVerif.

**Contact:** benjamin.bisping@telecom-sudparis.eu

## Description

This project contains ProVerif models for analyzing the security of password authentication systems:

- **examples/hashed_passwords.pv** - Models a basic password authentication system with hashed passwords
- **examples/singularized_passwords.pv** - Models a more sophisticated system using password singularization

The `scenario_preprocessor.py` script automates the generation and verification of multiple attack scenarios. For attack tree extraction and visualization, use `attack_tree_extractor.py`.

## Requirements

- Python 3 (tested with Python 3.13.9)
- [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) - Protocol verification tool
- [Graphviz](https://graphviz.org/) - Optional, required for PDF rendering of attack trees
- [pytest](https://pytest.org/) - Test framework (optional, for running tests)

## Setup

Install pytest for testing (optional):

```bash
pip install pytest
```

Coverage reporting uses the built-in `coverage` module if available.

## Testing

The project includes a comprehensive test suite with 89 unit tests covering the core modules.

**Run all tests:**

```bash
python3 -m pytest
```

**Run tests and show coverage** (alternative method):

```bash
# Run tests with coverage tracking
python3 -m coverage run -m pytest tests/

# View coverage report
python3 -m coverage report -m
```

## Usage

### Running the Scenario Preprocessor

The scenario preprocessor automatically generates multiple security scenarios from ProVerif files that contain special "magical comments" marking optional attack vectors.

**Basic usage:**

```bash
python3 scenario_preprocessor.py <input_file.pv> [additional_files.pv ...]
```

**Examples:**

Process a single example file:
```bash
python3 scenario_preprocessor.py examples/hashed_passwords.pv
```

Process multiple example files:
```bash
python3 scenario_preprocessor.py examples/hashed_passwords.pv examples/singularized_passwords.pv
```

### How It Works

The preprocessor looks for special comment blocks in your ProVerif files:

```proverif
(*** Attack Scenario Name
    (* your attack code here *)
    |   (!intruder_at_database())
***)
```

For each combination of these optional blocks, it generates a separate scenario file and runs ProVerif verification on it. Results are displayed with checkmarks (✓) for proven properties and crosses (✗) for failed properties. The names of properties are extracted from comments in the ProVerif files in front of the queries.

### Output

Generated scenarios are placed in `_scenarios/<filename>/` subdirectories. For example:
- `_scenarios/hashed_passwords/base_scenario.pv`
- `_scenarios/hashed_passwords/intruder_at_database.pv`
- `_scenarios/singularized_passwords/base_scenario.pv`

The script automatically runs ProVerif on all generated scenarios and displays the verification results.

#### Manifest Files

For each input file, the preprocessor generates a `manifest.json` file in the corresponding scenario directory (e.g., `_scenarios/hashed_passwords/manifest.json`). This manifest provides a comprehensive machine-readable record of all generated scenarios and their verification results.

**Manifest structure:**

```json
{
  "input_file": "hashed_passwords.pv",
  "generated_at": null,
  "scenarios": [
    {
      "file": "base_scenario.pv",
      "path": "_scenarios/hashed_passwords/base_scenario.pv",
      "capabilities": [],
      "total_costs": {},
      "queries": [
        {
          "tag": "no faux authentication",
          "query": "(* no faux authentication *)\nquery uidx: uid;"
        }
      ],
      "verification": {
        "status": "success",
        "query_results": [
          {
            "tag": "no faux authentication",
            "result": true
          }
        ],
        "error_message": null
      }
    }
  ]
}
```

**Manifest fields:**

- **`input_file`**: Original ProVerif file that was processed
- **`scenarios`**: Array of all generated scenario files, each containing:
  - **`file`**: Scenario filename
  - **`path`**: Full path to the scenario file
  - **`capabilities`**: List of attacker capabilities included in this scenario:
    - `name`: Capability name (e.g., "Rainbow table attack")
    - `costs`: Cost dictionary for this capability (e.g., `{"time": 10}`)
  - **`total_costs`**: Aggregated costs across all capabilities in this scenario
  - **`queries`**: List of ProVerif security queries:
    - `tag`: Human-readable query label
    - `query`: Full ProVerif query text
  - **`verification`**: ProVerif verification results:
    - `status`: Verification status (success/error/timeout/exception)
    - `query_results`: Array of outcomes for each query (tag and true/false result)
    - `error_message`: Error details if verification failed


### Attack Tree Extractor

The `attack_tree_extractor.py` script extracts clauses and derivations from ProVerif output and generates graphviz visualizations of attack trees.

**Basic usage:**

```bash
python3 attack_tree_extractor.py <scenario_file.pv> [additional_files.pv ...]
```

**With graphviz output:**

```bash
# Generate graphviz dot files
python3 attack_tree_extractor.py <scenario_file.pv> --graphviz-dot <output_dir>

# Generate PDF visualizations (requires graphviz installed)
python3 attack_tree_extractor.py <scenario_file.pv> --graphviz-pdf <output_dir>

# Generate both dot and PDF
python3 attack_tree_extractor.py <scenario_file.pv> --graphviz-dot <dir> --graphviz-pdf <dir>
```

**Examples:**

Extract clauses and derivations from a generated scenario:
```bash
python3 attack_tree_extractor.py _scenarios/hashed_passwords/brute_force_attack.pv
```

Generate attack tree diagrams:
```bash
python3 attack_tree_extractor.py _scenarios/hashed_passwords/brute_force_attack+intruder_at_database.pv \
  --graphviz-pdf trees/
```

Process multiple scenarios and generate all outputs:
```bash
python3 attack_tree_extractor.py \
  _scenarios/hashed_passwords/base_scenario.pv \
  _scenarios/hashed_passwords/brute_force_attack+intruder_at_database.pv \
  _scenarios/singularized_passwords/rainbow_table_attack+intruder_at_database+intruder_at_singularization_database.pv \
  --graphviz-pdf trees/ \
  --graphviz-dot trees/
```

**Output:**

The script produces:

1. **Summary to console** - Lists extracted clauses and derivations for each scenario
2. **Dot files** (optional) - Graphviz graph description format, loadable in any graphviz tool
3. **PDF files** (optional) - Visual diagrams of attack trees with top-down layout

The attack tree visualizations show:
- **Goal at the top** (highlighted in green) - What the attacker aims to achieve
- **Intermediate facts** flowing downward with color coding:
  - Green nodes: Goal/target
  - Blue nodes: Clause references  
  - Yellow nodes: Applied transformations (projections, duplications, etc.)
  - Gray nodes: Other facts
- **Edges labeled with rules** showing how each fact is derived

**Options:**

- `--graphviz-dot DIR` - Output directory for graphviz dot files
- `--graphviz-pdf DIR` - Output directory for PDF files (requires graphviz package)
- `--no-summary` - Skip printing the console summary
- `--manifest FILE` - Use manifest.json for capability analysis (annotates clauses with capabilities)

#### Capability Analysis

The attack tree extractor can annotate attack trees with the capabilities that enable each attack step. It compares clauses between the base scenario and single-capability scenarios to identify which clauses are introduced by each capability (including completed clauses generated during ProVerif's saturation phase). Nodes are color-coded by capability for visual distinction.

**Usage:**

```bash
# Generate capability-annotated attack trees
python3 attack_tree_extractor.py \
  --manifest _scenarios/hashed_passwords/manifest.json \
  _scenarios/hashed_passwords/rainbow_table_attack+intruder_at_database.pv \
  --graphviz-pdf annotated_trees/
```

Attack tree nodes annotated with capabilities show labels like `[Rainbow table attack]` or `[Intruder at database]`, helping identify which attack steps depend on specific capabilities.
