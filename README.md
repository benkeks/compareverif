# OrangeProject

Formal verification of password authentication protocols using ProVerif.

**Contact:** benjamin.bisping@telecom-sudparis.eu

## Description

This project contains ProVerif models for analyzing the security of password authentication systems:

- **hashed_passwords.pv** - Models a basic password authentication system with hashed passwords
- **singularized_passwords.pv** - Models a more sophisticated system using password singularization

The `scenario_preprocessor.py` script automates the generation and verification of multiple attack scenarios.

## Requirements

- Python 3 (tested with Python 3.13.9)
- [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) - Protocol verification tool
- [Graphviz](https://graphviz.org/) - Optional, required for PDF rendering of attack trees

## Usage

### Running the Scenario Preprocessor

The scenario preprocessor automatically generates multiple security scenarios from ProVerif files that contain special "magical comments" marking optional attack vectors.

**Basic usage:**

```bash
python3 scenario_preprocessor.py <input_file.pv> [additional_files.pv ...]
```

**Examples:**

Process a single file:
```bash
python3 scenario_preprocessor.py hashed_passwords.pv
```

Process multiple files:
```bash
python3 scenario_preprocessor.py hashed_passwords.pv singularized_passwords.pv
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

Extract clauses and derivations from a single scenario:
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