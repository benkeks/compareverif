# ProVerif Batch Analysis for Protocol Comparison

This repository contains tools for batch processing of ProVerif models, in particular, to survey combinations of attacker capabilities, and to express found attacks in trees.
This can be used to compare the security of different protocol designs through their resilience in the face of various attack vectors.

- **Contact:** benjamin.bisping@telecom-sudparis.eu

## Description

There are two main scripts in this project:

- [`scenario_preprocessor.py`](#usage-of-the-scenario-preprocessor) automates the generation and verification of multiple attack scenarios, where capabilities are expressed as magical comments `(*** Attack name [price] some oracle code ***)` in ProVerif files.
- [`pareto_comparison.py`](#usage-of-the-pareto-comparison) renders Pareto fronts from manifests so you can compare breaking costs across protocol variants.
- [`attack_tree_extractor.py`](#usage-of-the-attack-tree-extractor) extracts and visualizes attack trees from ProVerif output, connecting it derivations back to underlying capabilities.

The shared code is located in `proverifbatch/`.

Under `examples`, this project contains ProVerif models for analyzing the security of password authentication systems:

- **examples/hashed_passwords.pv** - Models a basic password authentication system with hashed passwords
- **examples/singularized_passwords.pv** - Models a more sophisticated system using password singularization

## Requirements

- Python 3 (tested with Python 3.13.9)
- [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) - Protocol verification tool
- [Graphviz](https://graphviz.org/) - Optional, required for PDF rendering of attack trees
- [pytest](https://pytest.org/) - Test framework (optional, for running tests)

## Usage of the Scenario Preprocessor

The scenario preprocessor automatically generates multiple security scenarios from ProVerif files that contain special "magical comments" marking optional attack vectors.

**Basic usage:**

```bash
python3 scenario_preprocessor.py [--verbose] [--check-all-scenarios] [--logs] <input_file.pv> [additional_files.pv ...]
```

By default, output is concise. The generated-file list and per-scenario ProVerif status reports are shown only when `--verbose` is enabled.

**Examples:**

Process a single example file:
```bash
python3 scenario_preprocessor.py examples/hashed_passwords.pv
```

Process multiple example files:
```bash
python3 scenario_preprocessor.py examples/hashed_passwords.pv examples/singularized_passwords.pv
```

Show detailed generation and verification logs:
```bash
python3 scenario_preprocessor.py --verbose examples/hashed_passwords.pv
```

Force the previous exhaustive behavior over every capability variant combination:
```bash
python3 scenario_preprocessor.py --check-all-scenarios examples/hashed_passwords.pv
```

Persist the full ProVerif console output for each generated scenario in `.pv.log` files:
```bash
python3 scenario_preprocessor.py --logs examples/hashed_passwords.pv
```

### How It Works

The preprocessor looks for special comment blocks in your ProVerif files:

```proverif
(*** Attack Scenario Name
    (* your attack code here *)
    |   (!intruder_at_database())
***)
```

By default, the preprocessor treats each magical comment block as a boolean snippet, generates scenario files lazily, and uses a monotone search to find subset-minimal breaking capability combinations without running ProVerif on every snippet subset. Once that capability front is known, it reconstructs the variant-cost Pareto front offline, without additional ProVerif runs. With `--check-all-scenarios`, it falls back to the previous exhaustive behavior over every capability-variant combination. With `--verbose`, results are displayed with checkmarks (✓) for proven properties and crosses (✗) for failed properties. The names of properties are extracted from comments in the ProVerif files in front of the checks (`query` and `weaksecret`).

Even in lazy mode, the preprocessor still generates the base scenario and each single-capability scenario up front so that downstream tooling such as the attack-tree extractor can compare those files directly from the manifest.

### Output

Generated scenarios are placed in `_scenarios/<filename>/` subdirectories. For example:
- `_scenarios/hashed_passwords/base_scenario.pv`
- `_scenarios/hashed_passwords/intruder_at_database.pv`
- `_scenarios/singularized_passwords/base_scenario.pv`

The script automatically runs ProVerif on all generated scenarios. Detailed verification logs are displayed only in verbose mode. 
With `--logs`, the full ProVerif console output for each scenario is written to a sibling log file with the name `<scenario>.pv.log` in the same `_scenarios/<filename>/` directory.

For each input file, the preprocessor generates a `manifest.json` file in the corresponding scenario directory (e.g., `_scenarios/hashed_passwords/manifest.json`). This manifest provides a comprehensive machine-readable record of all generated scenarios and their verification results. (Documented in [`docs/manifests.md`](docs/manifests.md).)

## Usage of the Pareto Comparison

The Pareto comparison tool renders a two-dimensional cost front for the queries that break a property. By default it uses the first two available price dimensions from the manifests and shows all queries. You can refine the plotted cost dimensions with `--costs`, and you can select a specific query by tag/name or by 1-based index with `--query`.

**Basic usage:**

```bash
python3 pareto_comparison.py <manifest.json | manifest_dir> [additional_inputs ...]
```

**Examples:**

Render the default comparison from the generated manifests:
```bash
python3 pareto_comparison.py _scenarios/hashed_passwords _scenarios/singularized_passwords
```

Render only one query and choose explicit cost dimensions:
```bash
python3 pareto_comparison.py \
  _scenarios/hashed_passwords \
  _scenarios/singularized_passwords \
  --query "no pw leakage" \
  --costs time,hack
```

**Options:**

- `--costs X,Y` - Select the two cost dimensions to compare
- `--query QUERY` - Select a query by tag/name or by 1-based index

## Usage of the Attack Tree Extractor

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

# Highlight attack-relevant paths and fade less relevant branches
python3 attack_tree_extractor.py <scenario_file.pv> --graphviz-pdf <dir> --highlight-attack

# Dump the extracted attack tree as JSON
python3 attack_tree_extractor.py <scenario_file.pv> --json-out <dir>
```

**Examples:**

The examples assume that the `scenario_preprocessor.py` has already been run to generate the scenario files in `_scenarios/`.

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

Generate an annotated tree with clause IDs and attack highlighting:
```bash
python3 attack_tree_extractor.py \
  _scenarios/singularized_passwords/rainbow_table_attack+intruder_at_database+intruder_at_singularization_database.pv \
  --manifest _scenarios/singularized_passwords/manifest.json \
  --query "no pw leakage" \
  --show-clause-ids \
  --highlight-attack \
  --graphviz-pdf trees/
```

**Output:**

The script produces:

1. **Summary to console** - Lists extracted clauses and derivations for each scenario
2. **Dot files** (optional) - Graphviz graph description format, loadable in any graphviz tool
3. **PDF files** (optional) - Visual diagrams of attack trees
4. **JSON files** (optional) - Plain machine-readable attack tree structure

Details about the structure of the generated attack trees and the semantics of the JSON output are documented in [`docs/attack-trees.md`](docs/attack-trees.md).

**Options:**

- `--graphviz-dot DIR` - Output directory for graphviz dot files
- `--graphviz-pdf DIR` - Output directory for PDF files (requires graphviz package)
- `--json-out DIR` - Output directory for JSON tree dumps
- `--no-summary` - Skip printing the console summary
- `--manifest FILE` - Use manifest.json for capability analysis (annotates clauses with capabilities)
- `--original-terms` - Use original ProVerif terms in node labels instead of human-readable formatting
- `--query QUERY` - Select a specific query to visualize by 1-based index or query name
- `--show-clause-ids` - Include ProVerif clause numbers in fact node labels
- `--highlight-attack` - Emphasize attack-relevant paths and fade less relevant branches

#### Capability Analysis

The attack tree extractor can annotate attack trees with the capabilities that enable each attack step. It compares clauses between the base scenario and single-capability scenarios to identify which clauses are introduced by each capability (including completed clauses generated during ProVerif's saturation phase).

When capability analysis is enabled via `--manifest`, the graph uses dedicated capability leaf nodes (red octagons). Capability costs are rendered in these capability nodes.

**Usage:**

```bash
# Generate capability-annotated attack trees
python3 attack_tree_extractor.py \
  --manifest _scenarios/hashed_passwords/manifest.json \
  _scenarios/hashed_passwords/rainbow_table_attack+intruder_at_database.pv \
  --graphviz-pdf annotated_trees/
```

## Testing

The project includes a comprehensive test suite covering the core modules.

Install pytest for testing:

```bash
pip install pytest
```

**Run all tests:**

```bash
python3 -m pytest
```

**Run tests and show coverage** (alternative method):

Coverage reporting uses the built-in `coverage` module if available.

```bash
# Run tests with coverage tracking
python3 -m coverage run -m pytest tests/

# View coverage report
python3 -m coverage report -m
```