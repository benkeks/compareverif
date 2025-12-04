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
