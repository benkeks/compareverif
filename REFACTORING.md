# Orange Project - Refactored Scenario Module

This document describes the refactored scenario preprocessing module.

## Architecture Overview

The scenario processing functionality has been refactored into modular, testable components:

### Module Structure

```
src/scenarios/
├── __init__.py              # Public API exports
├── models.py                # Data classes (AttackVariant, AttackerCapability, etc.)
├── parser.py                # Parse magical comments and costs from .pv files
├── generator.py             # Generate scenario combinations and filenames
├── analyzer.py              # Analyze verification results for minimal breaking combinations
└── preprocessor.py          # High-level orchestrator (ScenarioPreprocessor class)

src/common/
├── __init__.py
└── formatting.py            # Shared formatting utilities (print_headline, etc.)
```

## Module Responsibilities

### `models.py`
Data classes with no dependencies:
- `AttackVariant`: Cost variant of a capability
- `AttackerCapability`: A capability with multiple variants
- `ScenarioFile`: Generated scenario with path, capabilities, costs
- `ScenarioResult`: Verification result for a scenario

### `parser.py`
Pure functions for parsing file content:
- `parse_costs()`: Parse `[100 time, 10 hack]` syntax
- `parse_magical_comment()`: Extract capability variants from header
- `extract_attacker_capabilities()`: Find all `(*** ... ***)` blocks in a file

**No I/O or external dependencies**. Fully testable with string inputs.

### `generator.py`
Pure functions for scenario generation:
- `generate_scenario_combinations()`: All capability combinations
- `build_scenario_content()`: Assemble .pv file from combination
- `extract_queries()`: Extract query statements from .pv content
- `create_scenario_filename()`: Generate filename from capability names

**No I/O or external dependencies**. Fully testable with data structures.

### `analyzer.py`
Analysis of verification results:
- `analyze_minimal_false_combinations()`: Find minimal sets of capabilities that break queries

**Pure function** - takes results, returns analysis.

### `preprocessor.py`
High-level orchestrator class `ScenarioPreprocessor`:
- `preprocess()`: Extract capabilities, generate combinations, write files
- `run_proverif()`: Execute ProVerif on scenarios (uses subprocess)
- `analyze()`: Analyze results
- `print_analysis()`: Pretty-print analysis results

**Coordinates** the other modules and handles I/O and external command execution.

### `common/formatting.py`
Shared utilities:
- `print_headline()`: Print centered heading with borders
- `print_subheading()`: Print subheading

## Usage

### As a CLI (backward compatible)

```bash
python scenario_preprocessor_refactored.py input.pv
```

### As a library

```python
from src.scenarios import ScenarioPreprocessor

preprocessor = ScenarioPreprocessor()
scenarios, output_dir = preprocessor.preprocess("input.pv")
results = preprocessor.run_proverif(scenarios)
analysis = preprocessor.analyze(results, ["input.pv"])
```

### Pure functions (no orchestrator)

```python
from src.scenarios.parser import extract_attacker_capabilities, parse_costs
from src.scenarios.generator import generate_scenario_combinations

content = open("file.pv").read()
caps, chunks = extract_attacker_capabilities(content)
combinations = generate_scenario_combinations(caps)
```

## Testing

### Structure

```
tests/
├── conftest.py                      # Shared fixtures
├── unit/
│   ├── test_scenario_parser.py      # Parser tests (no I/O)
│   ├── test_scenario_generator.py   # Generator tests (no I/O)
│   ├── test_scenario_preprocessor.py # Orchestrator tests (with mocked subprocess)
│   └── test_scenario_analyzer.py    # Analyzer tests (no I/O)
└── integration/
    └── test_scenario_workflow.py    # End-to-end tests
```

### Running Tests

```bash
# All tests
pytest tests/

# Unit tests only
pytest tests/unit/

# Integration tests
pytest tests/integration/

# With coverage
pytest tests/ --cov=src/scenarios --cov-report=html

# Specific test
pytest tests/unit/test_scenario_parser.py::TestParseCosts::test_single_cost_dimension
```

### Design for Testability

1. **Pure Functions**: `parser.py` and `generator.py` are pure functions - pass in strings/data, get back results. No mocking needed.

2. **Dependency Injection**: `ScenarioPreprocessor` can be initialized with custom timeout, making it easy to test with fast timeouts.

3. **Fixtures**: `conftest.py` provides reusable fixtures:
   - `tmp_scenario_dir`: Temporary directory for test files
   - `sample_scenario_content`: Example .pv file with magical comments
   - `sample_scenario_file`: Actual file created in temp directory

## Migration from Old Code

The old `scenario_preprocessor.py` has been split:

| Old Code | New Location |
|----------|--------------|
| `AttackVariant`, `AttackerCapability`, etc. | `src/scenarios/models.py` |
| `parse_costs()`, `parse_magical_comment()` | `src/scenarios/parser.py` |
| `extract_attacker_capabilities()` | `src/scenarios/parser.py` |
| `generate_scenario_combinations()`, `build_scenario_content()` | `src/scenarios/generator.py` |
| `extract_queries()` | `src/scenarios/generator.py` |
| `analyze_minimal_false_combinations()` | `src/scenarios/analyzer.py` |
| `print_headline()`, `print_subheading()` | `src/common/formatting.py` |
| `ScenarioPreprocessor` (orchestrator) | `src/scenarios/preprocessor.py` |

**Backward Compatibility**: `scenario_preprocessor_refactored.py` provides the same CLI interface as the old script.

## Benefits of Refactoring

| Aspect | Benefit |
|--------|---------|
| **Modularity** | Each module has single responsibility; 50-150 lines each |
| **Testability** | Pure functions need no mocking; modules have 100% coverage potential |
| **Reusability** | Import just `parse_costs()` or `generate_scenario_combinations()` in other scripts |
| **Maintainability** | Clear separation of concerns; related code grouped |
| **Extensibility** | Easy to add new analyzers, generators, or parsers without touching existing code |
| **Documentation** | Each module's purpose is self-evident |

## Next Steps

Phase 2 (after scenario refactoring verified):
- Refactor `attack_tree` module similarly
- Create `src/proverif/` for ProVerif runner and parser
- Create integration tests combining scenario and attack tree workflows
