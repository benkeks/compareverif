# Scenario Module Refactoring - Summary

## What Was Done

The scenario preprocessing functionality from `scenario_preprocessor.py` has been refactored into a modular, testable architecture organized in `src/scenarios/`.

## New Structure

```
src/
├── __init__.py
├── scenarios/                    # Scenario processing modules
│   ├── __init__.py              # Exports public API
│   ├── models.py                # Data classes
│   ├── parser.py                # Parse file content (pure functions)
│   ├── generator.py             # Generate combinations (pure functions)
│   ├── analyzer.py              # Analyze results (pure function)
│   └── preprocessor.py          # Orchestrator class
└── common/                       # Shared utilities
    ├── __init__.py
    └── formatting.py            # Formatting utilities

tests/
├── conftest.py                  # Pytest fixtures
├── unit/                        # Unit tests (32 tests, all passing)
│   ├── test_scenario_parser.py
│   ├── test_scenario_generator.py
│   └── test_scenario_preprocessor.py
└── integration/                 # Integration tests (placeholder)
```

## Key Design Decisions

### 1. Separation of Concerns

| Module | Responsibility | Dependencies |
|--------|---|---|
| `models.py` | Data structures | None |
| `parser.py` | Parse text (pure) | models.py |
| `generator.py` | Generate combinations (pure) | models.py |
| `analyzer.py` | Analyze results (pure) | models.py |
| `preprocessor.py` | Orchestrate workflow | parser, generator, analyzer, subprocess |
| `common/formatting.py` | Formatting utilities | None |

### 2. Testability

**Pure Functions** (no mocking needed):
- `parse_costs()`, `parse_magical_comment()`, `extract_attacker_capabilities()`
- `generate_scenario_combinations()`, `build_scenario_content()`, `extract_queries()`
- `analyze_minimal_false_combinations()`

**Class with Setup**:
- `ScenarioPreprocessor` - can be initialized with different timeouts for fast tests

### 3. Backward Compatibility

- Original `scenario_preprocessor.py` still exists (unchanged)
- New `scenario_preprocessor_refactored.py` provides identical CLI interface
- Can run both versions in parallel during transition

## Testing

### Unit Tests: 32/32 Passing ✓

```bash
pytest tests/unit/ -v
```

Test categories:
- **Parser**: 12 tests covering cost parsing, magical comments, capability extraction
- **Generator**: 13 tests covering combinations, content building, query extraction, filenames
- **Preprocessor**: 7 tests covering initialization, preprocessing, analysis

### Test Infrastructure

**Fixtures** (in `conftest.py`):
- `tmp_scenario_dir`: Temporary directory for test files
- `sample_scenario_content`: Example .pv file with magical comments
- `sample_scenario_file`: Actual file in temp directory

**Pure Functions**: Can be tested directly without any fixtures

## Usage

### As a Library (Recommended for new code)

```python
from src.scenarios import ScenarioPreprocessor
from src.scenarios.parser import parse_costs
from src.scenarios.generator import extract_queries

# High-level usage
preprocessor = ScenarioPreprocessor()
scenarios, output_dir = preprocessor.preprocess("input.pv")
results = preprocessor.run_proverif(scenarios)
analysis = preprocessor.analyze(results, ["input.pv"])

# Low-level usage (pure functions)
costs = parse_costs("[100 time, 10 hack]")
queries = extract_queries(file_content)
```

### As a CLI (same as before)

```bash
python3 scenario_preprocessor_refactored.py input.pv
```

## Benefits

| Aspect | Before | After |
|--------|--------|-------|
| **Organization** | 1 monolithic file (500+ lines) | 6 focused modules (50-150 lines each) |
| **Testability** | Hard to test in isolation | 32 unit tests, easy to add more |
| **Reusability** | Must import entire module | Can import individual functions |
| **Maintainability** | All logic mixed together | Clear separation of concerns |
| **Documentation** | Single README | Per-module docstrings + REFACTORING.md |

## Next Phase: Attack Tree Module

The attack_tree refactoring will follow the same pattern:

```
src/
├── attack_tree/
│   ├── models.py           # TreeNode, DerivationTree
│   ├── builder.py          # Build from derivations
│   ├── renderer.py         # Graphviz rendering
│   ├── capability_analyzer.py  # Map capabilities to nodes
│   └── extractor.py        # Orchestrator
└── proverif/
    ├── runner.py           # Run ProVerif
    └── output_parser.py    # Parse ProVerif output
```

## Files Modified/Created

### New Files Created:
- `src/__init__.py`
- `src/scenarios/__init__.py`, `models.py`, `parser.py`, `generator.py`, `analyzer.py`, `preprocessor.py`
- `src/common/__init__.py`, `formatting.py`
- `tests/__init__.py`, `conftest.py`
- `tests/unit/__init__.py`, `test_scenario_*.py` files
- `tests/integration/__init__.py`
- `scenario_preprocessor_refactored.py` (new CLI using refactored modules)
- `REFACTORING.md` (detailed documentation)
- `pytest.ini` (test configuration)

### Original Files Unchanged:
- `scenario_preprocessor.py` (original, still works)
- `attack_tree_extractor.py` (unchanged, will be refactored in phase 2)
- All other project files

## Validation

✓ All 32 unit tests passing
✓ Refactored CLI produces identical output to original
✓ No breaking changes to existing code
✓ Ready for phase 2: Attack tree refactoring

## How to Proceed

1. **Verify**: Run `pytest tests/unit/ -v` to confirm all tests pass
2. **Test**: Try `python3 scenario_preprocessor_refactored.py singularized_passwords.pv` 
3. **Migrate**: Update any scripts that import from `scenario_preprocessor` to use `src.scenarios` instead
4. **Phase 2**: Refactor attack_tree module using same pattern
