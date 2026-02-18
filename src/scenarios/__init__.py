"""Scenario preprocessing, generation, and analysis."""

from .models import (
    AttackVariant,
    AttackerCapability,
    ScenarioFile,
    ScenarioResult,
)
from .parser import (
    parse_costs,
    parse_magical_comment,
    extract_attacker_capabilities,
)
from .generator import (
    generate_scenario_combinations,
    build_scenario_content,
)
from .analyzer import analyze_minimal_false_combinations
from .preprocessor import ScenarioPreprocessor

__all__ = [
    "AttackVariant",
    "AttackerCapability",
    "ScenarioFile",
    "ScenarioResult",
    "parse_costs",
    "parse_magical_comment",
    "extract_attacker_capabilities",
    "generate_scenario_combinations",
    "build_scenario_content",
    "analyze_minimal_false_combinations",
    "ScenarioPreprocessor",
]
