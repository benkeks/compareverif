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
    generate_capability_presence_combinations,
    generate_base_capability_presence_combination,
    generate_full_capability_presence_combination,
    generate_support_scenario_combinations,
    generate_scenario_combinations,
    build_scenario_content,
)
from .analyzer import analyze_minimal_false_combinations
from .serialization import format_costs, build_manifest_scenario_entry
from .preprocessor import ScenarioPreprocessor

__all__ = [
    "AttackVariant",
    "AttackerCapability",
    "ScenarioFile",
    "ScenarioResult",
    "parse_costs",
    "parse_magical_comment",
    "extract_attacker_capabilities",
    "generate_capability_presence_combinations",
    "generate_base_capability_presence_combination",
    "generate_full_capability_presence_combination",
    "generate_support_scenario_combinations",
    "generate_scenario_combinations",
    "build_scenario_content",
    "format_costs",
    "build_manifest_scenario_entry",
    "analyze_minimal_false_combinations",
    "ScenarioPreprocessor",
]
