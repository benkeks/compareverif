"""Data models for scenarios."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Any, Optional


@dataclass
class AttackVariant:
    """Represents a cost variant of an attacker capability."""
    name: str
    costs: Dict[str, float]


@dataclass
class AttackerCapability:
    """Represents an attacker capability with multiple cost variants."""
    primary_name: str
    variants: List[AttackVariant]
    content: str


@dataclass
class ScenarioFile:
    """Result of generating a scenario file."""
    path: Path
    capabilities: List[AttackVariant]
    costs: Dict[str, float]
    queries: List[Dict[str, str]]
    capability_names: List[str] = field(default_factory=list)
    libraries: List[str] = field(default_factory=list)


@dataclass
class ScenarioResult:
    """Represents the result of verifying a generated scenario file."""
    scenario: ScenarioFile
    status: Optional[str] = None
    query_results: List[Dict[str, Any]] = field(default_factory=list)
    error_message: Optional[str] = None
