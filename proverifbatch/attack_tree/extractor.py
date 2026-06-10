"""Main orchestrator for attack tree extraction."""

from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Sequence

from proverifbatch.proverif import Derivation, ProVerifRunner, ProVerifOutputParser, ProVerifOutput
from proverifbatch.proverif.runner import DEFAULT_TIMEOUT

from .capability_analyzer import CapabilityAnalyzer
from .models import DerivationTree
from .renderer import GraphvizRenderer

if TYPE_CHECKING:
    from proverifbatch.scenarios.models import ScenarioFile


def _normalize_query_text(query: str) -> str:
    """Normalize query text so scenario query declarations match derivation query facts."""
    if not query:
        return ""

    normalized = re.sub(r"\(\*.*?\*\)", "", query)
    normalized = normalized.strip().lower()
    normalized = normalized.replace("query ", "")
    normalized = normalized.replace("weaksecret ", "")
    normalized = normalized.replace("\n", "")
    normalized = normalized.replace(" ", "")
    normalized = normalized.replace("[", "").replace("]", "")
    normalized = normalized.replace(";", "").replace(".", "")
    return normalized


def _build_query_tag_filter(
    query_tag: str,
    scenario_queries: Sequence[Dict[str, str]],
) -> Optional[Callable[[Derivation], bool]]:
    """Resolve a scenario query tag to a derivation filter."""
    target_queries = {
        _normalize_query_text(query_info.get("query", ""))
        for query_info in scenario_queries
        if _normalize_query_text(query_info.get("tag", ""))
        == _normalize_query_text(query_tag)
    }
    target_queries.discard("")
    if not target_queries:
        return None

    return lambda derivation: _normalize_query_text(derivation.query or "") in target_queries


@dataclass
class AttackTreeBuildResult:
    """Structured result for high-level attack-tree extraction."""

    output: ProVerifOutput
    derivations: List[Derivation]
    tree: Optional[DerivationTree]
    capability_analyzer: Optional[CapabilityAnalyzer] = None


class AttackTreeExtractor:
    """Main orchestrator for extracting attack trees from ProVerif."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.runner = ProVerifRunner(timeout=timeout)
        self.parser = ProVerifOutputParser()

    def extract(
        self, scenario_file: Path, verbose_clauses: bool = True
    ) -> ProVerifOutput:
        """
        Run ProVerif and extract clauses and derivations.

        Args:
            scenario_file: Path to the ProVerif file
            verbose_clauses: Whether to use short clause verbosity

        Returns:
            ProVerifOutput containing extracted information
        """
        try:
            return_code, stdout, stderr = self.runner.run(scenario_file, verbose_clauses)
            output = self.parser.parse(stdout)
            if stderr:
                output.errors = stderr.split("\n")
            return output
        except FileNotFoundError as e:
            output = ProVerifOutput()
            output.errors = [str(e)]
            return output
        except TimeoutError as e:
            output = ProVerifOutput()
            output.errors = [str(e)]
            return output

    def extract_tree(
        self,
        scenario_file: Path,
        *,
        query_tag: Optional[str] = None,
        derivation_filter: Optional[Callable[[Derivation], bool]] = None,
        capability_analyzer: Optional[CapabilityAnalyzer] = None,
        capability_scenarios: Optional[Sequence["ScenarioFile"]] = None,
        scenario_queries: Optional[Sequence[Dict[str, str]]] = None,
        readable_nodes: bool = False,
        show_clause_ids: bool = False,
        highlight_attack: bool = False,
        verbose_clauses: bool = True,
    ) -> AttackTreeBuildResult:
        """Extract ProVerif output and build an optionally capability-annotated tree."""
        output = self.extract(scenario_file, verbose_clauses=verbose_clauses)
        derivations = output.derivations
        if derivation_filter is None and query_tag and scenario_queries is not None:
            derivation_filter = _build_query_tag_filter(query_tag, scenario_queries)
        if derivation_filter is not None:
            derivations = [derivation for derivation in derivations if derivation_filter(derivation)]

        if capability_analyzer is None and capability_scenarios is not None:
            capability_analyzer = CapabilityAnalyzer.from_scenarios(capability_scenarios)

        capability_costs = (
            capability_analyzer.capability_costs if capability_analyzer is not None else None
        )
        tree = GraphvizRenderer.build_tree_from_derivations(
            derivations,
            query_tag=query_tag,
            capability_costs=capability_costs,
            readable_nodes=readable_nodes,
            show_clause_ids=show_clause_ids,
            highlight_attack=highlight_attack,
        )
        if tree is not None and capability_analyzer is not None:
            tree = capability_analyzer.annotate_tree_with_capabilities(tree, scenario_file)

        return AttackTreeBuildResult(
            output=output,
            derivations=derivations,
            tree=tree,
            capability_analyzer=capability_analyzer,
        )

    def print_summary(self, output: ProVerifOutput) -> None:
        """Print a summary of extracted information."""
        print(f"\n{'='*60}")
        print("Attack Tree Extraction Summary")
        print(f"{'='*60}")

        print(f"\nClauses extracted: {len(output.clauses)}")
        if output.clauses:
            max_display = min(10, len(output.clauses))
            for clause in output.clauses[:max_display]:
                clause_text = clause.original_text or str(clause)
                clause_num = (
                    str(clause.clause_number)
                    if clause.clause_number is not None
                    else "?"
                )
                scope_str = (
                    f" [Query {clause.clause_scope + 1}]"
                    if clause.clause_scope is not None
                    else ""
                )
                clause_str = f"Clause {clause_num}{scope_str}: {clause_text}"
                # Truncate if necessary
                if len(clause_str) > 70:
                    clause_str = clause_str[:67] + "..."
                clause_tag = "initial" if clause.is_initial else "derived"
                print(f"  {clause_str} [{clause_tag}]")
            if len(output.clauses) > 10:
                print(f"  ... and {len(output.clauses) - 10} more")

        print(f"\nDerivations extracted: {len(output.derivations)}")
        if output.derivations:
            max_display = min(10, len(output.derivations))
            for derivation in output.derivations[:max_display]:
                indent = "  " * derivation.indent_level
                rule_label = derivation.rule_name or "step"
                if rule_label == "clause" and derivation.clause_number is not None:
                    scope_str = (
                        f" [Query {derivation.query_scope + 1}]"
                        if derivation.query_scope is not None
                        else ""
                    )
                    rule_label = f"clause {derivation.clause_number}{scope_str}"
                deriv_str = f"{indent}{rule_label}: {derivation.conclusion}"
                # Truncate if necessary
                if len(deriv_str) > 70:
                    deriv_str = deriv_str[:67] + "..."
                print(f"  {deriv_str}")
            if len(output.derivations) > 10:
                print(f"  ... and {len(output.derivations) - 10} more")

        if output.errors:
            print(f"\nErrors encountered: {len(output.errors)}")
            for error in output.errors[:5]:
                if error.strip():
                    print(f"  - {error}")
