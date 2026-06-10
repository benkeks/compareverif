"""Analyze which clauses and facts are introduced by specific capabilities."""

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Set, Tuple

from proverifbatch.proverif import ProVerifRunner, ProVerifOutputParser, ProVerifOutput

if TYPE_CHECKING:
    from proverifbatch.scenarios.models import ScenarioFile


class CapabilityAnalyzer:
    """Analyzes which clauses and facts are introduced by specific capabilities."""

    def __init__(self, capability_costs: Optional[Dict[str, Dict[str, int]]] = None):
        self.base_clauses: Set[str] = set()
        self.capability_clauses: Dict[str, Set[str]] = {}
        self.capability_clause_numbers: Dict[
            str, List[Tuple[Optional[Set[int]], int, str]]
        ] = {}
        self.capability_costs = (
            capability_costs or {}
        )  # Map: capability name -> {"time": X, "hack": Y, ...}

    @classmethod
    def from_scenarios(
        cls,
        scenarios: Sequence["ScenarioFile"],
    ) -> Optional["CapabilityAnalyzer"]:
        """Build an analyzer directly from generated scenarios.

        This is the library counterpart to the manifest-based CLI workflow and is
        intended for API consumers such as notebooks.
        """
        if not scenarios:
            return None

        analyzer = cls(cls._collect_capability_costs_from_scenarios(scenarios))
        analysis = analyzer.analyze_from_scenarios(scenarios)
        if analysis is None:
            return None
        return analyzer

    @staticmethod
    def _collect_capability_costs_from_scenarios(
        scenarios: Sequence["ScenarioFile"],
    ) -> Dict[str, Dict[str, int]]:
        """Collect one cost mapping per capability from generated scenarios."""
        capability_costs: Dict[str, Dict[str, int]] = {}
        for scenario in scenarios:
            for capability in scenario.capabilities:
                if capability.name not in capability_costs and capability.costs:
                    capability_costs[capability.name] = capability.costs
        return capability_costs

    def analyze_from_scenarios(
        self,
        scenarios: Sequence["ScenarioFile"],
    ) -> Optional[Dict[str, Set[str]]]:
        """Analyze capabilities by comparing generated base and singleton scenarios."""
        base_scenario = next((scenario for scenario in scenarios if not scenario.capabilities), None)
        single_capability_scenarios = [
            scenario for scenario in scenarios if len(scenario.capabilities) == 1
        ]

        if base_scenario is None or not single_capability_scenarios:
            return None

        return self._analyze_from_scenario_paths(
            base_scenario.path,
            [
                (scenario.capabilities[0].name, scenario.path)
                for scenario in single_capability_scenarios
            ],
            verbose=False,
        )

    def analyze_from_manifest(self, manifest_path: Path) -> Dict[str, Set[str]]:
        """
        Analyze capabilities by comparing base scenario with single-capability scenarios.

        Args:
            manifest_path: Path to manifest.json file

        Returns:
            Dict mapping capability names to sets of clause text introduced by that capability
        """
        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        # Find base scenario (no capabilities)
        base_scenario = None
        single_capability_scenarios = []

        for scenario in manifest["scenarios"]:
            if len(scenario["capabilities"]) == 0:
                base_scenario = scenario
            elif len(scenario["capabilities"]) == 1:
                single_capability_scenarios.append(scenario)

        if not base_scenario:
            print(f"Warning: No base scenario found in {manifest_path}")
            return {}

        return self._analyze_from_scenario_paths(
            Path(base_scenario["path"]),
            [
                (scenario["capabilities"][0]["name"], Path(scenario["path"]))
                for scenario in single_capability_scenarios
            ],
            verbose=True,
        )

    def _analyze_from_scenario_paths(
        self,
        base_scenario_path: Path,
        single_capability_scenarios: List[Tuple[str, Path]],
        *,
        verbose: bool,
    ) -> Dict[str, Set[str]]:
        """Populate capability clause attribution from base and singleton scenarios."""
        self.capability_clauses = {}

        # Extract clauses from base scenario
        base_output = self._extract_clauses_from_scenario(base_scenario_path)
        self.base_clauses = set(c.original_text for c in base_output.clauses)

        # Compare each single-capability scenario with base
        for cap_name, scenario_path in single_capability_scenarios:
            cap_output = self._extract_clauses_from_scenario(scenario_path)
            cap_clauses = set(c.original_text for c in cap_output.clauses)

            # Find clauses only in capability scenario
            # Use fuzzy matching: if base has a structurally similar clause, don't mark as new
            new_clauses = set()
            for cap_clause in cap_clauses:
                is_new = True
                for base_clause in self.base_clauses:
                    if cap_clause == base_clause or self._clauses_structurally_match(
                        cap_clause, base_clause
                    ):
                        is_new = False
                        break
                if is_new:
                    new_clauses.add(cap_clause)

            self.capability_clauses[cap_name] = new_clauses

            if verbose:
                print(f"  {cap_name}: {len(new_clauses)} new clauses")

        return self.capability_clauses

    def _clauses_structurally_match(self, clause1: str, clause2: str) -> bool:
        """
        Check if two clauses have the same structure, ignoring variable names.

        Example:
            "table(singularizations(uid0_1,r0_2))" matches
            "table(singularizations(uid0_2,r0_2))" (same structure, different var names)
        """

        def normalize_clause(clause: str) -> str:
            # Replace variable names (lowercase identifiers) with X.
            # Exclude identifiers followed by '(', '_', or '[': function calls and
            # global constants (ProVerif writes constants as name[]) should not be
            # normalised away, since different constant names are semantically distinct.
            normalized = re.sub(r"\b[a-z_]\w*\d*(?![_([])\b", "X", clause)
            return normalized

        return normalize_clause(clause1) == normalize_clause(clause2)

    def update_capability_clause_numbers_from_output(
        self, output: ProVerifOutput
    ) -> None:
        """Populate and print capability clause numbers based on the scenario's derivations."""
        self.capability_clause_numbers = {}
        all_clause_initial: Dict[Tuple[int, str], bool] = {}

        # First, collect all clauses that are actually used in derivations
        clauses_in_derivations: Set[int] = set()
        for deriv in output.derivations:
            if deriv.clause_number is not None:
                clauses_in_derivations.add(deriv.clause_number)

        # For each clause used in derivations, find which capabilities introduced it
        clause_to_caps: Dict[Tuple[int, str], Tuple[Set[str], Set[int]]] = {}

        for clause in output.clauses:
            if (
                clause.clause_number is None
                or clause.clause_number not in clauses_in_derivations
            ):
                continue

            # Check which capabilities have a clause with similar text
            clause_text = clause.original_text
            matching_caps = set()

            for cap_name, cap_clauses in self.capability_clauses.items():
                # Try exact match first
                if clause_text in cap_clauses:
                    matching_caps.add(cap_name)
                else:
                    # Try fuzzy match: same structure, ignoring variable names
                    for cap_clause_text in cap_clauses:
                        if self._clauses_structurally_match(clause_text, cap_clause_text):
                            matching_caps.add(cap_name)
                            break

            if matching_caps:
                key = (clause.clause_number, clause_text)
                if key not in clause_to_caps:
                    clause_to_caps[key] = (matching_caps, set())
                caps, scopes = clause_to_caps[key]
                if clause.clause_scope is not None:
                    scopes.add(clause.clause_scope)
                all_clause_initial[key] = clause.is_initial

        # Reorganize by capability
        for cap_name in sorted(self.capability_clauses.keys()):
            cap_clauses_list = []
            for (clause_num, clause_text), (caps, scopes) in clause_to_caps.items():
                if cap_name in caps:
                    cap_clauses_list.append(
                        (scopes if scopes else None, clause_num, clause_text)
                    )

            cap_clauses_list.sort(key=lambda item: (item[1], item[2]))
            self.capability_clause_numbers[cap_name] = cap_clauses_list

        # Print capability-attributed clauses
        if self.capability_clause_numbers:
            print("\nCapability clauses (by capability):")
            for cap_name in sorted(self.capability_clause_numbers.keys()):
                entries = self.capability_clause_numbers[cap_name]
                print(f"\n{cap_name}:")
                if not entries:
                    print("  (none)")
                    continue
                for clause_scopes, clause_number, clause_text in entries:
                    clause_tag = (
                        "initial"
                        if all_clause_initial.get((clause_number, clause_text), False)
                        else "derived"
                    )
                    if clause_scopes:
                        query_indices = ", ".join(
                            str(scope + 1) for scope in sorted(clause_scopes)
                        )
                        print(
                            f"  Clause {clause_number} (Query {query_indices}) [{clause_tag}]: {clause_text}"
                        )
                    else:
                        print(
                            f"  Clause {clause_number} [{clause_tag}]: {clause_text}"
                        )

    def _extract_clauses_from_scenario(self, scenario_path: Path) -> ProVerifOutput:
        """Extract clauses from a scenario file, including completed clauses."""
        runner = ProVerifRunner()
        parser = ProVerifOutputParser()

        try:
            # Use verboseClauses to get ALL clauses, including those generated during saturation
            return_code, stdout, stderr = runner.run(
                scenario_path, verbose_clauses=True, clause_verbosity="short"
            )
            return parser.parse(stdout)
        except Exception as e:
            print(f"Warning: Failed to extract clauses from {scenario_path}: {e}")
            return ProVerifOutput()

    def annotate_tree_with_capabilities(
        self, tree, scenario_path: Path
    ):
        """
        Annotate tree nodes with the capabilities that introduced them.
        Creates separate variant nodes when multiple capabilities can achieve the same result.

        Uses clause text comparison to determine which capabilities introduce new clauses.

        Args:
            tree: DerivationTree to annotate
            scenario_path: Path to the scenario file

        Returns:
            Annotated tree (modifies in place, but also returns for convenience)
        """

        # Extract clauses and derivations from the scenario
        output = self._extract_clauses_from_scenario(scenario_path)

        # Build mapping from clause number to capabilities
        clause_num_to_caps: Dict[Tuple[Optional[int], int], Set[str]] = {}

        for clause in output.clauses:
            if clause.clause_number is None:
                continue

            matching_caps = set()
            clause_text = clause.original_text

            # Check if clause text appears in any capability's new clauses
            for cap_name, cap_clauses in self.capability_clauses.items():
                # Try exact match first
                if clause_text in cap_clauses:
                    matching_caps.add(cap_name)
                else:
                    # Try fuzzy match: same structure, ignoring variable names
                    for cap_clause_text in cap_clauses:
                        if self._clauses_structurally_match(clause_text, cap_clause_text):
                            matching_caps.add(cap_name)
                            break

            if matching_caps:
                clause_key = (clause.clause_scope, clause.clause_number)
                clause_num_to_caps[clause_key] = matching_caps

        # First pass: collect capabilities for each fact based on the clause used to derive it
        node_capabilities: Dict[Tuple[str, Optional[str]], Set[str]] = {}

        for key, node in list(tree.nodes.items()):
            fact, variant_id = key
            # Skip only the dedicated goal node
            if variant_id == tree.GOAL_VARIANT:
                continue

            capabilities = set()

            # Check clause number to see if this node was derived using a capability-specific clause
            if node.clause_number is not None:
                clause_key = (node.clause_scope, node.clause_number)
                if clause_key in clause_num_to_caps:
                    capabilities.update(clause_num_to_caps[clause_key])
                else:
                    fallback_key = (None, node.clause_number)
                    if fallback_key in clause_num_to_caps:
                        print(
                            f"Warning: Using unscoped clause match for clause {node.clause_number} "
                            f"(node fact: {fact})"
                        )
                        capabilities.update(clause_num_to_caps[fallback_key])

            if capabilities:
                node_capabilities[key] = capabilities

        # Add dedicated capability leaf nodes under facts derived via those capabilities.
        for (fact, variant_id), caps in sorted(node_capabilities.items()):
            if (fact, variant_id) not in tree.nodes:
                continue

            for cap in sorted(caps):
                scope = tree.nodes[(fact, variant_id)].clause_scope
                clause_number = tree.nodes[(fact, variant_id)].clause_number
                cap_variant = (
                    f"capability_leaf::{variant_id or 'base'}::{scope if scope is not None else 'global'}::"
                    f"{clause_number if clause_number is not None else 'none'}::{cap}"
                )
                tree.add_node(
                    cap,
                    rule=tree.CAPABILITY_RULE,
                    node_type="capability",
                    capabilities={cap},
                    variant_id=cap_variant,
                )
                tree.add_edge(
                    fact,
                    cap,
                    source_variant=variant_id,
                    target_variant=cap_variant,
                    source_node_type="fact",
                    target_node_type="capability",
                )

        return tree
