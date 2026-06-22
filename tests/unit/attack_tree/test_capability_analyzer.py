"""Comprehensive tests for CapabilityAnalyzer."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from proverifbatch.attack_tree import CapabilityAnalyzer, DerivationTree
from proverifbatch.proverif import ProVerifOutput, Clause, Derivation
from proverifbatch.scenarios.models import AttackVariant, ScenarioFile


class TestCapabilityAnalyzerInitialization:
    """Test CapabilityAnalyzer initialization and setup."""

    def test_init_default(self):
        """Test initializing analyzer with default parameters."""
        analyzer = CapabilityAnalyzer()
        assert analyzer.base_clauses == set()
        assert analyzer.capability_clauses == {}
        assert analyzer.capability_clause_numbers == {}
        assert analyzer.capability_costs == {}

    def test_init_with_capability_costs(self):
        """Test initializing analyzer with capability costs."""
        costs = {
            "brute_force": {"time": 10, "hack": 1},
            "rainbow_attack": {"time": 5, "hack": 2},
        }
        analyzer = CapabilityAnalyzer(capability_costs=costs)
        assert analyzer.capability_costs == costs


class TestClausesStructurallyMatch:
    """Test fuzzy structural clause matching."""

    def test_exact_match(self):
        """Test exact clause text match."""
        analyzer = CapabilityAnalyzer()
        clause = "attacker(password[])"
        assert analyzer._clauses_structurally_match(clause, clause)

    def test_variable_name_normalization(self):
        """Test that variable names with different numbers normalize."""
        analyzer = CapabilityAnalyzer()
        clause1 = "table(singularizations(uid0_1, r0_2))"
        clause2 = "table(singularizations(uid0_5, r0_9))"
        assert analyzer._clauses_structurally_match(clause1, clause2)

    def test_different_structure_no_match(self):
        """Test that structurally different clauses don't match."""
        analyzer = CapabilityAnalyzer()
        clause1 = "table(passwords(x))"
        clause2 = "table(hashes(x))"
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_different_arity_no_match(self):
        """Test that different function arity prevents matching."""
        analyzer = CapabilityAnalyzer()
        clause1 = "func(a, b)"
        clause2 = "func(a, b, c)"
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_different_nesting_no_match(self):
        """Test that different nesting levels don't match."""
        analyzer = CapabilityAnalyzer()
        clause1 = "table(x(y(z)))"
        clause2 = "table(x(z))"
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_empty_clauses(self):
        """Test matching empty clauses."""
        analyzer = CapabilityAnalyzer()
        assert analyzer._clauses_structurally_match("", "")

    def test_uppercase_constants_preserved(self):
        """Test that uppercase constants are preserved in matching."""
        analyzer = CapabilityAnalyzer()
        clause1 = "event(auth(ADMIN, user0_1))"
        clause2 = "event(auth(ADMIN, user0_5))"
        assert analyzer._clauses_structurally_match(clause1, clause2)

    def test_different_uppercase_constants_no_match(self):
        """Test that different constants prevent matching."""
        analyzer = CapabilityAnalyzer()
        clause1 = "event(auth(ADMIN, user0_1))"
        clause2 = "event(auth(USER, user0_1))"
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_proverif_global_constants_preserved(self):
        """ProVerif global constants (name[]) must not be normalised away.

        Regression: attacker(singularization_server_secret[]) was previously
        matched against attacker(user1[]) because the constant name was stripped
        to X, yielding identical normal forms attacker(X[]).
        """
        analyzer = CapabilityAnalyzer()
        clause1 = "attacker(singularization_server_secret[])"
        clause2 = "attacker(user1[])"
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_proverif_same_global_constant_matches(self):
        """Two occurrences of the same global constant should still match."""
        analyzer = CapabilityAnalyzer()
        clause = "attacker(singularization_server_secret[])"
        assert analyzer._clauses_structurally_match(clause, clause)

    def test_function_names_not_normalised(self):
        """Function names must not be replaced with X.

        Regression: clauses like 'attacker(hashed(m,s)) && attacker(s) -> attacker(m)'
        (rainbow table attack) were normalised to the same form as
        'attacker(singularized(m,r)) && attacker(r) -> attacker(m)' (base scenario),
        causing the rainbow-table capability to appear to introduce no new clauses.
        """
        analyzer = CapabilityAnalyzer()
        clause1 = "attacker(hashed(m,s)) && attacker(s) -> attacker(m)"
        clause2 = "attacker(singularized(m,r)) && attacker(r) -> attacker(m)"
        assert not analyzer._clauses_structurally_match(clause1, clause2)


class TestAnalyzeFromManifest:
    """Test capability analysis from manifest.json files."""

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_from_manifest_collects_capability_costs(self, mock_extract):
        """Manifest-based analyzer should expose capability costs for rendering."""
        base_output = ProVerifOutput(clauses=[], derivations=[])
        cap_output = ProVerifOutput(
            clauses=[
                Clause(head="table(rainbow(h))", original_text="table(rainbow(h))", clause_number=2)
            ],
            derivations=[],
        )
        mock_extract.side_effect = [base_output, cap_output]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            manifest = {
                "input_file": "test.pv",
                "scenarios": [
                    {
                        "file": "base.pv",
                        "path": "base.pv",
                        "capabilities": [],
                    },
                    {
                        "file": "rainbow.pv",
                        "path": "rainbow.pv",
                        "capabilities": [
                            {"name": "Rainbow", "costs": {"time": 5}}
                        ],
                    },
                ],
            }
            json.dump(manifest, f)
            manifest_path = Path(f.name)

        try:
            analyzer = CapabilityAnalyzer.from_manifest(manifest_path)
            assert analyzer.capability_costs == {"Rainbow": {"time": 5}}
        finally:
            manifest_path.unlink()

    def test_analyze_no_base_scenario(self):
        """Test analyzing manifest without base scenario."""
        analyzer = CapabilityAnalyzer()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            manifest = {
                "input_file": "test.pv",
                "scenarios": [
                    {
                        "file": "cap.pv",
                        "path": "cap.pv",
                        "capabilities": [{"name": "attack"}],
                    }
                ],
            }
            json.dump(manifest, f)
            manifest_path = Path(f.name)

        try:
            result = analyzer.analyze_from_manifest(manifest_path)
            assert result == {}
        finally:
            manifest_path.unlink()

    def test_analyze_empty_manifest(self):
        """Test analyzing empty manifest."""
        analyzer = CapabilityAnalyzer()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            manifest = {"input_file": "test.pv", "scenarios": []}
            json.dump(manifest, f)
            manifest_path = Path(f.name)

        try:
            result = analyzer.analyze_from_manifest(manifest_path)
            assert result == {}
        finally:
            manifest_path.unlink()

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_analyze_identifies_new_clauses(self, mock_extract):
        """Test that analysis correctly identifies clauses unique to capabilities."""
        analyzer = CapabilityAnalyzer()

        # Base has clause 1
        base_output = ProVerifOutput(
            clauses=[
                Clause(head="table(passwords(h))", original_text="table(passwords(h))", clause_number=1)
            ],
            derivations=[],
        )

        # Capability has clause 1 AND a new clause 2
        cap_output = ProVerifOutput(
            clauses=[
                Clause(head="table(passwords(h))", original_text="table(passwords(h))", clause_number=1),
                Clause(head="table(rainbow(h))", original_text="table(rainbow(h))", clause_number=2),
            ],
            derivations=[],
        )

        mock_extract.side_effect = [base_output, cap_output]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            manifest = {
                "input_file": "test.pv",
                "scenarios": [
                    {"file": "base.pv", "path": "base.pv", "capabilities": []},
                    {"file": "rainbow.pv", "path": "rainbow.pv", "capabilities": [{"name": "Rainbow"}]},
                ],
            }
            json.dump(manifest, f)
            manifest_path = Path(f.name)

        try:
            result = analyzer.analyze_from_manifest(manifest_path)
            assert "Rainbow" in result
            assert "table(rainbow(h))" in result["Rainbow"]
        finally:
            manifest_path.unlink()


class TestAnalyzeFromScenarios:
    """Test capability analysis directly from generated scenario objects."""

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_from_scenarios_identifies_new_clauses_without_manifest(self, mock_extract):
        """API consumers should be able to build attribution from generated scenarios alone."""
        base_output = ProVerifOutput(
            clauses=[
                Clause(
                    head="table(passwords(h))",
                    original_text="table(passwords(h))",
                    clause_number=1,
                )
            ],
            derivations=[],
        )
        cap_output = ProVerifOutput(
            clauses=[
                Clause(
                    head="table(passwords(h))",
                    original_text="table(passwords(h))",
                    clause_number=1,
                ),
                Clause(
                    head="table(rainbow(h))",
                    original_text="table(rainbow(h))",
                    clause_number=2,
                ),
            ],
            derivations=[],
        )
        mock_extract.side_effect = [base_output, cap_output]

        scenarios = [
            ScenarioFile(
                path=Path("base.pv"),
                capabilities=[],
                costs={},
                queries=[],
            ),
            ScenarioFile(
                path=Path("rainbow.pv"),
                capabilities=[AttackVariant(name="Rainbow", costs={"time": 5})],
                costs={"time": 5},
                queries=[],
            ),
        ]

        analyzer = CapabilityAnalyzer.from_scenarios(scenarios)

        assert analyzer is not None
        assert analyzer.capability_costs == {"Rainbow": {"time": 5}}
        assert analyzer.capability_clauses == {"Rainbow": {"table(rainbow(h))"}}

    def test_from_scenarios_requires_base_and_singleton_support(self):
        """Analyzer construction should fail fast when support scenarios are missing."""
        scenarios = [
            ScenarioFile(
                path=Path("combo.pv"),
                capabilities=[
                    AttackVariant(name="Rainbow", costs={"time": 5}),
                    AttackVariant(name="Database", costs={"hack": 1}),
                ],
                costs={"time": 5, "hack": 1},
                queries=[],
            )
        ]

        analyzer = CapabilityAnalyzer.from_scenarios(scenarios)

        assert analyzer is None


class TestUpdateCapabilityClauseNumbers:
    """Test updating capability clause numbers from ProVerif output."""

    def test_update_empty_output(self):
        """Test update with empty output."""
        analyzer = CapabilityAnalyzer()
        output = ProVerifOutput(clauses=[], derivations=[])
        analyzer.update_capability_clause_numbers_from_output(output)
        assert analyzer.capability_clause_numbers == {}

    def test_update_with_no_clauses_in_derivations(self):
        """Test update when no clauses are referenced in derivations."""
        analyzer = CapabilityAnalyzer()
        output = ProVerifOutput(
            clauses=[
                Clause(head="unused", original_text="unused", clause_number=1)
            ],
            derivations=[Derivation(conclusion="goal", rule_name="goal", indent_level=0)],
        )
        analyzer.update_capability_clause_numbers_from_output(output)
        # No clauses referenced in derivations, so nothing to update
        assert analyzer.capability_clause_numbers == {}


class TestAnnotateTreeWithCapabilities:
    """Test tree annotation with capabilities."""

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_annotate_tree_with_goal_only(self, mock_extract):
        """Test annotating a tree with just goal node."""
        analyzer = CapabilityAnalyzer()
        analyzer.capability_clauses = {}
        mock_extract.return_value = ProVerifOutput(clauses=[], derivations=[])

        tree = DerivationTree(goal="attacker(x)")
        result = analyzer.annotate_tree_with_capabilities(tree, Path("test.pv"))

        assert result is tree
        assert tree.goal == "attacker(x)"

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_annotate_single_capability_node(self, mock_extract):
        """Test annotating node with single matching capability leaf."""
        analyzer = CapabilityAnalyzer()
        analyzer.capability_clauses = {
            "Brute Force": {"guess(password)"}
        }

        output = ProVerifOutput(
            clauses=[
                Clause(head="guess(password)", original_text="guess(password)", clause_number=2)
            ],
            derivations=[],
        )
        mock_extract.return_value = output

        tree = DerivationTree(goal="goal")
        tree.add_node("guess(password)", rule="clause", clause_number=2)

        analyzer.annotate_tree_with_capabilities(tree, Path("test.pv"))

        capability_nodes = [
            node
            for node in tree.nodes.values()
            if node.node_type == "capability" and node.fact == "Brute Force"
        ]
        assert len(capability_nodes) == 1

        fact_to_capability_edges = [
            (source_key, target_key)
            for source_key, target_key in tree.edges
            if source_key[0] == "guess(password)"
            and tree.nodes[target_key].node_type == "capability"
            and tree.nodes[target_key].fact == "Brute Force"
        ]
        assert len(fact_to_capability_edges) == 1

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_annotate_handles_missing_clauses_gracefully(self, mock_extract):
        """Test that annotation doesn't crash with unrecognized clauses."""
        analyzer = CapabilityAnalyzer()
        analyzer.capability_clauses = {"Known": {"known_clause()"}}

        output = ProVerifOutput(
            clauses=[
                Clause(head="unknown()", original_text="unknown()", clause_number=1)
            ],
            derivations=[],
        )
        mock_extract.return_value = output

        tree = DerivationTree(goal="goal")
        tree.add_node("unknown()", rule="clause", clause_number=1)

        # Should not crash
        result = analyzer.annotate_tree_with_capabilities(tree, Path("test.pv"))
        assert result is tree

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_or_capability_leaves_do_not_duplicate_fact_nodes(self, mock_extract):
        """Multiple capability alternatives should become capability leaves under one fact node."""
        analyzer = CapabilityAnalyzer(
            capability_costs={
                "Rainbow table attack": {"time": 100},
                "Side-channel attack": {"observation": 10, "time": 10},
            }
        )
        analyzer.capability_clauses = {
            "Rainbow table attack": {"attacker(secret[])"},
            "Side-channel attack": {"attacker(secret[])"},
        }

        output = ProVerifOutput(
            clauses=[
                Clause(
                    head="attacker(secret[])",
                    original_text="attacker(secret[])",
                    clause_number=1,
                    clause_scope=None,
                )
            ],
            derivations=[],
        )
        mock_extract.return_value = output

        tree = DerivationTree(goal="goal")
        tree.add_node("attacker(secret[])", rule="clause", clause_number=1)
        tree.add_edge("goal", "attacker(secret[])")

        analyzer.annotate_tree_with_capabilities(tree, Path("test.pv"))

        fact_nodes = [
            key for key, node in tree.nodes.items() if node.node_type == "fact" and key[0] == "attacker(secret[])"
        ]
        assert fact_nodes == [("attacker(secret[])", None)]

        capability_nodes = [
            node.fact for node in tree.nodes.values() if node.node_type == "capability"
        ]
        assert sorted(capability_nodes) == ["Rainbow table attack", "Side-channel attack"]

        dot_output = tree.to_graphviz()
        assert dot_output.count('label="OR"') == 2


class TestCapabilityAnalyzerIntegration:
    """Integration tests for full workflows."""

    @patch("proverifbatch.attack_tree.capability_analyzer.CapabilityAnalyzer._extract_clauses_from_scenario")
    def test_full_workflow_analyze_and_annotate(self, mock_extract):
        """Test complete workflow: analyze manifest and annotate tree."""
        analyzer = CapabilityAnalyzer(capability_costs={"Rainbow": {"time": 5}})

        # Prepare mock outputs
        base_output = ProVerifOutput(
            clauses=[
                Clause(head="table(pwd)", original_text="table(pwd)", clause_number=1)
            ],
            derivations=[],
        )
        rainbow_output = ProVerifOutput(
            clauses=[
                Clause(head="table(pwd)", original_text="table(pwd)", clause_number=1),
                Clause(head="table(rainbow)", original_text="table(rainbow)", clause_number=2),
            ],
            derivations=[],
        )

        mock_extract.side_effect = [base_output, rainbow_output, rainbow_output]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            manifest = {
                "input_file": "test.pv",
                "scenarios": [
                    {"file": "base.pv", "path": "base.pv", "capabilities": []},
                    {"file": "rainbow.pv", "path": "rainbow.pv", "capabilities": [{"name": "Rainbow"}]},
                ],
            }
            json.dump(manifest, f)
            manifest_path = Path(f.name)

        try:
            # Analyze
            analyzer.analyze_from_manifest(manifest_path)
            assert "Rainbow" in analyzer.capability_clauses

            # Annotate
            tree = DerivationTree(goal="goal")
            tree.add_node("table(rainbow)", rule="clause", clause_number=2)
            analyzer.annotate_tree_with_capabilities(tree, Path("rainbow.pv"))

            # Tree should be modified
            assert len(tree.nodes) > 1

        finally:
            manifest_path.unlink()
