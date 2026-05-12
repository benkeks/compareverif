"""Unit tests for attack tree GraphvizRenderer."""

import pytest
from proverifbatch.proverif import Derivation
from proverifbatch.attack_tree import GraphvizRenderer, DerivationTree


class TestGraphvizRenderer:
    """Test GraphvizRenderer class."""

    def test_build_tree_empty_derivations(self):
        """Test building tree from empty derivations."""
        tree = GraphvizRenderer.build_tree_from_derivations([])
        assert tree is None

    def test_build_tree_single_goal(self):
        """Test building tree with just goal."""
        derivations = [
            Derivation(conclusion="attacker(x)", rule_name="goal", indent_level=0)
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(derivations)
        assert tree is not None
        assert tree.goal == "attacker(x)"
        assert len(tree.nodes) >= 1

    def test_build_tree_with_multiple_levels(self):
        """Test building tree with multiple derivation levels."""
        derivations = [
            Derivation(conclusion="attacker(x)", rule_name="goal", indent_level=0),
            Derivation(
                conclusion="event(auth)",
                rule_name="clause",
                indent_level=1,
                clause_number=5,
            ),
            Derivation(
                conclusion="initial_fact",
                rule_name="initial",
                indent_level=2,
            ),
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(derivations)
        assert len(tree.nodes) >= 3
        assert len(tree.edges) == 2  # Two parent-child relationships

    def test_build_tree_skips_apply_steps(self):
        """Test that apply transformations are skipped in tree building."""
        derivations = [
            Derivation(conclusion="tuple(a, b)", rule_name="goal", indent_level=0),
            Derivation(
                conclusion="a", rule_name="apply proj-fst", indent_level=1
            ),
            Derivation(
                conclusion="fact", rule_name="clause", indent_level=1
            ),
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(derivations)
        # Should have goal and clause, but not the apply step
        assert ("a", None) not in tree.nodes  # apply step not added

    def test_build_tree_with_query_tag(self):
        """Test building tree with query tag."""
        derivations = [
            Derivation(
                conclusion="attacker(x)", rule_name="goal", indent_level=0, query="test"
            )
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(
            derivations, query_tag="broken_query"
        )
        assert tree.query_tag == "broken_query"

    def test_build_tree_with_capability_costs(self):
        """Test building tree with capability costs."""
        derivations = [
            Derivation(conclusion="attacker(x)", rule_name="goal", indent_level=0)
        ]
        costs = {"brute_force": {"hack": 1, "time": 10}}
        tree = GraphvizRenderer.build_tree_from_derivations(
            derivations, capability_costs=costs
        )
        assert tree.capability_costs == costs

    def test_build_tree_readable_nodes(self):
        """Test building tree with readable nodes enabled."""
        derivations = [
            Derivation(
                conclusion="attacker(password[])", rule_name="goal", indent_level=0
            )
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(
            derivations, readable_nodes=True
        )
        assert tree.readable_nodes is True

    def test_build_tree_show_clause_ids(self):
        """Test building tree with clause IDs enabled."""
        derivations = [
            Derivation(
                conclusion="attacker(x)",
                rule_name="goal",
                indent_level=0,
            ),
            Derivation(
                conclusion="event(auth)",
                rule_name="clause",
                indent_level=1,
                clause_number=5,
            ),
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(
            derivations, show_clause_ids=True
        )
        assert tree.show_clause_ids is True

    def test_build_tree_highlight_attack(self):
        """Test building tree with attack highlighting enabled."""
        derivations = [
            Derivation(conclusion="attacker(x)", rule_name="goal", indent_level=0)
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(
            derivations, highlight_attack=True
        )
        assert tree.highlight_attack is True

    def test_build_tree_no_self_loops(self):
        """Test that self-loops are not created."""
        derivations = [
            Derivation(conclusion="attacker(x)", rule_name="goal", indent_level=0),
            Derivation(
                conclusion="attacker(x)", rule_name="duplicate", indent_level=1
            ),
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(derivations)
        # Check that no edges pointing to self are created
        for source_key, target_key in tree.edges:
            assert source_key[0] != target_key[0]  # Different facts

    def test_render_to_file(self, tmp_path):
        """Test rendering tree to dot file."""
        tree = DerivationTree(goal="attacker(x)")
        output_file = tmp_path / "test.dot"

        GraphvizRenderer.render_to_file(tree, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "digraph DerivationTree" in content

    def test_render_to_json(self, tmp_path):
        """Test rendering tree to JSON file."""
        tree = DerivationTree(goal="attacker(x)")
        output_file = tmp_path / "test.json"

        GraphvizRenderer.render_to_json(tree, output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert '"meta"' in content
        assert '"nodes"' in content
        assert '"depends_on_all"' in content
        assert '"depends_on_any"' in content

    def test_render_to_pdf(self, tmp_path):
        """Test rendering tree to PDF (checks dot file is created)."""
        tree = DerivationTree(goal="attacker(x)")
        output_path = tmp_path / "test"

        # This will fail without graphviz installed, but should create dot file
        GraphvizRenderer.render_to_pdf(tree, output_path)

        # Check that at least the dot file was created
        dot_file = output_path.with_suffix(".dot")
        assert dot_file.exists()

    def test_build_tree_multiple_queries(self):
        """Test building tree extracts only first query."""
        derivations = [
            Derivation(
                conclusion="goal1",
                rule_name="goal",
                indent_level=0,
                query="query1",
            ),
            Derivation(
                conclusion="fact1", rule_name="clause", indent_level=1, query="query1"
            ),
            # Second query starts
            Derivation(
                conclusion="goal2",
                rule_name="goal",
                indent_level=0,
                query="query2",
            ),
            Derivation(
                conclusion="fact2", rule_name="clause", indent_level=1, query="query2"
            ),
        ]
        tree = GraphvizRenderer.build_tree_from_derivations(derivations)
        # Should only process first query's derivations
        assert tree.goal == "goal1"
        # Count nodes - should have goal and fact1, not goal2 and fact2
        facts = [fact for fact, _ in tree.nodes.keys()]
        assert "goal1" in facts
        assert "fact1" in facts
