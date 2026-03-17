"""Unit tests for attack tree models."""

import pytest
from src.attack_tree import TreeNode, DerivationTree


class TestTreeNode:
    """Test TreeNode data class."""

    def test_tree_node_creation(self):
        """Test basic TreeNode creation."""
        node = TreeNode(fact="attacker(password[])", rule="clause", clause_number=5)
        assert node.fact == "attacker(password[])"
        assert node.rule == "clause"
        assert node.clause_number == 5
        assert node.node_id is not None
        assert node.capabilities == set()

    def test_tree_node_with_capabilities(self):
        """Test TreeNode with capabilities."""
        node = TreeNode(
            fact="attack(x)",
            rule="clause",
            capabilities={"brute_force", "rainbow_table"},
        )
        assert node.capabilities == {"brute_force", "rainbow_table"}

    def test_tree_node_readable_format_attacker(self):
        """Test readable format for attacker facts."""
        result = TreeNode.to_readable_format("attacker(password[])")
        assert "Attacker learns" in result
        assert "password" in result
        assert "courier" in result

    def test_tree_node_readable_format_table(self):
        """Test readable format for table facts."""
        result = TreeNode.to_readable_format("table(passwords(hash))")
        assert "Table" in result
        assert "passwords" in result
        assert "contains" in result

    def test_tree_node_readable_format_event(self):
        """Test readable format for event facts."""
        result = TreeNode.to_readable_format("event(authenticated(user[]))")
        assert "Event" in result
        assert "authenticated" in result
        assert "happens" in result

    def test_tree_node_readable_format_tuple(self):
        """Test readable format for tuple in attacker fact."""
        result = TreeNode.to_readable_format("attacker((password[], hash[]))")
        assert "Attacker learns" in result
        assert " and " in result

    def test_tree_node_unique_ids(self):
        """Test that different nodes get different IDs."""
        node1 = TreeNode(fact="fact1", rule="clause")
        node2 = TreeNode(fact="fact2", rule="clause")
        assert node1.node_id != node2.node_id

    def test_tree_node_variant_ids(self):
        """Test node IDs with variants."""
        node1 = TreeNode(fact="fact", variant_id="variant1")
        node2 = TreeNode(fact="fact", variant_id="variant2")
        assert node1.node_id != node2.node_id


class TestDerivationTree:
    """Test DerivationTree class."""

    def test_tree_creation(self):
        """Test basic tree creation."""
        tree = DerivationTree(goal="attacker(password[])", query_tag="test_query")
        assert tree.goal == "attacker(password[])"
        assert tree.query_tag == "test_query"
        assert len(tree.nodes) == 1  # Goal node

    def test_add_node(self):
        """Test adding nodes to tree."""
        tree = DerivationTree(goal="attacker(x)")
        node = tree.add_node("event(auth)", rule="clause")
        assert node.fact == "event(auth)"
        assert len(tree.nodes) == 2

    def test_add_duplicate_node(self):
        """Test that adding duplicate node updates it instead of creating new one."""
        tree = DerivationTree(goal="attacker(x)")
        node1 = tree.add_node("event(auth)", rule="initial")
        assert len(tree.nodes) == 2

        node2 = tree.add_node("event(auth)", rule="clause")
        assert len(tree.nodes) == 2  # Still 2 nodes
        assert node2.rule == "clause"  # Rule updated to higher priority

    def test_add_edge(self):
        """Test adding edges between nodes."""
        tree = DerivationTree(goal="attacker(x)")
        tree.add_edge("event(auth)", "attacker(x)", rule="clause")
        assert len(tree.edges) == 1

    def test_rule_priority(self):
        """Test that rule priority is respected."""
        tree = DerivationTree(goal="attacker(x)")
        # First add as "initial"
        node = tree.add_node("auth", rule="initial")
        assert node.rule == "initial"

        # Update to "clause" (higher priority)
        node = tree.add_node("auth", rule="clause")
        assert node.rule == "clause"

        # Try to downgrade to "duplicate" (lower priority) - should not change
        node = tree.add_node("auth", rule="duplicate")
        assert node.rule == "clause"

    def test_graphviz_generation(self):
        """Test graphviz output generation."""
        tree = DerivationTree(goal="attacker(x)", query_tag="broken_query")
        tree.add_edge("event(auth)", "attacker(x)", rule="clause")

        dot_output = tree.to_graphviz()
        assert "digraph DerivationTree" in dot_output
        assert "event(auth)" in dot_output
        assert "attacker(x)" in dot_output
        assert "->" in dot_output  # Check for edges

    def test_graphviz_with_capabilities(self):
        """Test graphviz output with capability annotations."""
        tree = DerivationTree(goal="attacker(x)")
        tree.add_node("hack", capabilities={"brute_force"})

        dot_output = tree.to_graphviz()
        assert "brute_force" in dot_output
        assert "#DDA0DD" in dot_output  # Plum color for capability nodes

    def test_readable_nodes(self):
        """Test readable node format in graphviz output."""
        tree = DerivationTree(goal="attacker(password[])", readable_nodes=True)
        dot_output = tree.to_graphviz()
        # Readable format should contain HTML formatting
        assert "<FONT" in dot_output or "Attacker" in dot_output

    def test_clause_numbers_in_graphviz(self):
        """Test that clause numbers appear in nodes when enabled."""
        tree = DerivationTree(goal="attacker(x)", show_clause_ids=True)
        tree.add_node("auth", rule="clause", clause_number=5)
        dot_output = tree.to_graphviz()
        assert "Clause 5" in dot_output

    def test_capability_costs_in_edges(self):
        """Test that capability costs are shown in edge labels."""
        tree = DerivationTree(
            goal="attacker(x)",
            capability_costs={"brute_force": {"hack": 1, "time": 10}},
        )
        node = tree.add_node("crack", capabilities={"brute_force"})
        tree.add_edge("attacker(x)", "crack")

        dot_output = tree.to_graphviz()
        # Should have edge labels with costs
        assert "label=" in dot_output

    def test_variant_nodes(self):
        """Test tree with variant nodes (multiple ways to achieve same fact)."""
        tree = DerivationTree(goal="attacker(x)")
        # Create two variant nodes for the same fact
        n1 = tree.add_node("auth", variant_id="variant1")
        n2 = tree.add_node("auth", variant_id="variant2")

        assert n1.node_id != n2.node_id
        assert len(tree.nodes) == 3  # goal + 2 variants

    def test_empty_derivation_tree(self):
        """Test tree with just the goal node."""
        tree = DerivationTree(goal="attacker(password[])")
        dot_output = tree.to_graphviz()
        assert "attacker(password[])" in dot_output
        assert tree.nodes[(tree.goal, DerivationTree.GOAL_VARIANT)].rule == "goal"
