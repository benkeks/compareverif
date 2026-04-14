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
        tree.add_edge("event(auth)", "attacker(x)")
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
        tree.add_edge("event(auth)", "attacker(x)")

        dot_output = tree.to_graphviz()
        assert "digraph DerivationTree" in dot_output
        assert "event(auth)" in dot_output
        assert "attacker(x)" in dot_output
        assert "->" in dot_output  # Check for edges

    def test_goal_node_rendered_as_purple_circle(self):
        """Query/goal nodes should be circular and purple."""
        tree = DerivationTree(goal="attacker(x)")
        dot_output = tree.to_graphviz()

        assert 'shape="ellipse"' in dot_output
        assert 'fillcolor="#D8B4E2"' in dot_output

    def test_default_fact_node_rendered_as_grey_box(self):
        """Intermediate fact nodes should default to grey rectangular boxes."""
        tree = DerivationTree(goal="attacker(x)")
        tree.add_node("event(auth)", rule="clause")
        dot_output = tree.to_graphviz()

        assert 'shape="box"' in dot_output
        assert 'fillcolor="#D9D9D9"' in dot_output

    def test_table_node_rendered_as_cylinder(self):
        """Table facts should render as cylinders."""
        tree = DerivationTree(goal="attacker(x)")
        tree.add_node("table(passwd(uid,pw,salt))", rule="clause")
        dot_output = tree.to_graphviz()

        assert 'shape="cylinder"' in dot_output

    def test_channel_transport_node_rendered_as_note(self):
        """Channel transport facts should render as note-shaped nodes."""
        tree = DerivationTree(goal="attacker(x)")
        tree.add_node("mess(chan,msg)", rule="clause")
        dot_output = tree.to_graphviz()

        assert 'shape="note"' in dot_output

    def test_highlight_attack_fades_non_attack_branch(self):
        """Highlight mode should fade branches that are not above capabilities."""
        tree = DerivationTree(goal="goal", highlight_attack=True)
        tree.add_node("fact1", rule="clause")
        tree.add_node("table(entry1)", rule="clause")
        tree.add_edge("goal", "fact1")
        tree.add_edge("fact1", "table(entry1)")

        tree.add_node(
            "Attack Capability",
            rule=tree.CAPABILITY_RULE,
            node_type="capability",
            capabilities={"Attack Capability"},
            variant_id="cap_leaf",
        )
        tree.add_edge(
            "fact1",
            "Attack Capability",
            target_variant="cap_leaf",
            target_node_type="capability",
        )

        dot_output = tree.to_graphviz()

        # Non-attack sibling branch is dimmed.
        assert "table(entry1)" in dot_output
        assert 'color="#A6A6A6"' in dot_output
        assert 'penwidth=0.8' in dot_output

    def test_graphviz_with_capabilities(self):
        """Test graphviz output with dedicated capability nodes."""
        tree = DerivationTree(goal="attacker(x)")
        tree.add_node(
            "Brute Force",
            rule=tree.CAPABILITY_RULE,
            node_type="capability",
            capabilities={"Brute Force"},
            variant_id="cap_leaf",
        )

        dot_output = tree.to_graphviz()
        assert "Brute Force" in dot_output
        assert 'shape="octagon"' in dot_output
        assert "#CC0000" in dot_output

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
        assert "clause 5" in dot_output

    def test_capability_costs_in_capability_nodes(self):
        """Test that capability costs are shown only in dedicated capability nodes."""
        tree = DerivationTree(
            goal="attacker(x)",
            capability_costs={"Brute Force": {"hack": 1, "time": 10}},
        )
        tree.add_node("crack", rule="clause", clause_number=7)
        tree.add_node(
            "Brute Force",
            rule=tree.CAPABILITY_RULE,
            node_type="capability",
            capabilities={"Brute Force"},
            variant_id="cap_leaf",
        )
        tree.add_edge("crack", "Brute Force", target_variant="cap_leaf", target_node_type="capability")

        dot_output = tree.to_graphviz()
        assert "1 hack" in dot_output
        assert "10 time" in dot_output
        assert "clause 7" not in dot_output or "Brute Force<BR/>clause 7" not in dot_output

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

    def test_plain_json_structure(self):
        """Test plain JSON export has node-level dependencies and metadata."""
        tree = DerivationTree(goal="attacker(x)", highlight_attack=True)
        tree.add_node("event(auth)", rule="clause", clause_number=3)
        tree.add_edge("attacker(x)", "event(auth)")

        data = tree.to_json()
        assert "meta" in data
        assert "nodes" in data
        assert "edges" not in data
        assert data["meta"]["goal"] == "attacker(x)"
        assert data["meta"]["highlight_attack"] is True
        assert any(node["fact"] == "event(auth)" for node in data["nodes"])
        assert all("id" in node for node in data["nodes"])
        assert all("depends_on_all" in node and "depends_on_any" in node for node in data["nodes"])
        goal_node = next(node for node in data["nodes"] if node["fact"] == "attacker(x)")
        event_node = next(node for node in data["nodes"] if node["fact"] == "event(auth)")
        assert goal_node["depends_on_all"] == [event_node["id"]]
        assert goal_node["depends_on_any"] == []

    def test_plain_json_distinguishes_or_dependencies(self):
        """OR alternatives should be separated from conjunctive prerequisites."""
        tree = DerivationTree(goal="goal")
        tree.add_node("fact", rule="clause")
        tree.add_node("pre", rule="clause")
        tree.add_edge("fact", "pre")
        tree.add_node(
            "Cap A",
            rule=tree.CAPABILITY_RULE,
            node_type="capability",
            capabilities={"Cap A"},
            variant_id="cap_a",
        )
        tree.add_node(
            "Cap B",
            rule=tree.CAPABILITY_RULE,
            node_type="capability",
            capabilities={"Cap B"},
            variant_id="cap_b",
        )
        tree.add_edge("fact", "Cap A", target_variant="cap_a", target_node_type="capability")
        tree.add_edge("fact", "Cap B", target_variant="cap_b", target_node_type="capability")

        data = tree.to_json()
        fact_node = next(node for node in data["nodes"] if node["fact"] == "fact")
        pre_node = next(node for node in data["nodes"] if node["fact"] == "pre")
        cap_a_node = next(node for node in data["nodes"] if node["fact"] == "Cap A")
        cap_b_node = next(node for node in data["nodes"] if node["fact"] == "Cap B")

        assert fact_node["depends_on_all"] == [pre_node["id"]]
        assert fact_node["depends_on_any"] == [[cap_a_node["id"], cap_b_node["id"]]]

    def test_plain_json_capability_costs_in_nodes(self):
        """Capability nodes should carry explicit costs in JSON."""
        tree = DerivationTree(goal="goal", capability_costs={"Brute Force": {"hack": 1, "time": 10}})
        tree.add_node(
            "Brute Force",
            rule=tree.CAPABILITY_RULE,
            node_type="capability",
            capabilities={"Brute Force"},
            variant_id="cap_leaf",
        )

        data = tree.to_json()
        cap_node = next(node for node in data["nodes"] if node["node_type"] == "capability")
        assert cap_node["costs"] == {"hack": 1, "time": 10}

    def test_node_ids_are_collision_free(self):
        """Node IDs must be unique within a tree."""
        tree = DerivationTree(goal="goal")
        for idx in range(300):
            tree.add_node(f"fact_{idx}", rule="clause")

        node_ids = [node.node_id for node in tree.nodes.values()]
        assert len(node_ids) == len(set(node_ids))
