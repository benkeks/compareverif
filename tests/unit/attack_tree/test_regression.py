"""Regression tests for attack tree functionality based on bugs fixed."""

from pathlib import Path
from unittest.mock import patch
from xml.etree import ElementTree as ET

from compareverif.attack_tree import DerivationTree, CapabilityAnalyzer
from compareverif.proverif import ProVerifOutput, Clause, ProVerifOutputParser
from compareverif.attack_tree.analyzer import DerivationTreeAnalyzer
from compareverif.uppaal import AttackTreeUppaalGenerator


def test_hypothesis_remains_a_leaf_when_fact_also_has_a_clause_derivation(tmp_path):
    output = ProVerifOutputParser().parse("""
Derivation:
goal event(finished)
    clause 1 event(finished)
        clause 2 attacker(key)
            duplicate event(finished)
        hypothesis attacker(key)
""")

    tree = DerivationTreeAnalyzer.build_tree_from_derivations(output.derivations)
    assert tree is not None

    fact_key = ("attacker(key)", None)
    assert tree.nodes[fact_key].node_type == "or"
    key = next(key for key, node in tree.nodes.items() if node.rule == "hypothesis")
    assert tree.nodes[key].clause_number is None
    assert tree.nodes[key].clause_scope is None
    assert not any(source == key for source, _ in tree.edges)
    assert (fact_key, key) in tree.edges

    output_file = tmp_path / "hypothesis.xml"
    AttackTreeUppaalGenerator.render_tree(output_file, tree)
    root = ET.parse(output_file).getroot()
    variable = AttackTreeUppaalGenerator._node_variable_names(tree)[key]
    transition = next(
        transition
        for transition in root.findall(".//transition")
        if transition.findtext("label[@kind='assignment']") == f"{variable} = true"
    )
    assert transition.findtext("label[@kind='guard']") == f"!{variable}"


def test_alternative_derivations_keep_separate_requirement_bundles(tmp_path):
    output = ProVerifOutputParser().parse("""
Derivation:
goal event(done)
    clause 1 attacker(result)
        initial knowledge attacker(left)
        initial knowledge attacker(right)
    clause 2 attacker(result)
        initial knowledge attacker(other)
    clause 3 event(consumer)
        duplicate attacker(result)
""")

    tree = DerivationTreeAnalyzer.build_tree_from_derivations(output.derivations)
    assert tree is not None

    fact_key = ("attacker(result)", None)
    assert tree.nodes[fact_key].node_type == "or"
    alternatives = [target for source, target in tree.edges if source == fact_key]
    assert len(alternatives) == 2
    bundles = {
        frozenset(target[0] for source, target in tree.edges if source == alternative)
        for alternative in alternatives
    }
    assert bundles == {
        frozenset({"attacker(left)", "attacker(right)"}),
        frozenset({"attacker(other)"}),
    }
    assert (("event(consumer)", None), fact_key) in tree.edges

    nodes_by_id = {node["id"]: node for node in tree.to_json()["nodes"]}
    fact_json = nodes_by_id[tree.nodes[fact_key].node_id]
    assert fact_json["depends_on_all"] == []
    alternative_ids = [tree.nodes[alternative].node_id for alternative in alternatives]
    assert all(node_id is not None for node_id in alternative_ids)
    assert fact_json["depends_on_any"] == [
        sorted(node_id for node_id in alternative_ids if node_id is not None)
    ]
    for alternative in alternatives:
        bundle_json = nodes_by_id[tree.nodes[alternative].node_id]
        assert bundle_json["depends_on_any"] == []
        assert bundle_json["depends_on_all"]

    output_file = tmp_path / "alternatives.xml"
    AttackTreeUppaalGenerator.render_tree(output_file, tree)
    names = AttackTreeUppaalGenerator._node_variable_names(tree)
    guards_by_variable = {
        (transition.findtext("label[@kind='assignment']") or "").removesuffix(" = true"):
        transition.findtext("label[@kind='guard']")
        for transition in ET.parse(output_file).getroot().findall(".//transition")
    }
    assert guards_by_variable[names[fact_key]] == (
        f"!{names[fact_key]} && "
        f"({names[alternatives[0]]} || {names[alternatives[1]]})"
    )
    for alternative in alternatives:
        prerequisites = [target for source, target in tree.edges if source == alternative]
        assert guards_by_variable[names[alternative]] == " && ".join(
            [f"!{names[alternative]}", *(names[target] for target in prerequisites)]
        )
    consumer_name = names[("event(consumer)", None)]
    assert guards_by_variable[consumer_name] == f"!{consumer_name} && {names[fact_key]}"
    dot = tree.to_graphviz()
    assert 'shape="diamond"' in dot
    assert '[label="OR", style=dashed]' in dot

def test_apply_contraction_follows_ancestry_instead_of_previous_siblings():
    output = ProVerifOutputParser().parse("""
Derivation:
goal event(done)
    clause 1 attacker(server_finished)
        clause 2 attacker(master_secret)
            initial knowledge attacker(seed)
        apply 2-tuple attacker(transcript)
            apply FIN attacker(finished_message)
                clause 3 attacker(client_finished)
                    duplicate attacker(master_secret)
""")

    tree = DerivationTreeAnalyzer.build_tree_from_derivations(output.derivations)
    assert tree is not None

    goal = ("event(done)", DerivationTree.GOAL_VARIANT)
    server = ("attacker(server_finished)", None)
    master = ("attacker(master_secret)", None)
    client = ("attacker(client_finished)", None)
    seed = ("attacker(seed)", None)
    assert set(tree.edges) == {
        (goal, server),
        (server, master),
        (server, client),
        (master, seed),
        (client, master),
    }
    assert all(not (node.rule or "").startswith("apply ") for node in tree.nodes.values())


def test_seconds_annotation_follows_apply_ancestry_instead_of_previous_sibling():
    output = ProVerifOutputParser().parse("""
Derivation:
goal event(done)
    clause 1 event(previous_sibling)
        initial knowledge attacker(seed)
    apply wrapper attacker(wrapped_time)
        apply seconds attacker(seconds(3))
            apply 0 attacker(0)
""")

    tree = DerivationTreeAnalyzer.build_tree_from_derivations(output.derivations)
    assert tree is not None

    assert tree.nodes[("event(done)", DerivationTree.GOAL_VARIANT)].required_seconds == 3
    assert tree.nodes[("event(previous_sibling)", None)].required_seconds is None


def test_same_clause_keeps_distinct_bundles_and_delays_but_deduplicates_repeats():
    output = ProVerifOutputParser().parse("""
Derivation:
goal event(done)
    clause 7 attacker(result)
        initial knowledge attacker(left)
        apply seconds attacker(seconds(2))
    clause 7 attacker(result)
        initial knowledge attacker(right)
        apply seconds attacker(seconds(5))
    clause 7 attacker(result)
        initial knowledge attacker(left)
        apply seconds attacker(seconds(2))
""")

    tree = DerivationTreeAnalyzer.build_tree_from_derivations(output.derivations)
    assert tree is not None

    fact_key = ("attacker(result)", None)
    assert tree.nodes[fact_key].node_type == "or"
    assert tree.nodes[fact_key].required_seconds is None
    alternatives = [target for source, target in tree.edges if source == fact_key]
    assert len(alternatives) == 2
    assert {tree.nodes[key].clause_number for key in alternatives} == {7}
    assert {tree.nodes[key].required_seconds for key in alternatives} == {2, 5}
    for alternative in alternatives:
        required = {target[0] for source, target in tree.edges if source == alternative}
        assert required == (
            {"attacker(left)"}
            if tree.nodes[alternative].required_seconds == 2
            else {"attacker(right)"}
        )


def test_multiple_goal_derivations_keep_semantic_goal_above_alternatives(tmp_path):
    output = ProVerifOutputParser().parse("""
Derivation:
goal attacker(result)
    clause 1 attacker(result)
        initial knowledge attacker(left)
    clause 2 attacker(result)
        initial knowledge attacker(right)
""")

    tree = DerivationTreeAnalyzer.build_tree_from_derivations(output.derivations)
    assert tree is not None

    goal_key = (tree.goal, DerivationTree.GOAL_VARIANT)
    assert tree.nodes[goal_key].rule == "goal"
    assert tree.nodes[goal_key].node_type == "or"
    alternatives = [target for source, target in tree.edges if source == goal_key]
    assert len(alternatives) == 2
    assert {tree.nodes[key].clause_number for key in alternatives} == {1, 2}
    for key in alternatives:
        variant_id = tree.nodes[key].variant_id
        assert variant_id is not None
        assert variant_id.startswith("goal_clause_")

    output_file = tmp_path / "goal.xml"
    AttackTreeUppaalGenerator.render_tree(output_file, tree)
    root = ET.parse(output_file).getroot()
    names = AttackTreeUppaalGenerator._node_variable_names(tree)
    assert root.findtext(".//formula") == f"E<> {names[goal_key]}"
    transition = next(
        transition for transition in root.findall(".//transition")
        if transition.findtext("label[@kind='assignment']") == f"{names[goal_key]} = true"
    )
    assert transition.findtext("label[@kind='guard']") == (
        f"!{names[goal_key]} && ({names[alternatives[0]]} || {names[alternatives[1]]})"
    )


class TestFuzzyClauseMatchingRegression:
    """Regression tests for fuzzy structural clause matching (false attribution).
    
    Bug: A clause was falsely attributed to capabilities because exact text matching
    failed when variable names differed across ProVerif runs (e.g., uid0_1 vs uid0_2).
    
    Fix: Implemented fuzzy structural matching that normalizes variable names before
    comparing clause structure.
    """

    def test_normalize_clause_variable_names(self):
        """Test that variable names with different suffixes are considered equivalent."""
        analyzer = CapabilityAnalyzer()
        
        # Same structure with different variable naming
        clause1 = "table(singularizations(uid0_1,r0_2))"
        clause2 = "table(singularizations(uid0_2,r0_3))"
        
        assert analyzer._clauses_structurally_match(clause1, clause2)

    def test_clauses_do_not_match_if_structure_differs(self):
        """Test that structurally different clauses don't match even with same vars."""
        analyzer = CapabilityAnalyzer()
        
        # Different structures
        clause1 = "table(singularizations(uid0_1))"
        clause2 = "table(passwords(uid0_1))"  # Different inner function
        
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_clauses_with_different_nesting_do_not_match(self):
        """Test that different nesting levels don't match."""
        analyzer = CapabilityAnalyzer()
        
        clause1 = "table(x(y(uid0_1)))"
        clause2 = "table(x(uid0_1))"  # Missing one level of nesting
        
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_clauses_with_different_arities_do_not_match(self):
        """Test that different arities (number of arguments) don't match."""
        analyzer = CapabilityAnalyzer()
        
        clause1 = "table(x(a, b))"
        clause2 = "table(x(a, b, c))"  # Different number of args
        
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_exact_same_clause_matches(self):
        """Test that identical clauses match."""
        analyzer = CapabilityAnalyzer()
        
        clause = "attacker(password[])"
        
        assert analyzer._clauses_structurally_match(clause, clause)

    def test_numeric_suffixes_in_variable_names_normalized(self):
        """Test that numeric suffixes in variables are properly normalized."""
        analyzer = CapabilityAnalyzer()
        
        # Variables with different numeric suffixes should match
        clause1 = "attacker((hash0_1, salt0_2))"
        clause2 = "attacker((hash0_5, salt0_6))"
        
        assert analyzer._clauses_structurally_match(clause1, clause2)

    def test_mixed_variable_patterns_match(self):
        """Test matching with mixed variable naming patterns."""
        analyzer = CapabilityAnalyzer()
        
        # Different variable naming styles but same structure
        clause1 = "event(auth(user0_1, realm0_2))"
        clause2 = "event(auth(user1_1, realm1_2))"
        
        assert analyzer._clauses_structurally_match(clause1, clause2)

    def test_non_variable_names_affect_matching(self):
        """Test that actual function/constant names still matter."""
        analyzer = CapabilityAnalyzer()
        
        # Function names are different, so clauses don't match
        clause1 = "table(passwords(uid0_1))"
        clause2 = "table(hashes(uid0_1))"
        
        assert not analyzer._clauses_structurally_match(clause1, clause2)

    def test_clause_with_uppercase_constants_match_properly(self):
        """Test matching when clauses contain uppercase constants (truly constant-like)."""
        analyzer = CapabilityAnalyzer()
        
        # Uppercase constants like 'ADMIN' are preserved and must match
        clause1 = "event(auth(ADMIN, uid0_1))"
        clause2 = "event(auth(ADMIN, uid0_5))"
        
        assert analyzer._clauses_structurally_match(clause1, clause2)

    def test_clause_with_different_uppercase_constants_do_not_match(self):
        """Test that different uppercase constants prevent matching."""
        analyzer = CapabilityAnalyzer()
        
        clause1 = "event(auth(ADMIN, uid0_1))"
        clause2 = "event(auth(USER, uid0_1))"  # Different uppercase constant
        
        assert not analyzer._clauses_structurally_match(clause1, clause2)


class TestRulePriorityAndCapabilityInteraction:
    """Integration tests combining rule priority with capability analysis."""

    def test_rule_priority_preserved_in_capability_analysis(self):
        """Test that rule priority is maintained when analyzing capabilities."""
        tree = DerivationTree(goal="attacker(x)")
        
        # Add node with multiple rule types
        tree.add_node("sensitive", rule="apply")
        tree.add_node("sensitive", rule="clause")  # Upgrade
        
        # Assign capability
        node = tree.add_node("sensitive", capabilities={"rainbow_attack"})
        
        # Rule should still be at highest priority
        assert node.rule == "clause"
        assert "rainbow_attack" in node.capabilities

    def test_goal_node_not_capability_annotated_on_fact_collision(self):
        """Goal node should stay semantic goal even if same fact appears in capability clauses."""
        analyzer = CapabilityAnalyzer()
        analyzer.capability_clauses = {
            "Rainbow table attack": {"attacker(secret[])"}
        }

        output = ProVerifOutput(
            clauses=[
                Clause(
                    head="attacker(secret[])",
                    original_text="attacker(secret[])",
                    clause_number=7,
                    clause_scope=None,
                )
            ],
            derivations=[],
        )

        tree = DerivationTree(goal="attacker(secret[])")
        tree.add_node("attacker(secret[])", rule="clause", clause_number=7)

        with patch.object(analyzer, "_extract_clauses_from_scenario", return_value=output):
            analyzer.annotate_tree_with_capabilities(tree, Path("dummy.pv"))

        goal_node = tree.nodes[("attacker(secret[])", DerivationTree.GOAL_VARIANT)]
        assert goal_node.rule == "goal"
        assert goal_node.capabilities == set()

    def test_goal_clause_variant_is_capability_annotated(self):
        """Non-goal variant for same fact should get a dedicated capability leaf."""
        analyzer = CapabilityAnalyzer()
        analyzer.capability_clauses = {
            "Rainbow table attack": {"attacker(secret[])"}
        }

        output = ProVerifOutput(
            clauses=[
                Clause(
                    head="attacker(secret[])",
                    original_text="attacker(secret[])",
                    clause_number=7,
                    clause_scope=None,
                )
            ],
            derivations=[],
        )

        tree = DerivationTree(goal="attacker(secret[])")
        variant_id = "goal_clause_global_7_1"
        tree.add_node(
            "attacker(secret[])",
            rule="clause",
            clause_number=7,
            variant_id=variant_id,
        )

        with patch.object(analyzer, "_extract_clauses_from_scenario", return_value=output):
            analyzer.annotate_tree_with_capabilities(tree, Path("dummy.pv"))

        clause_variant_node = tree.nodes[("attacker(secret[])", variant_id)]
        assert clause_variant_node.node_type == "fact"

        capability_children = [
            tree.nodes[target_key]
            for source_key, target_key in tree.edges
            if source_key == ("attacker(secret[])", variant_id)
            and tree.nodes[target_key].node_type == "capability"
        ]
        assert [node.fact for node in capability_children] == ["Rainbow table attack"]

        goal_node = tree.nodes[("attacker(secret[])", DerivationTree.GOAL_VARIANT)]
        assert goal_node.capabilities == set()
