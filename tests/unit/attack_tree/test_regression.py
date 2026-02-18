"""Regression tests for attack tree functionality based on bugs fixed."""

from src.attack_tree import DerivationTree, CapabilityAnalyzer

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
