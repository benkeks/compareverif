"""Unit tests for ProVerif output parsing."""

import pytest
from proverifbatch.proverif import (
    Clause,
    Derivation,
    ProVerifOutput,
    ProVerifOutputParser,
)


class TestClause:
    """Test Clause data class."""

    def test_clause_creation(self):
        """Test basic clause creation."""
        clause = Clause(
            head="attacker(x[])",
            body=["event(e)"],
            original_text="event(e) -> attacker(x[])",
            clause_number=5,
        )
        assert clause.head == "attacker(x[])"
        assert clause.body == ["event(e)"]
        assert clause.clause_number == 5

    def test_clause_repr_with_body(self):
        """Test __repr__ for clause with body."""
        clause = Clause(head="attacker(x)", body=["event(e)", "mess(c, m)"])
        assert ":-" in repr(clause)
        assert "event(e)" in repr(clause)

    def test_clause_repr_no_body(self):
        """Test __repr__ for clause without body."""
        clause = Clause(head="attacker(x)")
        assert repr(clause) == "attacker(x)"


class TestDerivation:
    """Test Derivation data class."""

    def test_derivation_creation(self):
        """Test basic derivation creation."""
        deriv = Derivation(
            conclusion="attacker(password[])",
            rule_name="clause",
            indent_level=0,
            clause_number=5,
        )
        assert deriv.conclusion == "attacker(password[])"
        assert deriv.rule_name == "clause"
        assert deriv.clause_number == 5

    def test_derivation_repr_with_premises(self):
        """Test __repr__ for derivation with premises."""
        deriv = Derivation(
            conclusion="attacker(x)",
            premises=["event(e)"],
            rule_name="clause",
        )
        assert "=>" in repr(deriv)
        assert "event(e)" in repr(deriv)

    def test_derivation_repr_no_premises(self):
        """Test __repr__ for derivation without premises."""
        deriv = Derivation(conclusion="initial_fact")
        assert repr(deriv) == "initial_fact"


class TestProVerifOutputParser:
    """Test ProVerif output parser."""

    def test_parse_empty_output(self):
        """Test parsing empty output."""
        parser = ProVerifOutputParser()
        output = parser.parse("")
        assert len(output.clauses) == 0
        assert len(output.derivations) == 0

    def test_parse_clause_line(self):
        """Test parsing a single clause line."""
        parser = ProVerifOutputParser()
        parser._parse_clause_line(
            "event(e) -> attacker(x[])",
            clause_number=1,
            is_initial=True,
        )
        assert len(parser.output.clauses) == 1
        assert parser.output.clauses[0].head == "attacker(x[])"
        assert parser.output.clauses[0].body == ["event(e)"]

    def test_parse_clause_multiple_premises(self):
        """Test parsing clause with multiple premises."""
        parser = ProVerifOutputParser()
        parser._parse_clause_line(
            "event(e1) && event(e2) && event(e3) -> result()",
            clause_number=2,
        )
        assert len(parser.output.clauses) == 1
        assert len(parser.output.clauses[0].body) == 3

    def test_parse_clause_no_premises(self):
        """Test parsing clause with no premises."""
        parser = ProVerifOutputParser()
        parser._parse_clause_line("initial_fact()", clause_number=3)
        assert len(parser.output.clauses) == 1
        assert len(parser.output.clauses[0].body) == 0

    def test_parse_derivation_block_goal(self):
        """Test parsing derivation block with goal."""
        parser = ProVerifOutputParser()
        lines = ["goal attacker(password[])"]
        parser._parse_derivation_block(lines, query="test_query")
        assert len(parser.output.derivations) == 1
        assert parser.output.derivations[0].rule_name == "goal"

    def test_parse_derivation_block_clause(self):
        """Test parsing derivation block with clause reference."""
        parser = ProVerifOutputParser()
        lines = ["    clause 5 attacker(x)"]
        parser._parse_derivation_block(lines)
        assert len(parser.output.derivations) == 1
        assert parser.output.derivations[0].clause_number == 5

    def test_parse_derivation_block_with_indentation(self):
        """Test parsing derivation block with proper indentation levels."""
        parser = ProVerifOutputParser()
        lines = [
            "goal attacker(x)",
            "    clause 5 auth()",
            "        initial knowledge fact()",
        ]
        parser._parse_derivation_block(lines)
        assert len(parser.output.derivations) == 3
        assert parser.output.derivations[0].indent_level == 0
        assert parser.output.derivations[1].indent_level == 1
        assert parser.output.derivations[2].indent_level == 2

    def test_parse_derivation_apply(self):
        """Test parsing apply transformations."""
        parser = ProVerifOutputParser()
        lines = ["    apply proj-fst (x, y)"]
        parser._parse_derivation_block(lines)
        assert len(parser.output.derivations) == 1
        assert "apply" in parser.output.derivations[0].rule_name

    def test_parse_derivation_duplicate(self):
        """Test parsing duplicate operations."""
        parser = ProVerifOutputParser()
        lines = ["    duplicate attacker(x)"]
        parser._parse_derivation_block(lines)
        assert len(parser.output.derivations) == 1
        assert parser.output.derivations[0].rule_name == "duplicate"

    def test_parse_derivation_initial(self):
        """Test parsing initial knowledge."""
        parser = ProVerifOutputParser()
        lines = ["    initial knowledge fact()"]
        parser._parse_derivation_block(lines)
        assert len(parser.output.derivations) == 1
        assert parser.output.derivations[0].rule_name == "initial"

    def test_full_parse_with_clauses_and_derivations(self):
        """Test full parsing with both clauses and derivations."""
        parser = ProVerifOutputParser()
        raw_output = """
Initial clauses:
Clause 1: event(e) -> attacker(password[])
Clause 2: initial_fact()

Starting query test_query

Derivation:
goal attacker(password[])
    clause 1 attacker(password[])
        initial knowledge initial_fact()
"""
        output = parser.parse(raw_output)
        assert len(output.clauses) == 2
        assert len(output.derivations) == 3
        assert output.query == "test_query"

    def test_parse_maintains_clause_scope(self):
        """Test that clause scope is properly tracked across queries."""
        parser = ProVerifOutputParser()
        raw_output = """
-- Query 1
Initial clauses:
Clause 1: fact1() -> attacker(x)
Derivation:
goal attacker(x)
    clause 1 attacker(x)

-- Query 2
Initial clauses:
Clause 1: fact2() -> attacker(y)
Derivation:
goal attacker(y)
    clause 1 attacker(y)
"""
        output = parser.parse(raw_output)
        # Two queries should be detected and tracked with 0-based scope IDs
        assert len(output.derivations) == 4
        clause_derivations = [d for d in output.derivations if d.rule_name == "clause"]
        assert len(clause_derivations) == 2
        assert clause_derivations[0].query_scope == 0
        assert clause_derivations[1].query_scope == 1

        clause_entries = [c for c in output.clauses if c.clause_number == 1]
        assert len(clause_entries) == 2
        assert clause_entries[0].clause_scope == 0
        assert clause_entries[1].clause_scope == 1

    def test_parse_resets_state_between_calls(self):
        """Reusing one parser instance should not leak clauses or derivations."""
        parser = ProVerifOutputParser()

        first_output = parser.parse(
            """
Initial clauses:
Clause 1: fact_a() -> attacker(a)

Starting query query_a

Derivation:
goal attacker(a)
    clause 1 attacker(a)
"""
        )
        second_output = parser.parse(
            """
Initial clauses:
Clause 2: fact_b() -> attacker(b)

Starting query query_b

Derivation:
goal attacker(b)
    clause 2 attacker(b)
"""
        )

        assert len(first_output.clauses) == 1
        assert len(first_output.derivations) == 2
        assert first_output.query == "query_a"

        assert len(second_output.clauses) == 1
        assert len(second_output.derivations) == 2
        assert second_output.query == "query_b"
        assert second_output.clauses[0].clause_number == 2
        assert second_output.derivations[0].conclusion == "attacker(b)"
