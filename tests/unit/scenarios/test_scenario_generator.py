"""Tests for scenario generator module."""

import pytest
from src.scenarios.generator import (
    generate_scenario_combinations,
    build_scenario_content,
    extract_queries,
    create_scenario_filename,
)
from src.scenarios.models import AttackerCapability, AttackVariant


class TestGenerateScenarioCombinations:
    """Tests for generate_scenario_combinations function."""
    
    def test_no_capabilities(self):
        """Test with no capabilities."""
        result = generate_scenario_combinations([])
        assert result == [()] or result == []
    
    def test_single_capability_no_variants(self):
        """Test with single capability that has no variants."""
        cap = AttackerCapability(
            primary_name="Attack A",
            variants=[AttackVariant(name="Attack A", costs={"time": 100})],
            content="code a"
        )
        result = generate_scenario_combinations([cap])
        # Should generate: (0,) exclude, (1,) variant 1
        assert len(result) == 2
        assert (0,) in result
        assert (1,) in result
    
    def test_multiple_capabilities(self):
        """Test with multiple capabilities."""
        cap1 = AttackerCapability(
            primary_name="A",
            variants=[AttackVariant(name="A", costs={"time": 100})],
            content="code a"
        )
        cap2 = AttackerCapability(
            primary_name="B",
            variants=[AttackVariant(name="B", costs={"time": 50})],
            content="code b"
        )
        result = generate_scenario_combinations([cap1, cap2])
        # 2 choices per capability: (exclude, variant1) = 2^2 = 4 combinations
        assert len(result) == 4
        assert (0, 0) in result
        assert (0, 1) in result
        assert (1, 0) in result
        assert (1, 1) in result


class TestBuildScenarioContent:
    """Tests for build_scenario_content function."""
    
    def test_exclude_all_capabilities(self):
        """Test building scenario with all capabilities excluded."""
        cap = AttackerCapability(
            primary_name="Attack A",
            variants=[AttackVariant(name="Attack A", costs={"time": 100})],
            content="attack code"
        )
        chunks = ["base ", None, " end"]
        
        content, variants, costs = build_scenario_content((0,), [cap], chunks)
        
        assert "base " in content
        assert "end" in content
        assert "attack code" not in content
        assert len(variants) == 0
        assert costs == {}
    
    def test_include_single_capability(self):
        """Test building scenario with single capability included."""
        cap = AttackerCapability(
            primary_name="Attack A",
            variants=[AttackVariant(name="Attack A", costs={"time": 100})],
            content="attack code"
        )
        chunks = ["base ", None, " end"]
        
        content, variants, costs = build_scenario_content((1,), [cap], chunks)
        
        assert "base " in content
        assert "attack code" in content
        assert "end" in content
        assert len(variants) == 1
        assert variants[0].name == "Attack A"
        assert costs == {"time": 100}
    
    def test_multiple_capabilities(self):
        """Test building scenario with multiple capabilities."""
        cap1 = AttackerCapability(
            primary_name="Attack A",
            variants=[AttackVariant(name="Attack A", costs={"time": 100})],
            content="code a"
        )
        cap2 = AttackerCapability(
            primary_name="Attack B",
            variants=[AttackVariant(name="Attack B", costs={"hack": 50})],
            content="code b"
        )
        chunks = ["base", None, "middle", None, "end"]
        
        content, variants, costs = build_scenario_content((1, 1), [cap1, cap2], chunks)
        
        assert "code a" in content
        assert "code b" in content
        assert len(variants) == 2
        assert costs == {"time": 100, "hack": 50}


class TestExtractQueries:
    """Tests for extract_queries function."""
    
    def test_simple_query(self):
        """Test extracting a simple query."""
        content = "query attacker(key)."
        result = extract_queries(content)
        assert len(result) == 1
        assert result[0]['tag'] == 'query'
        assert 'attacker(key)' in result[0]['query']
    
    def test_tagged_query(self):
        """Test extracting a query with tag."""
        content = "(* Login authentication guard *) query attacker(password)."
        result = extract_queries(content)
        assert len(result) == 1
        assert result[0]['tag'] == 'Login authentication guard'
        assert 'attacker(password)' in result[0]['query']
    
    def test_multiple_queries(self):
        """Test extracting multiple queries."""
        content = """
        (* Query 1 *) query attacker(a).
        (* Query 2 *) query attacker(b).
        """
        result = extract_queries(content)
        assert len(result) == 2

    def test_simple_weaksecret(self):
        """Test extracting a weaksecret check."""
        content = "weaksecret n."
        result = extract_queries(content)
        assert len(result) == 1
        assert result[0]['tag'] == 'weaksecret'
        assert 'weaksecret n.' in result[0]['query']

    def test_tagged_weaksecret(self):
        """Test extracting a tagged weaksecret check."""
        content = "(* Offline guessing resistance *) weaksecret n."
        result = extract_queries(content)
        assert len(result) == 1
        assert result[0]['tag'] == 'Offline guessing resistance'
        assert 'weaksecret n.' in result[0]['query']

    def test_mixed_query_and_weaksecret(self):
        """Test extracting both query and weaksecret checks."""
        content = """
        (* Secrecy *) query attacker(k).
        (* Guessing resistance *) weaksecret n.
        """
        result = extract_queries(content)
        assert len(result) == 2
        assert result[0]['tag'] == 'Secrecy'
        assert result[1]['tag'] == 'Guessing resistance'


class TestCreateScenarioFilename:
    """Tests for create_scenario_filename function."""
    
    def test_no_capabilities(self):
        """Test filename when no capabilities included."""
        result = create_scenario_filename([])
        assert result == "base_scenario"
    
    def test_single_capability(self):
        """Test filename with single capability."""
        result = create_scenario_filename(["Rainbow table attack"])
        assert result == "rainbow_table_attack"
    
    def test_multiple_capabilities(self):
        """Test filename with multiple capabilities."""
        result = create_scenario_filename(["Rainbow table", "Side channel"])
        assert result == "rainbow_table+side_channel"
    
    def test_special_characters(self):
        """Test that special characters are converted to underscores."""
        result = create_scenario_filename(["Attack-A", "Attack (B)"])
        assert result == "attack_a+attack__b_"
