"""Tests for scenario parser module."""

import pytest
from compareverif.scenarios.parser import (
    parse_costs,
    parse_magical_comment,
    extract_attacker_capabilities,
)
from compareverif.scenarios.models import AttackVariant


class TestParseCosts:
    """Tests for parse_costs function."""
    
    def test_single_cost_dimension(self):
        """Test parsing a single cost dimension."""
        result = parse_costs("[100 time]")
        assert result == {"time": 100}
    
    def test_multiple_cost_dimensions(self):
        """Test parsing multiple cost dimensions."""
        result = parse_costs("[100 time, 10 hack]")
        assert result == {"time": 100, "hack": 10}
    
    def test_float_costs(self):
        """Test parsing float costs."""
        result = parse_costs("[99.5 time, 10.2 hack]")
        assert result == {"time": 99.5, "hack": 10.2}
    
    def test_empty_brackets(self):
        """Test handling empty brackets."""
        result = parse_costs("[]")
        assert result == {}
    
    def test_no_brackets(self):
        """Test handling text without brackets."""
        result = parse_costs("no costs here")
        assert result == {}


class TestParseMagicalComment:
    """Tests for parse_magical_comment function."""
    
    def test_single_variant(self):
        """Test parsing a single variant."""
        result = parse_magical_comment("Rainbow table attack [100 time]")
        assert len(result) == 1
        assert result[0].name == "Rainbow table attack"
        assert result[0].costs == {"time": 100}
    
    def test_multiple_variants(self):
        """Test parsing multiple variants separated by /."""
        result = parse_magical_comment("Attack A [50 time] / Attack B [30 time, 10 hack]")
        assert len(result) == 2
        assert result[0].name == "Attack A"
        assert result[0].costs == {"time": 50}
        assert result[1].name == "Attack B"
        assert result[1].costs == {"time": 30, "hack": 10}
    
    def test_no_costs(self):
        """Test parsing variants without costs."""
        result = parse_magical_comment("Simple attack")
        assert len(result) == 1
        assert result[0].name == "Simple attack"
        assert result[0].costs == {}


class TestExtractAttackerCapabilities:
    """Tests for extract_attacker_capabilities function."""
    
    def test_no_capabilities(self):
        """Test file with no magical comments."""
        content = "new key: bitstring.\nquery attacker(key)."
        caps, chunks = extract_attacker_capabilities(content)
        assert caps == []
        assert chunks == [content]
    
    def test_single_capability(self):
        """Test extracting a single capability."""
        content = """base content.
(*** Attack A [100 time]
attack code here.
***)
more content."""
        caps, chunks = extract_attacker_capabilities(content)
        
        assert len(caps) == 1
        assert caps[0].primary_name == "Attack A"
        assert caps[0].variants[0].costs == {"time": 100}
        assert "attack code here." in caps[0].content
        
        assert len(chunks) == 3
        assert "base content." in chunks[0]
        assert chunks[1] is None  # Placeholder for capability
        assert "more content." in chunks[2]
    
    def test_multiple_capabilities(self):
        """Test extracting multiple capabilities."""
        content = """initial.
(*** Cap 1 [10 time]
code1.
***)
middle.
(*** Cap 2 [20 hack]
code2.
***)
final."""
        caps, chunks = extract_attacker_capabilities(content)
        
        assert len(caps) == 2
        assert caps[0].primary_name == "Cap 1"
        assert caps[1].primary_name == "Cap 2"
        assert len(chunks) == 5  # initial, None, middle, None, final
    
    def test_variant_capability(self):
        """Test extracting capability with variants."""
        content = """(*** Attack [50 time] / Attack variant [25 time, 10 hack]
code here.
***)"""
        caps, chunks = extract_attacker_capabilities(content)
        
        assert len(caps) == 1
        assert len(caps[0].variants) == 2
        assert caps[0].variants[0].name == "Attack"
        assert caps[0].variants[1].name == "Attack variant"
