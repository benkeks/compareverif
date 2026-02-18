"""Parsing utilities for scenario files and magical comments."""

import re
from typing import Dict, List, Tuple
from .models import AttackVariant, AttackerCapability


def parse_costs(header_part: str) -> Dict[str, float]:
    """Extract costs from a header part like '[100 time, 10 obstime]'.
    
    Args:
        header_part: String containing cost specifications in brackets
        
    Returns:
        Dictionary mapping cost dimension to numeric value
    """
    costs: Dict[str, float] = {}
    bracket_contents = re.findall(r'\[([^\]]+)\]', header_part)
    for content in bracket_contents:
        for item in content.split(','):
            item = item.strip()
            if not item:
                continue
            m = re.match(r'([0-9]+(?:\.[0-9]+)?)\s+(\w+)', item)
            if not m:
                continue
            quantity, dimension = m.groups()
            try:
                costs[dimension] = int(quantity)
            except ValueError:
                costs[dimension] = float(quantity)
    return costs


def parse_magical_comment(header: str) -> List[AttackVariant]:
    """Parse a magical comment header into variants.
    
    Supports syntax like:
        'Rainbow table attack [100 time] / Side-channel attack [10 time]'
    
    Args:
        header: Header string to parse
        
    Returns:
        List of AttackVariant objects
    """
    variants: List[AttackVariant] = []
    header_parts = [part.strip() for part in header.split('/') if part.strip()]
    
    for part in header_parts:
        costs = parse_costs(part)
        clean_name = re.sub(r'\s*\[[^\]]+\]', '', part).strip()
        variants.append(AttackVariant(name=clean_name, costs=costs))
    
    return variants


def extract_attacker_capabilities(content: str) -> Tuple[List[AttackerCapability], List[str]]:
    """Extract all attacker capabilities and base content chunks from file.
    
    Looks for blocks of the form:
        (*** <Header with costs>
          <ProVerif code>
        ***)
    
    Args:
        content: File content to extract capabilities from
        
    Returns:
        Tuple of (attacker_capabilities, content_chunks)
        where content_chunks contains strings and None placeholders for capabilities
    """
    pattern = r'\(\*\*\*\s*(.*?)\s*\n(.*?)\*\*\*\)'
    matches = list(re.finditer(pattern, content, re.DOTALL))
    
    if not matches:
        return [], [content]
    
    capabilities: List[AttackerCapability] = []
    content_chunks: List[str] = []
    last_pos = 0
    
    for match in matches:
        # Add base content before this match
        if match.start() > last_pos:
            content_chunks.append(content[last_pos:match.start()])
        
        # Parse capability
        header = match.group(1).strip()
        variants = parse_magical_comment(header)
        
        if variants:
            capability = AttackerCapability(
                primary_name=variants[0].name,
                variants=variants,
                content=match.group(2).strip()
            )
            capabilities.append(capability)
            content_chunks.append(None)  # Placeholder for this capability
        
        last_pos = match.end()
    
    # Add remaining base content after last match
    if last_pos < len(content):
        content_chunks.append(content[last_pos:])
    
    return capabilities, content_chunks
