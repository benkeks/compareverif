"""Parsing utilities for scenario files and magical comments."""

import re
from typing import Dict, List, Tuple
from .models import AttackVariant, AttackerCapability, CapabilityPlaceholder


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


def parse_attributes(header_part: str) -> Dict[str, str]:
    """Extract key-value attributes from a header part like '{unlock: 1, mitigate: 2}'.

    Values may optionally be wrapped in single or double quotes, which allows
    commas and colons to appear inside the value (e.g. '{note: "a, b: c"}').

    Args:
        header_part: String containing attribute specifications in braces

    Returns:
        Dictionary mapping attribute key to string value
    """
    attributes: Dict[str, str] = {}
    brace_contents = re.findall(r'\{([^}]*)\}', header_part)
    pair_pattern = re.compile(r'([^,:{}]+):\s*(?:"([^"]*)"|\'([^\']*)\'|([^,}]*))')
    for content in brace_contents:
        for match in pair_pattern.finditer(content):
            key = match.group(1).strip()
            if not key:
                continue
            value = match.group(2)
            if value is None:
                value = match.group(3)
            if value is None:
                value = match.group(4) or ''
            attributes[key] = value.strip()
    return attributes


def parse_magical_comment(header: str) -> List[AttackVariant]:
    """Parse a magical comment header into variants.
    
    Supports syntax like:
        'Rainbow table attack [100 time] / Side-channel attack [10 time]'
    
    Variants may also carry string key-value attributes in braces, e.g.:
        'Database leak [1 hack] {unlock: 1, mitigate: 2}'
    
    Args:
        header: Header string to parse
        
    Returns:
        List of AttackVariant objects
    """
    variants: List[AttackVariant] = []
    header_parts = [part.strip() for part in header.split('/') if part.strip()]
    
    for part in header_parts:
        costs = parse_costs(part)
        attributes = parse_attributes(part)
        clean_name = re.sub(r'\s*\[[^\]]+\]', '', part)
        clean_name = re.sub(r'\s*\{[^}]*\}', '', clean_name).strip()
        variants.append(AttackVariant(name=clean_name, costs=costs, attributes=attributes))
    
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
    capabilities_by_name: Dict[str, AttackerCapability] = {}
    capability_indices: Dict[str, int] = {}
    metadata_sources: Dict[str, AttackVariant] = {}
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
            primary_name = variants[0].name
            snippet_content = match.group(2).strip()
            metadata_variant = next(
                (variant for variant in variants
                 if variant.costs or variant.attributes),
                None,
            )

            capability = capabilities_by_name.get(primary_name)
            if capability is None:
                capability = AttackerCapability(
                    primary_name=primary_name,
                    variants=variants,
                    content=snippet_content,
                )
                capabilities_by_name[primary_name] = capability
                capabilities.append(capability)
                capability_indices[primary_name] = len(capabilities) - 1
                if metadata_variant is not None:
                    metadata_sources[primary_name] = metadata_variant
            else:
                if metadata_variant is not None:
                    if primary_name in metadata_sources:
                        raise ValueError(
                            f"Capability '{primary_name}' has price or attributes "
                            "defined in multiple snippets"
                        )
                    capability.variants = variants
                    metadata_sources[primary_name] = metadata_variant
                capability.content = f"{capability.content}\n{snippet_content}"

            content_chunks.append(
                CapabilityPlaceholder(
                    capability_index=capability_indices[primary_name],
                    content=snippet_content,
                )
            )
        
        last_pos = match.end()
    
    # Add remaining base content after last match
    if last_pos < len(content):
        content_chunks.append(content[last_pos:])
    
    return capabilities, content_chunks
