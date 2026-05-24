"""Generate scenario file combinations."""

import re
from typing import Dict, List, Tuple, Optional
from itertools import product
from .models import AttackerCapability, AttackVariant


def generate_capability_presence_combinations(
    capabilities: List[AttackerCapability],
) -> List[Tuple[int, ...]]:
    """Generate combinations for snippet presence only.

    Each capability is treated as a boolean toggle:
    - 0 = exclude capability snippet
    - 1 = include capability snippet

    Args:
        capabilities: List of capabilities to combine

    Returns:
        List of tuples representing all boolean snippet combinations
    """
    choices_per_capability = [[0, 1] if cap.variants else [0] for cap in capabilities]
    return list(product(*choices_per_capability))


def generate_base_capability_presence_combination(
    capabilities: List[AttackerCapability],
) -> Tuple[int, ...]:
    """Generate the all-disabled boolean snippet combination."""
    return tuple(0 for _ in capabilities)


def generate_full_capability_presence_combination(
    capabilities: List[AttackerCapability],
) -> Tuple[int, ...]:
    """Generate the all-enabled boolean snippet combination."""
    return tuple(1 for _ in capabilities)


def generate_support_scenario_combinations(
    capabilities: List[AttackerCapability],
) -> List[Tuple[int, ...]]:
    """Generate base and singleton combinations required downstream."""
    if not capabilities:
        return []

    support_combinations = [generate_base_capability_presence_combination(capabilities)]
    for index in range(len(capabilities)):
        combo = list(generate_base_capability_presence_combination(capabilities))
        combo[index] = 1
        support_combinations.append(tuple(combo))

    return support_combinations


def generate_scenario_combinations(capabilities: List[AttackerCapability]) -> List[Tuple[int, ...]]:
    """Generate all possible combinations of capability variants.
    
    Returns list of tuples where each element is an index:
    - 0 = exclude capability
    - 1+ = variant index (1-indexed)
    
    Args:
        capabilities: List of capabilities to combine
        
    Returns:
        List of tuples representing all combinations
    """
    choices_per_capability = [list(range(len(cap.variants) + 1)) for cap in capabilities]
    return list(product(*choices_per_capability))


def build_scenario_content(
    combination: Tuple[int, ...],
    capabilities: List[AttackerCapability],
    content_chunks: List[Optional[str]],
    use_primary_variants_only: bool = False,
) -> Tuple[str, List[AttackVariant], Dict[str, float]]:
    """Build output content for a scenario combination.
    
    Args:
        combination: Tuple of variant choices (0=exclude, 1+=variant index)
        capabilities: List of capabilities being combined
        content_chunks: Content chunks with None placeholders for capabilities
        use_primary_variants_only: When True, include snippets as booleans and
            attach only the primary capability names without variant costs
        
    Returns:
        Tuple of (output_content, attack_variants_used, total_costs)
    """
    output_content = ''
    attack_variants: List[AttackVariant] = []
    total_costs: Dict[str, float] = {}
    
    # Process content chunks and insert capabilities based on combination
    cap_idx = 0
    for chunk in content_chunks:
        if chunk is None:
            # This is a capability placeholder
            if cap_idx < len(capabilities):
                choice = combination[cap_idx]
                if choice > 0:
                    if use_primary_variants_only:
                        variant = AttackVariant(
                            name=capabilities[cap_idx].primary_name,
                            costs={},
                        )
                    else:
                        variant = capabilities[cap_idx].variants[choice - 1]
                    attack_variants.append(variant)
                    output_content += capabilities[cap_idx].content
                    
                    if not use_primary_variants_only:
                        # Accumulate costs when variant choices are part of the scenario.
                        for cost_dim, cost_val in variant.costs.items():
                            total_costs[cost_dim] = total_costs.get(cost_dim, 0) + cost_val
                else:
                    output_content += f'(* No {capabilities[cap_idx].primary_name}*)'
                cap_idx += 1
        else:
            # Regular content chunk
            output_content += chunk
    
    return output_content, attack_variants, total_costs


def extract_queries(content: str) -> List[Dict[str, str]]:
    """Extract ProVerif checks (query/weaksecret) and their tags from content.
    
    Args:
        content: ProVerif file content
        
    Returns:
        List of dicts with 'tag' and 'query' keys
    """
    query_pattern = r'(?:\(\*\s*([^*)]+?)\s*\*\)\s*)?((?:query|weaksecret)\s+.*?)(?=\n|$)'
    query_matches = re.finditer(query_pattern, content, re.MULTILINE)
    queries: List[Dict[str, str]] = []
    
    for match in query_matches:
        statement = match.group(2).strip()
        default_tag = statement.split(None, 1)[0].lower() if statement else "query"
        tag = match.group(1).strip() if match.group(1) else default_tag
        queries.append({
            'tag': tag,
            'query': match.group(0)
        })
    
    return queries


def create_scenario_filename(included_capabilities: List[str]) -> str:
    """Create a scenario filename from included capabilities.
    
    Args:
        included_capabilities: List of capability names
        
    Returns:
        Filename stem (without extension)
    """
    if not included_capabilities:
        return "base_scenario"
    return '+'.join(re.sub(r'[^a-zA-Z0-9_]', '_', name.lower()) 
                    for name in included_capabilities)
