"""Generate scenario file combinations."""

import re
from typing import Dict, List, Tuple, Optional
from itertools import product
from .models import AttackerCapability, AttackVariant


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
    content_chunks: List[Optional[str]]
) -> Tuple[str, List[AttackVariant], Dict[str, float]]:
    """Build output content for a scenario combination.
    
    Args:
        combination: Tuple of variant choices (0=exclude, 1+=variant index)
        capabilities: List of capabilities being combined
        content_chunks: Content chunks with None placeholders for capabilities
        
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
                    variant = capabilities[cap_idx].variants[choice - 1]
                    attack_variants.append(variant)
                    output_content += capabilities[cap_idx].content
                    
                    # Accumulate costs
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
    """Extract query statements and their tags from content.
    
    Args:
        content: ProVerif file content
        
    Returns:
        List of dicts with 'tag' and 'query' keys
    """
    query_pattern = r'(?:\(\*\s*([^*)]+?)\s*\*\)\s*)?query\s+.*?(?=\n|$)'
    query_matches = re.finditer(query_pattern, content, re.MULTILINE)
    queries: List[Dict[str, str]] = []
    
    for match in query_matches:
        tag = match.group(1).strip() if match.group(1) else "query"
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
