"""Analyze scenario verification results."""

from itertools import product
from typing import Dict, List, Any, FrozenSet, Tuple, Optional
from .models import ScenarioResult, AttackerCapability


def analyze_minimal_false_combinations(
    results: List[ScenarioResult],
    input_files: List[str],
    capabilities_by_input: Optional[Dict[str, List[AttackerCapability]]] = None,
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Analyze results to find minimal scenario combinations that make queries false.
    
    For each input file and query, finds the Pareto front of subset-minimal
    capability combinations that make the query false.

    Minimality is computed in two stages:
    1. Keep only false combinations whose enabled capability set has no proper
       false subset.
    2. Pareto-reduce those subset-minimal combinations by total cost.

    This preserves the intended semantics for exhaustive variant evaluation,
    while also handling lazy boolean-snippet evaluation where costs are not yet
    attached to the verified scenarios.
    
    Args:
        results: List of ScenarioResult objects from verification
        input_files: List of original input file paths
        capabilities_by_input: Optional mapping used to reconstruct variant-cost
            combinations offline once subset-minimal capability sets are known
    
    Returns:
        Dict mapping input_file -> query_tag -> list of dicts with 'scenarios' and 'costs'
    """
    from pathlib import Path
    
    # Group results by input file
    analysis = {}
    
    for input_file in input_files:
        input_stem = Path(input_file).stem
        analysis[input_file] = {}
        
        # Find all results from this input file
        file_results = [r for r in results if input_stem in str(r.scenario.path)]
        
        if not file_results:
            continue
        
        # Get query tags from first result
        query_tags = [q['tag'] for q in file_results[0].query_results]
        
        # For each query, find false combinations
        for query_idx, query_tag in enumerate(query_tags):
            false_combinations = []
            
            for result in file_results:
                if query_idx < len(result.query_results):
                    query_result = result.query_results[query_idx]
                    if query_result['result'] is False:
                        false_combinations.append({
                            'scenarios': set(result.scenario.capability_names),
                            'costs': result.scenario.costs
                        })

            minimal_combinations = _find_subset_minimal_combinations(false_combinations)

            expanded_combinations = minimal_combinations
            if capabilities_by_input and input_file in capabilities_by_input:
                expanded_combinations = _expand_minimal_combinations_to_variant_costs(
                    minimal_combinations,
                    capabilities_by_input[input_file],
                )

            analysis[input_file][query_tag] = _pareto_reduce_by_cost(expanded_combinations)
    
    return analysis


def _find_subset_minimal_combinations(
    false_combinations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Return false combinations whose capability set has no proper false subset."""
    return _filter_undominated_combinations(
        false_combinations,
        _scenario_subset_dominates,
    )


def _pareto_reduce_by_cost(combinations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return the cost Pareto front from a list of subset-minimal combinations."""
    return _filter_undominated_combinations(
        combinations,
        lambda other_combo, combo: _cost_dominates(other_combo['costs'], combo['costs']),
    )


def _expand_minimal_combinations_to_variant_costs(
    minimal_combinations: List[Dict[str, Any]],
    capabilities: List[AttackerCapability],
) -> List[Dict[str, Any]]:
    """Expand subset-minimal capability sets into offline variant-cost options."""
    expanded: List[Dict[str, Any]] = []

    for combo in minimal_combinations:
        capability_names = combo['scenarios']
        if not capability_names:
            expanded.append({
                'scenarios': set(),
                'costs': {},
            })
            continue

        selected_capabilities = [
            capability
            for capability in capabilities
            if capability.primary_name in capability_names
        ]
        if len(selected_capabilities) != len(capability_names):
            expanded.append(combo)
            continue

        for variant_combination in product(*(capability.variants for capability in selected_capabilities)):
            total_costs: Dict[str, float] = {}
            for variant in variant_combination:
                for dimension, value in variant.costs.items():
                    total_costs[dimension] = total_costs.get(dimension, 0) + value

            expanded.append({
                'scenarios': set(capability_names),
                'costs': total_costs,
            })

    return _deduplicate_combinations(expanded)


def _cost_dominates(left_costs: Dict[str, float], right_costs: Dict[str, float]) -> bool:
    """Return whether one cost vector dominates another."""
    all_dims = set(left_costs.keys()) | set(right_costs.keys())
    strictly_less = False

    for dim in all_dims:
        left_val = left_costs.get(dim, 0)
        right_val = right_costs.get(dim, 0)

        if left_val > right_val:
            return False
        if left_val < right_val:
            strictly_less = True

    return strictly_less


def _scenario_subset_dominates(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Return whether one scenario set is a strict subset of another."""
    return left['scenarios'] < right['scenarios']


def _filter_undominated_combinations(
    combinations: List[Dict[str, Any]],
    dominates,
) -> List[Dict[str, Any]]:
    """Keep combinations that are not dominated under the provided predicate."""
    minimal_combinations: List[Dict[str, Any]] = []

    for combo in combinations:
        is_minimal = True
        for other_combo in combinations:
            if combo is other_combo:
                continue

            if dominates(other_combo, combo):
                is_minimal = False
                break

        if is_minimal:
            minimal_combinations.append(combo)

    return _deduplicate_combinations(minimal_combinations)


def _deduplicate_combinations(combinations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Preserve order while removing duplicate scenario/cost pairs."""
    seen: set[Tuple[FrozenSet[str], Tuple[Tuple[str, float], ...]]] = set()
    deduplicated: List[Dict[str, Any]] = []

    for combo in combinations:
        key = (
            frozenset(combo['scenarios']),
            tuple(sorted(combo['costs'].items())),
        )
        if key in seen:
            continue

        seen.add(key)
        deduplicated.append(combo)

    return deduplicated
