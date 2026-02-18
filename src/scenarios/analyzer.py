"""Analyze scenario verification results."""

from typing import Dict, List, Any, Set
from .models import ScenarioResult


def analyze_minimal_false_combinations(
    results: List[ScenarioResult],
    input_files: List[str]
) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """Analyze results to find minimal scenario combinations that make queries false.
    
    For each input file and query, finds all minimal sets of included scenarios
    that result in a false query (where minimal means no other false-making 
    combination has pointwise lower or equal costs in all dimensions).
    
    Args:
        results: List of ScenarioResult objects from verification
        input_files: List of original input file paths
    
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
                    # Collect false results with their costs
                    if query_result['result'] is False:
                        scenario_names = [s.name for s in result.scenario.capabilities]
                        false_combinations.append({
                            'scenarios': set(scenario_names),
                            'costs': result.scenario.costs
                        })
            
            # Find minimal combinations using pointwise cost comparison
            # A combination is minimal if no other combination has costs
            # pointwise <= in all dimensions AND strictly < in at least one
            minimal_combinations = []
            for combo in false_combinations:
                is_minimal = True
                for other_combo in false_combinations:
                    if combo == other_combo:
                        continue
                    
                    # Check if other_combo dominates combo (costs pointwise <=)
                    all_dims = set(combo['costs'].keys()) | set(other_combo['costs'].keys())
                    dominates = True
                    strictly_less = False
                    
                    for dim in all_dims:
                        combo_val = combo['costs'].get(dim, 0)
                        other_val = other_combo['costs'].get(dim, 0)
                        
                        if other_val > combo_val:
                            # other is worse in this dimension
                            dominates = False
                            break
                        elif other_val < combo_val:
                            # other is strictly better in this dimension
                            strictly_less = True
                    
                    if dominates and strictly_less:
                        # other_combo dominates combo
                        is_minimal = False
                        break
                
                if is_minimal:
                    minimal_combinations.append(combo)
            
            analysis[input_file][query_tag] = minimal_combinations
    
    return analysis
