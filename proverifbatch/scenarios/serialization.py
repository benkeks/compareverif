"""Scenario formatting and serialization helpers."""

from typing import Dict, Any, Optional

from .models import ScenarioFile, ScenarioResult


def format_costs(costs: Dict[str, float]) -> str:
    """Format scenario costs for human-readable output."""
    if not costs:
        return "no cost"

    return ", ".join(f"{value} {name}" for name, value in sorted(costs.items()))


def build_manifest_scenario_entry(
    scenario_file: ScenarioFile,
    result: Optional[ScenarioResult] = None,
) -> Dict[str, Any]:
    """Build one manifest entry for a generated scenario."""
    scenario_info: Dict[str, Any] = {
        'file': str(scenario_file.path.name),
        'path': str(scenario_file.path),
        'capabilities': [
            {
                'name': variant.name,
                'costs': variant.costs,
            }
            for variant in scenario_file.capabilities
        ],
        'total_costs': scenario_file.costs,
        'queries': [
            {
                'tag': query['tag'],
                'query': query['query'],
            }
            for query in scenario_file.queries
        ],
    }

    if result is not None:
        scenario_info['verification'] = {
            'status': result.status,
            'query_results': [
                {
                    'tag': query_result['tag'],
                    'result': query_result['result'],
                }
                for query_result in result.query_results
            ],
            'error_message': result.error_message,
        }

    return scenario_info