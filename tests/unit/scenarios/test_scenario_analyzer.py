"""Tests for scenario result analysis."""

from pathlib import Path

from compareverif.scenarios.analyzer import analyze_minimal_false_combinations
from compareverif.scenarios.models import ScenarioFile, ScenarioResult, AttackerCapability, AttackVariant


def _result(path: str, capability_names: list[str], costs: dict[str, float], outcome: bool) -> ScenarioResult:
    scenario = ScenarioFile(
        path=Path(path),
        capabilities=[],
        costs=costs,
        queries=[{"tag": "q", "query": "query attacker(secret)."}],
        capability_names=capability_names,
    )
    return ScenarioResult(
        scenario=scenario,
        status="success",
        query_results=[{"tag": "q", "result": outcome}],
    )


def test_analyzer_uses_subset_minimality_when_costs_are_empty():
    analysis = analyze_minimal_false_combinations(
        [
            _result("_scenarios/test/base_scenario.pv", [], {}, True),
            _result("_scenarios/test/a.pv", ["A"], {}, True),
            _result("_scenarios/test/a+b.pv", ["A", "B"], {}, False),
            _result("_scenarios/test/a+b+c.pv", ["A", "B", "C"], {}, False),
        ],
        ["test.pv"],
    )

    assert analysis["test.pv"]["q"] == [
        {"scenarios": {"A", "B"}, "costs": {}},
    ]


def test_analyzer_pareto_reduces_subset_minimal_variant_costs():
    analysis = analyze_minimal_false_combinations(
        [
            _result("_scenarios/test/base_scenario.pv", [], {}, True),
            _result("_scenarios/test/a_low.pv", ["A"], {"time": 10}, False),
            _result("_scenarios/test/a_high.pv", ["A"], {"time": 100}, False),
            _result("_scenarios/test/a_b.pv", ["A", "B"], {"time": 12}, False),
        ],
        ["test.pv"],
    )

    assert analysis["test.pv"]["q"] == [
        {"scenarios": {"A"}, "costs": {"time": 10}},
    ]


def test_analyzer_reconstructs_variant_costs_from_capability_fronts():
    analysis = analyze_minimal_false_combinations(
        [
            _result("_scenarios/test/base_scenario.pv", [], {}, True),
            _result("_scenarios/test/a.pv", ["A"], {}, False),
        ],
        ["test.pv"],
        capabilities_by_input={
            "test.pv": [
                AttackerCapability(
                    primary_name="A",
                    variants=[
                        AttackVariant(name="A slow", costs={"time": 100}),
                        AttackVariant(name="A cheap", costs={"time": 10}),
                        AttackVariant(name="A stealth", costs={"hack": 1}),
                    ],
                    content="attacker(a).",
                ),
            ],
        },
    )

    assert analysis["test.pv"]["q"] == [
        {"scenarios": {"A"}, "costs": {"time": 10}},
        {"scenarios": {"A"}, "costs": {"hack": 1}},
    ]