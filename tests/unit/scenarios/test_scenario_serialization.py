"""Tests for scenario serialization helpers."""

from pathlib import Path

from compareverif.scenarios.models import AttackVariant, ScenarioFile, ScenarioResult
from compareverif.scenarios.serialization import build_manifest_scenario_entry, format_costs


def test_format_costs_sorts_dimensions_and_handles_empty():
    assert format_costs({}) == "no cost"
    assert format_costs({"time": 10, "hack": 2}) == "2 hack, 10 time"


def test_build_manifest_scenario_entry_without_result():
    scenario = ScenarioFile(
        path=Path("scenario.pv"),
        capabilities=[AttackVariant(name="Attack A", costs={"time": 5})],
        costs={"time": 5},
        queries=[{"tag": "q", "query": "query attacker(secret)."}],
        capability_names=["Attack A"],
    )

    entry = build_manifest_scenario_entry(scenario)

    assert entry["file"] == "scenario.pv"
    assert entry["capability_names"] == ["Attack A"]
    assert entry["capabilities"] == [{"name": "Attack A", "costs": {"time": 5}}]
    assert entry["total_costs"] == {"time": 5}
    assert "verification" not in entry


def test_build_manifest_scenario_entry_with_result():
    scenario = ScenarioFile(
        path=Path("scenario.pv"),
        capabilities=[],
        costs={},
        queries=[{"tag": "q", "query": "query attacker(secret)."}],
        capability_names=[],
    )
    result = ScenarioResult(
        scenario=scenario,
        status="success",
        query_results=[{"tag": "q", "result": True}],
    )

    entry = build_manifest_scenario_entry(scenario, result)

    assert entry["verification"] == {
        "status": "success",
        "query_results": [{"tag": "q", "result": True}],
        "error_message": None,
    }