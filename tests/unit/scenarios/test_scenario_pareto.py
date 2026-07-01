"""Tests for Pareto-front rendering helpers."""

import json
from pathlib import Path

import matplotlib

from compareverif.scenarios import ParetoFrontRenderer

matplotlib.use("Agg")


def test_renderer_projects_analysis_with_aliases():
    renderer = ParetoFrontRenderer.from_analysis(
        {
            "examples/hashed_passwords.pv": {
                "no pw leakage": [
                    {
                        "scenarios": {"rainbow_table_attack", "intruder_at_database"},
                        "costs": {"time": 10, "hack": 1},
                    },
                    {
                        "scenarios": {"rainbow_table_attack"},
                        "costs": {"time": 20, "hack": 2},
                    },
                ]
            }
        },
        scenario_aliases={
            "intruder_at_database": "intruder-at-db",
            "rainbow_table_attack": "rainbow-table",
        },
    )

    fronts = renderer.get_front_points("no pw leakage", costs=("time", "hack"))

    assert renderer.resolve_cost_dimensions() == ("time", "hack")
    assert fronts["hashed_passwords"] == [
        fronts["hashed_passwords"][0],
    ]
    assert fronts["hashed_passwords"][0].label == "intruder-at-db+rainbow-table"
    assert fronts["hashed_passwords"][0].costs == {"time": 10.0, "hack": 1.0}


def test_renderer_loads_manifests_from_directory_and_reconstructs_costs(tmp_path):
    input_file = tmp_path / "example_model.pv"
    input_file.write_text(
        """(*** Rainbow table attack [100 time]\nattacker(secret).\n***)\n"
        "(*** Intruder at database [2 hack]\nattacker(secret).\n***)\n"
        "(* no pw leakage *)\nquery attacker(secret).\n"
        "(* no hash leakage *)\nquery attacker(hash(secret)).\n""",
        encoding="utf-8",
    )

    manifest_dir = tmp_path / "_scenarios" / "example_model"
    manifest_dir.mkdir(parents=True)
    manifest_path = manifest_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "input_file": str(input_file),
                "scenarios": [
                    {
                        "file": "base_scenario.pv",
                        "path": str(manifest_dir / "base_scenario.pv"),
                        "capabilities": [],
                        "total_costs": {},
                        "queries": [
                            {"tag": "no pw leakage", "query": "query attacker(secret)."},
                            {"tag": "no hash leakage", "query": "query attacker(hash(secret))."},
                        ],
                        "verification": {
                            "status": "success",
                            "query_results": [
                                {"tag": "no pw leakage", "result": True},
                                {"tag": "no hash leakage", "result": True},
                            ],
                        },
                    },
                    {
                        "file": "rainbow_table_attack.pv",
                        "path": str(manifest_dir / "rainbow_table_attack.pv"),
                        "capabilities": [{"name": "Rainbow table attack", "costs": {}}],
                        "total_costs": {},
                        "queries": [
                            {"tag": "no pw leakage", "query": "query attacker(secret)."},
                            {"tag": "no hash leakage", "query": "query attacker(hash(secret))."},
                        ],
                        "verification": {
                            "status": "success",
                            "query_results": [
                                {"tag": "no pw leakage", "result": True},
                                {"tag": "no hash leakage", "result": True},
                            ],
                        },
                    },
                    {
                        "file": "intruder_at_database.pv",
                        "path": str(manifest_dir / "intruder_at_database.pv"),
                        "capabilities": [{"name": "Intruder at database", "costs": {}}],
                        "total_costs": {},
                        "queries": [
                            {"tag": "no pw leakage", "query": "query attacker(secret)."},
                            {"tag": "no hash leakage", "query": "query attacker(hash(secret))."},
                        ],
                        "verification": {
                            "status": "success",
                            "query_results": [
                                {"tag": "no pw leakage", "result": True},
                                {"tag": "no hash leakage", "result": True},
                            ],
                        },
                    },
                    {
                        "file": "intruder_at_database+rainbow_table_attack.pv",
                        "path": str(manifest_dir / "intruder_at_database+rainbow_table_attack.pv"),
                        "capabilities": [
                            {"name": "Intruder at database", "costs": {}},
                            {"name": "Rainbow table attack", "costs": {}},
                        ],
                        "total_costs": {},
                        "queries": [
                            {"tag": "no pw leakage", "query": "query attacker(secret)."},
                            {"tag": "no hash leakage", "query": "query attacker(hash(secret))."},
                        ],
                        "verification": {
                            "status": "success",
                            "query_results": [
                                {"tag": "no pw leakage", "result": False},
                                {"tag": "no hash leakage", "result": True},
                            ],
                        },
                    },
                ],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    renderer = ParetoFrontRenderer.from_manifest_inputs([manifest_dir])

    assert renderer.resolve_queries("1") == ["no pw leakage"]
    assert renderer.resolve_cost_dimensions() == ("time", "hack")

    fronts = renderer.get_front_points("no pw leakage")
    assert fronts["example_model"][0].costs == {"time": 100.0, "hack": 2.0}
    assert fronts["example_model"][0].scenarios == (
        "intruder_at_database",
        "rainbow_table_attack",
    )