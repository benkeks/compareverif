"""Tests for attack-tree query selection helpers."""

from pathlib import Path

from attack_tree_extractor import _query_options_for_output
from compareverif.proverif import Derivation, ProVerifOutput


def test_query_options_use_manifest_tags_and_support_indexing():
    output = ProVerifOutput(
        derivations=[
            Derivation(conclusion="goal1", rule_name="goal", indent_level=0, query="query attacker(a)."),
            Derivation(conclusion="goal2", rule_name="goal", indent_level=0, query="weaksecret attacker(b)."),
        ],
        clauses=[],
    )
    manifest = {
        "scenarios": [
            {
                "file": "scenario.pv",
                "queries": [
                    {"tag": "first query", "query": "query attacker(a)."},
                    {"tag": "second query", "query": "weaksecret attacker(b)."},
                ],
            }
        ]
    }

    options, canonical_to_display = _query_options_for_output(output, manifest, Path("scenario.pv"))

    assert [option.name for option in options] == ["first query", "second query"]
    assert options[0].value == "attacker(a)"
    assert canonical_to_display["attacker(a)"] == "query attacker(a)."