"""Tests for UPPAAL XML generation."""

import sys
from xml.etree import ElementTree as ET

import attack_tree_extractor
from compareverif.attack_tree import AttackTreeExtractor, DerivationTree
from compareverif.proverif import ProVerifOutput
from compareverif.uppaal import UppaalGenerator


def test_render_empty_writes_an_empty_nta_document(tmp_path):
    output_file = tmp_path / "model.xml"

    UppaalGenerator.render_empty(output_file)

    document = output_file.read_text()
    root = ET.parse(output_file).getroot()
    assert "<!DOCTYPE nta PUBLIC '-//Uppaal Team//DTD Flat System 1.6//EN'" in document
    assert root.tag == "nta"
    assert [element.tag for element in root] == ["declaration", "template", "system", "queries"]


def test_render_tree_declares_all_nodes_and_prerequisite_loops(tmp_path):
    output_file = tmp_path / "model.xml"
    tree = DerivationTree(goal="attacker(secret)")
    tree.add_node("event(login)", node_type="fact")
    tree.add_node("Rainbow table attack", node_type="capability", variant_id="capability_leaf")
    tree.add_edge("attacker(secret)", "event(login)")
    tree.add_edge("event(login)", "Rainbow table attack", target_variant="capability_leaf")

    UppaalGenerator.render_tree(output_file, tree)

    document = output_file.read_text()
    root = ET.parse(output_file).getroot()
    transitions = root.findall(".//transition")
    assert len(transitions) == len(tree.nodes)
    assert "// Attacker learns secret." in document
    assert "// Event login happens." in document
    assert "// Rainbow table attack" in document
    assert "bool_attacker_secret_goal_1" in document
    assert "bool_event_login_2" in document
    assert "bool_rainbow_table_attack_capability_leaf_3" in document
    assert "!bool_attacker_secret_goal_1" in document
    assert "bool_event_login_2 == true" in document
    assert "bool_rainbow_table_attack_capability_leaf_3 == true" in document
    assert "<location id=\"event_loop\"" in document
    assert "<nail x=" in document
    assert 'kind="comment"' in document


def test_cli_uppaal_out_writes_model_for_all_tree_nodes(tmp_path, monkeypatch):
    output_file = tmp_path / "model.xml"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "attack_tree_extractor.py",
            "scenario.pv",
            "--uppaal-out",
            str(output_file),
        ],
    )
    monkeypatch.setattr(
        AttackTreeExtractor,
        "extract",
        lambda _self, *_args, **_kwargs: ProVerifOutput(
            derivations=[],
        ),
    )

    stub_tree = DerivationTree(goal="attacker(secret)")
    stub_tree.add_node("event(login)", node_type="fact")
    stub_tree.add_edge("attacker(secret)", "event(login)")
    monkeypatch.setattr(
        attack_tree_extractor.GraphvizRenderer,
        "build_tree_from_derivations",
        lambda *_args, **_kwargs: stub_tree,
    )
    monkeypatch.setattr(
        attack_tree_extractor.AttackTreeExtractor,
        "print_summary",
        lambda *_args, **_kwargs: None,
    )

    attack_tree_extractor.main()

    document = output_file.read_text()
    assert "bool_attacker_secret_goal_1" in document
    assert "bool_event_login_2" in document
    assert ET.parse(output_file).getroot().tag == "nta"