"""Tests for UPPAAL XML generation."""

import re
import sys
from xml.etree import ElementTree as ET

import attack_tree_extractor
from compareverif.attack_tree import AttackTreeExtractor, DerivationTree
from compareverif.proverif import Derivation, ProVerifOutput
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
    tree = DerivationTree(
        goal="attacker(secret)",
        capability_costs={"Rainbow table attack": {"time": 10, "hack": 1}},
    )
    tree.add_node("event(login)", node_type="fact")
    tree.add_node(
        "Rainbow table attack",
        node_type="capability",
        capabilities={"Rainbow table attack"},
        variant_id="capability_leaf",
    )
    tree.add_edge("attacker(secret)", "event(login)")
    tree.add_edge("event(login)", "Rainbow table attack", target_variant="capability_leaf")

    UppaalGenerator.render_tree(output_file, tree)

    document = output_file.read_text()
    root = ET.parse(output_file).getroot()
    transitions = root.findall(".//transition")
    assert len(transitions) == len(tree.nodes)
    first_transition_children = [child.tag for child in transitions[0]]
    assert first_transition_children == ["source", "target", "label", "label", "label", "label", "nail", "nail"]
    loop_heights = [transition.findall("nail")[0].attrib["y"] for transition in transitions]
    assert len(loop_heights) == len(set(loop_heights))
    assert "// Attacker learns secret." in document
    assert "// Event login happens." in document
    assert "// Rainbow table attack" in document
    assert "bool goal_attacker_secret_goal_1 = false;" in document
    assert "bool ev_event_login_2 = false;" in document
    assert "bool cap_rainbow_table_attack = false;" in document
    assert "broadcast chan goal_attacker_secret_goal_1_c;" in document
    assert "broadcast chan ev_event_login_2_c;" in document
    assert "broadcast chan cap_rainbow_table_attack_c;" in document
    assert "int res_time = 10;" in document
    assert "int res_hack = 1;" in document
    assert "!goal_attacker_secret_goal_1" in document
    assert "ev_event_login_2" in document
    assert "cap_rainbow_table_attack" in document
    assert "res_time &gt;= 10" in document
    assert "res_hack &gt;= 1" in document
    assert "cap_rainbow_table_attack = true, res_time -= 10, res_hack -= 1" in document
    assert "goal_attacker_secret_goal_1_c!" in document
    assert "ev_event_login_2_c!" in document
    assert "cap_rainbow_table_attack_c!" in document
    assert "<formula>E&lt;&gt; goal_attacker_secret_goal_1</formula>" in document
    assert "<comment>Attacker learns secret.</comment>" in document
    assert "<location id=\"event_loop\"" in document
    assert "<nail x=" in document
    assert 'kind="synchronisation"' in document
    assert 'kind="comments"' in document


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
            derivations=[Derivation(conclusion="attacker(secret)", rule_name="goal", indent_level=0)],
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
    assert "goal_attacker_secret_goal_1" in document
    assert "ev_event_login_2" in document
    assert "<formula>E&lt;&gt; goal_attacker_secret_goal_1</formula>" in document
    assert ET.parse(output_file).getroot().tag == "nta"


def test_render_tree_limits_non_capability_variable_names_to_100_characters(tmp_path):
    output_file = tmp_path / "model.xml"
    long_fact = f"attacker({'secret_' * 30})"
    tree = DerivationTree(goal=long_fact)
    tree.add_node("Attack-A", node_type="capability", variant_id="capability_leaf")

    UppaalGenerator.render_tree(output_file, tree)

    declarations = ET.parse(output_file).getroot().find("declaration").text
    variable_names = re.findall(r"^bool (\w+) = false;$", declarations, re.MULTILINE)
    assert all(len(name) <= 60 for name in variable_names)
    assert "cap_attack_a" in variable_names