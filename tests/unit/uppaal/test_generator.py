"""Tests for UPPAAL XML generation."""

import re
import sys
from xml.etree import ElementTree as ET

import attack_tree_extractor
import pytest
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
    main_transitions = root.findall(".//template[name='EventLoop']/transition")
    capability_transitions = root.findall(".//template[name='Obtain_cap_rainbow_table_attack']/transition")
    assert len(main_transitions) == 2
    assert len(capability_transitions) == 1
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
    assert "<name>Obtain_cap_rainbow_table_attack</name>" in document
    capability_template = root.find(".//template[name='Obtain_cap_rainbow_table_attack']")
    assert any(name.text == "Obtained" for name in capability_template.findall("location/name"))
    assert "cap_rainbow_table_attack_process = Obtain_cap_rainbow_table_attack();" in document
    assert "<source ref=\"cap_rainbow_table_attack_idle\"" in document
    assert "<target ref=\"cap_rainbow_table_attack_obtained\"" in document
    assert "goal_attacker_secret_goal_1_c!" in document
    assert "ev_event_login_2_c!" in document
    assert "cap_rainbow_table_attack_c!" in document
    assert "<formula>E&lt;&gt; goal_attacker_secret_goal_1</formula>" in document
    assert "<comment>Attacker learns secret.</comment>" in document
    assert "<location id=\"event_loop\"" in document
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


def test_capability_backend_selects_timed_skeleton_from_attributes(tmp_path):
    output_file = tmp_path / "model.xml"
    tree = DerivationTree(
        goal="attacker(secret)",
        capability_attributes={
            "Database leak": {"unlocking_time": "2", "mitigation_time": "1"},
            "Rainbow table attack": {},
        },
    )
    tree.add_node(
        "Database leak",
        node_type="capability",
        capabilities={"Database leak"},
        variant_id="capability_leaf_1",
    )
    tree.add_node(
        "Rainbow table attack",
        node_type="capability",
        capabilities={"Rainbow table attack"},
        variant_id="capability_leaf_2",
    )

    UppaalGenerator.render_tree(output_file, tree)

    templates = ET.parse(output_file).getroot().findall("template")
    declarations = {
        template.findtext("name"): template.findtext("declaration")
        for template in templates
    }
    assert "// Backend: mitigatable_capability" in declarations["Obtain_cap_database_leak"]
    assert "// Backend: immediate_capability" in declarations["Obtain_cap_rainbow_table_attack"]

    standard_template = ET.parse(output_file).getroot().find(
        ".//template[name='Obtain_cap_rainbow_table_attack']"
    )
    assert "clock" not in (standard_template.findtext("declaration") or "")
    assert not any(name.text == "Committed" for name in standard_template.findall("location/name"))


def test_timed_capability_has_parameterized_three_state_acquisition(tmp_path):
    output_file = tmp_path / "model.xml"
    tree = DerivationTree(
        goal="attacker(secret)",
        capability_costs={"Database leak": {"hack": 1}},
        capability_attributes={
            "Database leak": {"unlocking_time": "2", "mitigation_time": "1"}
        },
    )
    tree.add_node(
        "Database leak",
        node_type="capability",
        capabilities={"Database leak"},
        variant_id="capability_leaf",
    )

    UppaalGenerator.render_tree(output_file, tree)

    root = ET.parse(output_file).getroot()
    template = root.find(".//template[name='Obtain_cap_database_leak']")
    assert template.findtext("parameter") == "int unlocking_time, int mitigation_time"
    assert "clock unlocking_clock, mitigation_clock;" in template.findtext("declaration")
    assert "broadcast chan cap_database_leak_start;" in root.findtext("declaration")
    assert "broadcast chan cap_database_leak_mitigated;" in root.findtext("declaration")
    assert {name.text for name in template.findall("location/name")} == {
        "Idle",
        "Committed",
        "Obtained",
    }
    locations = {
        location.findtext("name"): (location.attrib["x"], location.attrib["y"])
        for location in template.findall("location")
    }
    assert locations["Idle"] == ("0", "0")
    assert locations["Committed"] == ("260", "-140")
    assert locations["Obtained"] == ("520", "0")
    assert [child.tag for child in template] == [
        "name",
        "parameter",
        "declaration",
        "location",
        "location",
        "location",
        "init",
        "transition",
        "transition",
        "transition",
        "transition",
    ]
    transitions = template.findall("transition")
    assert len(transitions) == 4
    assert "unlocking_clock = 0" in ET.tostring(transitions[0], encoding="unicode")
    assert "cap_database_leak_start!" in ET.tostring(transitions[0], encoding="unicode")
    assert "unlocking_clock &gt;= unlocking_time" in ET.tostring(transitions[1], encoding="unicode")
    obtained_location = template.find("location[name='Obtained']")
    assert obtained_location.findtext("label[@kind='invariant']") == "mitigation_clock <= mitigation_time"
    committed_timeout = template.find("transition[@id='capability_transition_committed_timeout']")
    assert committed_timeout.findtext("label[@kind='guard']") == "mitigation_clock >= mitigation_time"
    assert committed_timeout.findtext("label[@kind='assignment']") == "mitigation_clock = 0"
    assert committed_timeout.findtext("label[@kind='synchronisation']") == "cap_database_leak_mitigated!"
    obtained_timeout = template.find("transition[@id='capability_transition_obtained_timeout']")
    assert obtained_timeout.findtext("label[@kind='guard']") == "mitigation_clock >= mitigation_time"
    assert obtained_timeout.findtext("label[@kind='assignment']") == (
        "cap_database_leak = false, mitigation_clock = 0"
    )
    assert obtained_timeout.findtext("label[@kind='synchronisation']") == "cap_database_leak_mitigated!"
    assert "database_leak_process = Obtain_cap_database_leak(2, 1);" in output_file.read_text()


@pytest.mark.parametrize(
    "attributes, expected_message",
    [
        ({"unlocking_time": "2"}, "missing mitigation_time"),
        ({"mitigation_time": "1"}, "missing unlocking_time"),
        ({"unlocking_time": "soon", "mitigation_time": "1"}, "malformed unlocking_time"),
        ({"unlocking_time": "2", "mitigation_time": "-1"}, "invalid mitigation_time"),
    ],
)
def test_timed_capability_rejects_invalid_timing_attributes(
    tmp_path, attributes, expected_message
):
    output_file = tmp_path / "model.xml"
    tree = DerivationTree(
        goal="attacker(secret)",
        capability_attributes={"Database leak": attributes},
    )
    tree.add_node(
        "Database leak",
        node_type="capability",
        capabilities={"Database leak"},
        variant_id="capability_leaf",
    )

    with pytest.raises(ValueError, match=expected_message):
        UppaalGenerator.render_tree(output_file, tree)