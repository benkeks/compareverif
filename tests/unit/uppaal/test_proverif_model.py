"""Tests for building a blank UPPAAL model from a parsed ProVerif process."""

from xml.etree import ElementTree as ET

import pytest

from compareverif.proverif.intermediate_process import extract_let_drifted_process
from compareverif.proverif.process_structure import UnsupportedProcessStructureError
from compareverif.uppaal import (
    DynamicChannelError,
    collect_channel_names,
    collect_table_arities,
    extract_global_free_names,
    render_channel_skeleton,
)


PROVERIF_OUTPUT = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}!
    {3}in(server_link, ct: bitstring);
    {4}out(server_link, ct)
) | (
    {5}in(tick, seconds(3));
    {6}out(loop, ())
)

Translating the process into Horn clauses...
"""

TABLE_PROVERIF_OUTPUT = """--  Process 1 (that is, process 0, with let moved downwards):
{1}insert singularizations(user1,singularization1);
{2}insert passwd(user1,hashed(singularized(pw1,singularization1),salt1),salt1);
(
    {3}get passwd(uid1: uid,hashedpw: bitstring,salt: bitstring) suchthat ((uid1 = u) && (hashedpw = hashed(pw1,salt))) in
        {4}out(c, uid1)
) | (
    {5}event done
)

Translating the process into Horn clauses...
"""


def test_collect_channel_names_deduplicates_and_preserves_first_seen_order():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert collect_channel_names(process) == ["server_link", "tick", "loop"]


def test_render_channel_skeleton_declares_channel_and_payload_variable(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    channels = render_channel_skeleton(output_file, process)

    assert channels == ["server_link", "tick", "loop"]
    document = output_file.read_text()
    root = ET.parse(output_file).getroot()
    assert "<!DOCTYPE nta PUBLIC '-//Uppaal Team//DTD Flat System 1.6//EN'" in document
    assert root.tag == "nta"
    for channel in channels:
        assert f"chan {channel};" in document
        assert f"int {channel}_p;" in document


def test_render_channel_skeleton_builds_prefix_and_component_automata(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    document = output_file.read_text()
    root = ET.parse(output_file).getroot()

    # `new key` in the prefix becomes a global variable, and the fork channel is declared globally.
    assert "int key;" in document
    assert "broadcast chan _fork;" in document

    template_names = [template.findtext("name") for template in root.findall("template")]
    assert template_names == ["Prefix", "Component1", "Component2"]

    for name in template_names:
        locations = root.findall(f".//template[name='{name}']/location")
        assert [location.get("id") for location in locations] == [f"{name}_before", f"{name}_after"]
        transition = root.find(f".//template[name='{name}']/transition")
        synchronisation = transition.find("label[@kind='synchronisation']").text
        assert synchronisation == ("_fork!" if name == "Prefix" else "_fork?")

    # `ct` (from `in(server_link, ct: bitstring)`) is local to Component1, not global or in Component2.
    assert "int ct;" in root.findtext(".//template[name='Component1']/declaration")
    assert "No locally declared names." in root.findtext(".//template[name='Component2']/declaration")

    system_text = root.findtext("system")
    assert "system Prefix, Component1, Component2;" in system_text
    prefix_assignments = [
        transition.findtext("label[@kind='assignment']")
        for transition in root.findall(".//template[name='Prefix']/transition")
    ]
    assert prefix_assignments == ["key = NEW()"]


def test_collect_table_arities_counts_top_level_arguments_only():
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)

    # `passwd`'s insert has a nested hashed(...) argument that must not be split on its inner comma.
    assert collect_table_arities(process) == {"singularizations": 2, "passwd": 3}


def test_extract_global_free_names_preserves_source_order():
    source = """free user1, pw1: bitstring [ private ].
free singularization1: bitstring [ private ].
free salt1: bitstring [ private ].
"""

    assert extract_global_free_names(source) == ["user1", "pw1", "singularization1", "salt1"]


def test_dynamically_bound_channel_raises_error_pointing_to_use_and_declaration():
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{12}new answer_channel: channel;
{14}in(answer_channel, singularized_pw_enc: bitstring)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(DynamicChannelError) as excinfo:
        collect_channel_names(process)

    assert "{14}" in str(excinfo.value)
    assert "{12}" in str(excinfo.value)
    assert "answer_channel" in str(excinfo.value)


def test_render_channel_skeleton_declares_table_struct_arrays(tmp_path):
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    document = output_file.read_text()
    assert "const int SINGULARIZATIONS_CAPACITY = 3;" in document
    assert "struct { int first, second; } singularizations[SINGULARIZATIONS_CAPACITY];" in document
    assert "int singularizations_size = 0;" in document
    assert "const int PASSWD_CAPACITY = 3;" in document
    assert "struct { int first, second, third; } passwd[PASSWD_CAPACITY];" in document
    assert "int passwd_size = 0;" in document


def test_prefix_new_and_insert_steps_generate_fresh_ids_and_table_updates(tmp_path):
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(
        output_file,
        process,
        global_free_names=["user1", "pw1", "singularization1", "salt1"],
    )

    root = ET.parse(output_file).getroot()
    declarations = root.findtext("declaration")
    prefix_transitions = root.findall(".//template[name='Prefix']/transition")
    assignments = [
        transition.findtext("label[@kind='assignment']") for transition in prefix_transitions
    ]

    assert "int user1 = 1;" in declarations
    assert "int pw1 = 2;" in declarations
    assert "int singularization1 = 3;" in declarations
    assert "int salt1 = 4;" in declarations
    assert "int entity_counter = 4;" in declarations
    assert "int NEW() { entity_counter++; return entity_counter; }" in declarations
    assert "int singularized(int value1, int value2) { return NEW(); }" in declarations
    assert "int hashed(int value1, int value2) { return NEW(); }" in declarations

    assert "void singularizations_insert(int value1, int value2) {" in declarations
    assert "singularizations[singularizations_size].first = value1;" in declarations
    assert "singularizations_size++;" in declarations
    assert "void passwd_insert(int value1, int value2, int value3) {" in declarations
    assert "passwd[passwd_size].third = value3;" in declarations

    assert assignments == [
        "singularizations_insert(user1, singularization1)",
        "passwd_insert(user1, hashed(singularized(pw1,singularization1),salt1), salt1)",
    ]
    assert prefix_transitions[-1].findtext("label[@kind='synchronisation']") == "_fork!"

    prefix_locations = root.findall(".//template[name='Prefix']/location")
    assert [(location.get("x"), location.get("y")) for location in prefix_locations] == [
        ("0", "0"),
        ("0", "160"),
        ("0", "320"),
    ]
    assert [
        (label.get("x"), label.get("y"))
        for label in prefix_transitions[1].findall("label")
    ] == [("30", "200"), ("30", "225"), ("30", "250")]


def test_render_channel_skeleton_rejects_process_without_top_level_parallel(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
{2}out(c, key)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(UnsupportedProcessStructureError):
        render_channel_skeleton(tmp_path / "model.xml", process)


