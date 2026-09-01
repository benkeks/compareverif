"""Tests for building a blank UPPAAL model from a parsed ProVerif process."""

import warnings

from xml.etree import ElementTree as ET

import pytest

from compareverif.proverif.intermediate_process import extract_let_drifted_process
from compareverif.proverif.attack_process import AttackProcess
from compareverif.proverif.libraries import read_declared_library_sources
from compareverif.proverif.process_structure import UnsupportedProcessStructureError
from compareverif.uppaal import (
    ComplexInputPatternError,
    ConstructorTagOverflowError,
    ConstructorWidthWarning,
    GeneratedNameCollisionWarning,
    GlobalNameCountWarning,
    DynamicChannelError,
    NestedReplicationError,
    TupleDataError,
    UnsupportedGetConditionError,
    collect_channel_names,
    collect_leak_channels,
    collect_table_arities,
    contains_replication,
    extract_global_free_names,
    extract_proverif_functions,
    ProVerifFunctions,
    ReservedTranslationNameError,
    UnknownUppaalPragmaWarning,
    analyze_constructor_widths,
    render_channel_skeleton,
    reject_reserved_global_names,
    parse_uppaal_pragmas,
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
    {3}get passwd(uid1: uid,hashedpw: bitstring,salt: bitstring) suchthat uid1 = u in
        {4}out(c, uid1)
) | (
    {5}event done
)

Translating the process into Horn clauses...
"""


def test_collect_channel_names_deduplicates_and_preserves_first_seen_order():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert collect_channel_names(process) == ["server_link", "tick", "loop"]


def test_leak_output_uses_broadcast_channel(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
(
    {1}out(leak, secret)
) | (
    {2}out(c, value)
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    assert collect_leak_channels(process) == {"leak"}
    render_channel_skeleton(output_file, process)
    declarations = ET.parse(output_file).getroot().findtext("declaration")
    assert "broadcast chan leak;" in declarations
    assert "chan c;" in declarations
    assert "broadcast chan c;" not in declarations


def test_render_channel_skeleton_declares_channel_and_payload_variable(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    channels = render_channel_skeleton(output_file, process)

    assert channels == ["server_link", "tick", "loop"]
    document = output_file.read_text()
    root = ET.parse(output_file).getroot()
    assert "<!DOCTYPE nta PUBLIC '-//Uppaal Team//DTD Flat System 1.6//EN'" in document
    assert root.tag == "nta"
    assert root.findtext("declaration").startswith(
        "typedef int [-1, (1 << 31) - 1] data;"
    )
    for channel in channels:
        assert f"chan {channel};" in document
        assert f"data {channel}_p;" in document


def test_render_channel_skeleton_builds_prefix_and_component_automata(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    document = output_file.read_text()
    root = ET.parse(output_file).getroot()

    # `new key` in the prefix becomes a global variable, and the fork channel is declared globally.
    assert "data key;" in document
    assert "broadcast chan _fork;" in document

    template_names = [template.findtext("name") for template in root.findall("template")]
    assert template_names == ["Prefix", "Component1", "Component2"]

    prefix_locations = root.findall(".//template[name='Prefix']/location")
    assert [location.get("id") for location in prefix_locations] == [
        "Prefix_step_1",
        "Prefix_terminated",
        "Prefix_forked",
    ]
    for name in template_names:
        locations = root.findall(f".//template[name='{name}']/location")
        if name == "Prefix":
            assert locations[0].get("id") == "Prefix_step_1"
            assert any(location.get("id") == "Prefix_terminated" for location in locations)
        else:
            assert locations[0].get("id") == f"{name}_before"
            has_replication = root.find(f".//template[name='{name}']/location[name='replication']") is not None
            assert any(location.get("id") == f"{name}_terminated" for location in locations) == (not has_replication)
        child_tags = [child.tag for child in root.find(f".//template[name='{name}']")]
        assert child_tags == sorted(
            child_tags,
            key={"name": 0, "declaration": 1, "location": 2, "init": 3, "transition": 4}.get,
        )
        transitions = root.findall(f".//template[name='{name}']/transition")
        transition = (
            next(t for t in transitions if t.find("target").get("ref") == "Prefix_forked")
            if name == "Prefix"
            else transitions[0]
        )
        synchronisation = transition.find("label[@kind='synchronisation']").text
        assert synchronisation == ("_fork!" if name == "Prefix" else "_fork?")

    # `ct` (from `in(server_link, ct: bitstring)`) is local to Component1, not global or in Component2.
    assert "data ct;" in root.findtext(".//template[name='Component1']/declaration")
    component_two_declaration = root.findtext(".//template[name='Component2']/declaration")
    assert "clock seconds_clock;" in component_two_declaration
    assert "data delay;" not in component_two_declaration
    assert "data seconds(data value1)" not in document
    component_two_labels = [
        (label.get("kind"), label.text)
        for label in root.findall(".//template[name='Component2']//label")
    ]
    assert ("synchronisation", "tick!") in component_two_labels
    assert "broadcast chan tick;" in document
    assert ("assignment", "seconds_clock = 0") in component_two_labels
    assert ("assignment", "seconds_clock = 0") in component_two_labels
    assert ("invariant", "seconds_clock <= 3") in component_two_labels
    assert ("guard", "seconds_clock == 3") in component_two_labels
    replication = root.find(".//template[name='Component1']/location[name='replication']")
    assert replication is not None
    replication_id = replication.get("id")
    component_one_transitions = root.findall(".//template[name='Component1']/transition")
    assert any(
        transition.find("target").get("ref") == replication_id
        and transition.find("source").get("ref") != "Component1_before"
        for transition in component_one_transitions
    )
    location_names = [location.findtext("name") for location in root.findall(".//template/location")]
    assert "step_3" in location_names
    assert all("{" not in name and "}" not in name for name in location_names if name)

    system_text = root.findtext("system")
    assert "system Prefix, Component1, Component2;" in system_text
    prefix_assignments = [
        transition.findtext("label[@kind='assignment']")
        for transition in root.findall(".//template[name='Prefix']/transition")
    ]
    assert [assignment for assignment in prefix_assignments if assignment is not None] == ["key = NEW()"]


def test_render_channel_skeleton_adds_attack_template_and_success_query(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    attack = AttackProcess(
        query="not attacker(secret)",
        query_number=1,
        nodes=(
            extract_let_drifted_process(
                "--  Process 1 (that is, process 0, with let moved downwards):\n"
                "{1}in(server_link, attack_message: bitstring);\n"
                "{2}if attack_message = secret then\n"
                "    {3}event attack_breaks_query_1()\n"
                "\nTranslating the process into Horn clauses...\n"
            ).nodes[0],
        ),
    )
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process, attack_processes=[attack])

    root = ET.parse(output_file).getroot()
    assert "AttackOnQuery1" in [template.findtext("name") for template in root.findall("template")]
    assert "system Prefix, Component1, Component2, AttackOnQuery1;" in root.findtext("system")
    assert root.findtext(".//template[name='AttackOnQuery1']/location[name='success']") is not None
    assert "E<> AttackOnQuery1.success" in [formula.text for formula in root.findall(".//queries/query/formula")]
    attack_transitions = root.findall(".//template[name='AttackOnQuery1']/transition")
    assert all(
        transition.findtext("label[@kind='synchronisation']") != "_fork?"
        for transition in attack_transitions
    )
    assert any(
        transition.find("target").get("ref") == "AttackOnQuery1_failed"
        and transition.findtext("label[@kind='guard']") == "!(attack_message == secret)"
        for transition in attack_transitions
    )


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


def test_all_caps_global_names_are_reserved_for_translation():
    with pytest.raises(ReservedTranslationNameError, match="ALL_CAPS names are reserved"):
        reject_reserved_global_names("fun MK(bitstring): bitstring.\nfree SECRET: bitstring.")


def test_warns_when_generated_channel_payload_name_appears_in_source(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    with pytest.warns(GeneratedNameCollisionWarning, match="server_link_p"):
        render_channel_skeleton(
            tmp_path / "model.xml",
            process,
            input_source="free server_link_p: bitstring [private].",
        )


def test_parse_uppaal_pragmas_configures_channels_and_warns_unknown_fields():
    source = """(* UPPAAL
non_blocking_channels:
  - c
time_channels:
  - timer
additional_queries:
  - A[] true
additional_queriess:
  - E&lt;&gt; true
*)
"""

    with pytest.warns(UnknownUppaalPragmaWarning, match="additional_queriess"):
        pragmas = parse_uppaal_pragmas(source)

    assert pragmas.non_blocking_channels == ["c"]
    assert pragmas.time_channels == ["timer"]
    assert pragmas.additional_queries == ["A[] true"]


def test_additional_queries_are_written_verbatim(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    render_channel_skeleton(
        tmp_path / "model.xml",
        process,
        additional_queries=["A[] true", "E<> Component1.terminated"],
    )

    formulas = [
        formula.text
        for formula in ET.parse(tmp_path / "model.xml").getroot().findall(".//queries/query/formula")
    ]
    assert formulas == ["A[] true", "E<> Component1.terminated"]


def test_configured_non_blocking_and_time_channels_override_defaults(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
(
    {1}out(c, value)
) | (
    {2}in(timer, seconds(3));
    {3}out(c, value)
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    render_channel_skeleton(
        tmp_path / "model.xml",
        process,
        non_blocking_channels=["c"],
        time_channels=["timer"],
    )

    document = (tmp_path / "model.xml").read_text()
    assert "broadcast chan c;" in document
    assert "broadcast chan timer;" in document
    assert "clock seconds_clock;" in document


def test_free_channel_name_is_not_declared_as_data(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(
        output_file,
        process,
        global_free_names=["server_link", "secret"],
    )

    declarations = ET.parse(output_file).getroot().findtext("declaration")
    assert "chan server_link;" in declarations
    assert "data server_link;" not in declarations
    assert "data secret = 1;" in declarations


def test_contains_replication_detects_replication_nodes():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert contains_replication(process)


def test_extract_proverif_functions_separates_constructors_and_selectors():
    source = """fun pair(bitstring, bitstring): bitstring.
fun select(bitstring): bitstring.
fun nonce(): bitstring.
fun seconds(nat): bitstring.
reduc forall value: bitstring; select(value) = value.
reduc forall first: bitstring, second: bitstring; nested(select(first), second) = first.
(* reduc forall value: bitstring; ignored(value) = value. *)
"""

    functions = extract_proverif_functions(source)

    assert functions.constructors == ["pair", "nonce"]
    assert functions.selectors == ["select", "nested"]
    assert functions.arities == {
        "pair": 2,
        "select": 1,
        "nonce": 0,
        "seconds": 1,
        "nested": 2,
    }


def test_render_channel_skeleton_lists_source_function_kinds(tmp_path):
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"
    functions = extract_proverif_functions(
        """fun pair(bitstring, bitstring): bitstring.
fun unary(bitstring): bitstring.
fun select(bitstring): bitstring.
fun nonce(): bitstring.
reduc forall value: bitstring; select(value) = value.
"""
    )

    render_channel_skeleton(output_file, process, proverif_functions=functions)

    declarations = ET.parse(output_file).getroot().findtext("declaration")
    assert "// ProVerif constructors." in declarations
    assert "const int PAIR = 1;" in declarations
    assert "const int UNARY = 2;" in declarations
    assert "const int NONCE = 3;" in declarations
    assert "data BUILD_PAIR(int datatype_id, data first, data second) {" in declarations
    assert "return datatype_id | (first_width << 4) | (first << 8) | (second << (8 + (first_width * 4)));" in declarations
    assert "data pair(data value1, data value2) { return BUILD_PAIR(PAIR, value1, value2); }" in declarations
    assert "data unary(data value1) { return UNARY + (value1 << 4); }" in declarations
    assert "data nonce() { return NONCE; }" in declarations
    assert "// ProVerif selectors defined by reduc rules." in declarations
    assert "data select(data value1) { if (true) return value1; return -1; }" in declarations
    assert "const int SELECT" not in declarations


def test_render_channel_skeleton_generates_packed_selectors(tmp_path):
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"
    functions = extract_proverif_functions(
        """fun wrap(bitstring): bitstring.
fun pair(bitstring, bitstring): bitstring.
reduc forall value: bitstring; unwrap(wrap(value)) = value.
reduc forall first: bitstring, second: bitstring; take_first(pair(first, second)) = first.
reduc forall first: bitstring, second: bitstring; match_second(pair(first, second), second) = first.
"""
    )

    render_channel_skeleton(output_file, process, proverif_functions=functions)

    declarations = ET.parse(output_file).getroot().findtext("declaration")
    assert "int TYPE_TAG(data value) { return value & 15; }" in declarations
    assert "data UNWRAP(data value) { return value >> 4; }" in declarations
    assert "data PAIR_FIRST(data value) {" in declarations
    assert "data PAIR_SECOND(data value) {" in declarations
    assert "data unwrap(data value1) { if (TYPE_TAG(value1) == WRAP) return UNWRAP(value1); return -1; }" in declarations
    assert "data take_first(data value1) { if (TYPE_TAG(value1) == PAIR) return PAIR_FIRST(value1); return -1; }" in declarations
    assert "data match_second(data value1, data value2) { if (TYPE_TAG(value1) == PAIR && value2 == PAIR_SECOND(value1)) return PAIR_FIRST(value1); return -1; }" in declarations


def test_wide_data_mode_declares_struct_typedef_and_bitwise_helpers(tmp_path):
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process, wide_data=True)

    declarations = ET.parse(output_file).getroot().findtext("declaration")
    assert "typedef int [-1, (1 << 31) - 1] data;" not in declarations
    assert "typedef int data[4];" not in declarations
    assert "typedef struct {" in declarations
    assert "  int[0, 65535] b0;" in declarations
    assert "  int[0, 65535] b16;" in declarations
    assert "  int[0, 65535] b32;" in declarations
    assert "  int[0, 65535] b48;" in declarations
    assert "} data;" in declarations
    assert "result[" not in declarations
    assert "value[" not in declarations
    assert "const data DATA_ZERO = {0, 0, 0, 0};" in declarations
    assert "const data DATA_NONE = {65535, 65535, 65535, 65535};" in declarations
    assert "data DATA_FROM_INT(int value) {" in declarations
    assert "  if (value < 0 || value >= 65535) return DATA_NONE;" in declarations
    assert "data DATA_SHL(data value, int amount) {" in declarations
    assert "data DATA_SHR(data value, int amount) {" in declarations
    assert "data DATA_OR(data a, data b) {" in declarations
    assert "data DATA_AND(data a, data b) {" in declarations


def test_wide_data_mode_uses_helpers_in_constructors_selectors_and_new(tmp_path):
    process = extract_let_drifted_process(TABLE_PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"
    functions = extract_proverif_functions(
        """fun pair(bitstring, bitstring): bitstring.
fun unary(bitstring): bitstring.
fun nonce(): bitstring.
fun select(bitstring): bitstring.
reduc forall value: bitstring; select(value) = value.
"""
    )

    render_channel_skeleton(
        output_file,
        process,
        proverif_functions=functions,
        global_free_names=["user1", "pw1", "singularization1", "salt1"],
        wide_data=True,
    )

    declarations = ET.parse(output_file).getroot().findtext("declaration")
    assert (
        "data BUILD_PAIR(int datatype_id, data first, data second) {" in declarations
    )
    assert "while (DATA_SHR(first, first_width * 4) != DATA_ZERO) first_width++;" in declarations
    assert (
        "return DATA_OR(DATA_OR(DATA_FROM_INT(datatype_id | (first_width << 4)), "
        "DATA_SHL(first, 8)), DATA_SHL(second, 8 + (first_width * 4)));"
    ) in declarations
    assert "data pair(data value1, data value2) { return BUILD_PAIR(PAIR, value1, value2); }" in declarations
    assert "data unary(data value1) { return DATA_OR(DATA_FROM_INT(UNARY), DATA_SHL(value1, 4)); }" in declarations
    assert "data nonce() { return DATA_FROM_INT(NONCE); }" in declarations
    assert "int TYPE_TAG(data value) { return DATA_AND(value, DATA_FROM_INT(15)).b0; }" in declarations
    assert "data UNWRAP(data value) { return DATA_SHR(value, 4); }" in declarations
    assert "data PAIR_FIRST(data value) {" in declarations
    assert "return DATA_AND(DATA_SHR(value, 8), DATA_ONES_MASK(PAIR_FIRST_WIDTH(value) * 4));" in declarations
    assert "data select(data value1) { if (true) return value1; return DATA_NONE; }" in declarations
    assert "data NEW() { entity_counter++; return DATA_FROM_INT(entity_counter); }" in declarations
    assert "data user1 = { 1, 0, 0, 0 };" in declarations
    assert "data salt1 = { 4, 0, 0, 0 };" in declarations


def test_wide_data_mode_uses_data_none_for_table_getters_and_get_guards(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}get table(value: bitstring,payload: bitstring) suchthat value = key in
        {3}out(c, payload)
) | (
    {4}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process, wide_data=True)

    root = ET.parse(output_file).getroot()
    declarations = root.findtext("declaration")
    assert "  return DATA_NONE;" in declarations
    labels = [
        (label.get("kind"), label.text)
        for label in root.findall(".//template[name='Component1']//label")
    ]
    assert ("guard", "table_get_second_by_first(key) != DATA_NONE") in labels



def test_library_functions_are_merged_into_constructor_and_selector_definitions(tmp_path):
    library = tmp_path / "primitives.pvl"
    library.write_text(
        """fun encrypt(bitstring): bitstring.
reduc forall value: bitstring; decrypt(encrypt(value)) = value.
"""
    )
    scenario = tmp_path / "scenario.pv"
    scenario.write_text(
        """(* -lib primitives.pvl *)
fun local(bitstring): bitstring.
fun seconds(nat): bitstring.
"""
    )

    functions = extract_proverif_functions(
        "\n".join([*read_declared_library_sources(scenario), scenario.read_text()])
    )

    assert functions.constructors == ["encrypt", "local"]
    assert functions.selectors == ["decrypt"]
    assert functions.arities == {"encrypt": 1, "decrypt": 1, "local": 1, "seconds": 1}


def test_constructor_width_warning_counts_nested_packed_components(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}out(c, aenc(msg(u,egenc(password,key)),singularization_server_pk))
) | (
    {3}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    functions = ProVerifFunctions(
        constructors=["aenc", "msg", "egenc"],
        selectors=["select"],
        arities={"aenc": 2, "msg": 2, "egenc": 2, "select": 1},
        rules={},
    )

    with pytest.warns(ConstructorWidthWarning, match="requires 10 packed components.*Use --wide-data"):
        render_channel_skeleton(tmp_path / "model.xml", process, proverif_functions=functions)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        render_channel_skeleton(
            tmp_path / "wide-model.xml",
            process,
            proverif_functions=functions,
            wide_data=True,
        )
    assert not any(issubclass(warning.category, ConstructorWidthWarning) for warning in caught)


def test_more_than_fifteen_constructors_are_rejected(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    names = [f"constructor{index}" for index in range(16)]
    functions = ProVerifFunctions(
        constructors=names,
        selectors=[],
        arities={name: 0 for name in names},
        rules={},
    )

    with pytest.raises(ConstructorTagOverflowError, match="at most fifteen"):
        render_channel_skeleton(tmp_path / "model.xml", process, proverif_functions=functions)


def test_more_than_fifteen_global_names_warn(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    with pytest.warns(GlobalNameCountWarning, match="creates 16 global names"):
        render_channel_skeleton(
            tmp_path / "model.xml",
            process,
            global_free_names=[f"free_name{index}" for index in range(15)],
        )


def test_neutral_function_uses_the_widest_constructor_argument(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}out(c, select(aenc(x,y)))
) | (
    {3}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    functions = ProVerifFunctions(
        constructors=["aenc"], selectors=["select"], arities={"aenc": 2, "select": 1}, rules={}
    )

    assert (2, 4, "select(aenc(x,y))") in analyze_constructor_widths(process, functions)


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
    assert "struct { data first, second; } singularizations[SINGULARIZATIONS_CAPACITY];" in document
    assert "int singularizations_size = 0;" in document
    assert "const int PASSWD_CAPACITY = 3;" in document
    assert "struct { data first, second, third; } passwd[PASSWD_CAPACITY];" in document
    assert "int passwd_size = 0;" in document


def test_component_insert_generates_shared_insert_helper(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
(
    {1}insert table(value)
) | (
    {2}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    root = ET.parse(output_file).getroot()
    declarations = root.findtext("declaration")
    labels = [
        (label.get("kind"), label.text)
        for label in root.findall(".//template[name='Component1']//label")
    ]
    assert "void table_insert(data value1) {" in declarations
    assert "table[table_size].first = value1;" in declarations
    assert ("assignment", "table_insert(value)") in labels


def test_prefix_communication_uses_statement_effect_translation(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}in(c, value: bitstring);
{2}out(c, value)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    transitions = ET.parse(output_file).getroot().findall(".//template[name='Prefix']/transition")
    labels = [
        (label.get("kind"), label.text)
        for transition in transitions
        for label in transition.findall("label")
    ]
    assert ("synchronisation", "c?") in labels
    assert ("assignment", "value = c_p") in labels
    assert ("synchronisation", "c!") in labels
    assert ("assignment", "c_p = value") in labels


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

    assert "data user1 = 1;" in declarations
    assert "data pw1 = 2;" in declarations
    assert "data singularization1 = 3;" in declarations
    assert "data salt1 = 4;" in declarations
    assert "int entity_counter = 4;" in declarations
    assert "data NEW() { entity_counter++; return entity_counter; }" in declarations
    assert "data singularized(data value1, data value2) { return NEW(); }" in declarations
    assert "data hashed(data value1, data value2) { return NEW(); }" in declarations

    assert "void singularizations_insert(data value1, data value2) {" in declarations
    assert "singularizations[singularizations_size].first = value1;" in declarations
    assert "singularizations_size++;" in declarations
    assert "void passwd_insert(data value1, data value2, data value3) {" in declarations
    assert "passwd[passwd_size].third = value3;" in declarations

    assert [assignment for assignment in assignments if assignment is not None] == [
        "singularizations_insert(user1, singularization1)",
        "passwd_insert(user1, hashed(singularized(pw1,singularization1),salt1), salt1)",
    ]
    assert prefix_transitions[-1].findtext("label[@kind='synchronisation']") == "_fork!"

    prefix_locations = root.findall(".//template[name='Prefix']/location")
    assert [(location.get("x"), location.get("y")) for location in prefix_locations] == [
        ("0", "0"),
        ("0", "160"),
        ("0", "320"),
        ("0", "480"),
    ]
    assert [
        (label.get("x"), label.get("y"))
        for label in prefix_transitions[1].findall("label")
    ] == [("30", "200"), ("30", "250")]


def test_render_channel_skeleton_rejects_process_without_top_level_parallel(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}if key = value then
    {2}out(c, key)
else
    {3}event done

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(UnsupportedProcessStructureError):
        render_channel_skeleton(tmp_path / "model.xml", process)


def test_component_translation_handles_process_constructs(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}!
    {3}in(c, x: bitstring);
    {4}let value: bitstring = x in
    {5}out(c, value)
) | (
    {6}get tb(first_value: bitstring,second_value: bitstring,third_value: bitstring) suchthat first_value = key in
        {7}event accepted(second_value)
    else
        {8}if key = value then
            {9}out(c, key);
        else
            {10}event rejected(value)
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    root = ET.parse(output_file).getroot()
    declarations = root.findtext("declaration")
    labels = [
        (label.get("kind"), label.text)
        for label in root.findall(".//template[name='Component1']//label")
        + root.findall(".//template[name='Component2']//label")
    ]
    assert "broadcast chan accepted;" in declarations
    assert "data accepted_p;" in declarations
    assert "data tb_get_second_by_first(data value1) {" in declarations
    assert "data tb_get_third_by_first(data value1) {" in declarations
    assert "int suchthat(" not in declarations
    assert ("synchronisation", "c?") in labels
    assert ("assignment", "x = c_p") in labels
    assert ("assignment", "value = x") in labels
    assert ("synchronisation", "c!") in labels
    assert ("assignment", "c_p = value") in labels
    assert ("guard", "tb_get_second_by_first(key) != -1 && tb_get_third_by_first(key) != -1") in labels
    assert ("assignment", "second_value = tb_get_second_by_first(key), third_value = tb_get_third_by_first(key)") in labels
    assert ("synchronisation", "accepted!") in labels
    assert ("guard", "key == value") in labels
    assert ("guard", "!(key == value)") in labels
    branch_locations = root.findall(".//template[name='Component2']/location")
    branch_x = {
        location.findtext("name"): int(location.get("x"))
        for location in branch_locations
        if location.findtext("name") in {"step_9", "step_10"}
    }
    assert branch_x["step_9"] < 0 < branch_x["step_10"]


def test_get_translation_preserves_nested_condition_terms(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new singularized_pw: bitstring;
(
    {2}get passwd(uid: uid,hashedpw: bitstring,salt: bitstring) suchthat uid = u in
        {3}out(c, salt)
) | (
    {4}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    labels = [
        (label.get("kind"), label.text)
        for label in ET.parse(output_file)
        .getroot()
        .findall(".//template[name='Component1']//label")
    ]
    getter = "passwd_get_second_by_first(u)"
    assert ("guard", f"{getter} != -1 && passwd_get_third_by_first(u) != -1") in labels
    assert ("assignment", f"hashedpw = {getter}, salt = passwd_get_third_by_first(u)") in labels


def test_get_matching_beyond_first_key_is_rejected(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}get passwd(uid: uid,hashedpw: bitstring,salt: bitstring) suchthat uid = key && hashedpw = hashed(pw,salt) in
        {3}event done
) | (
    {4}event other
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(UnsupportedGetConditionError, match="beyond the first key"):
        render_channel_skeleton(tmp_path / "model.xml", process)


def test_tuple_let_binding_is_rejected(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}let (left: bitstring,right: bitstring) = pair(key,key) in
    {3}out(c, left)
) | (
    {4}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(TupleDataError, match="Tuple data"):
        render_channel_skeleton(tmp_path / "model.xml", process)


def test_tuple_function_argument_is_rejected(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}out(c, hashed((key,key)))
) | (
    {3}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(TupleDataError, match="Tuple data"):
        render_channel_skeleton(tmp_path / "model.xml", process)


@pytest.mark.parametrize("pattern", ["hashed(value)", "first: bitstring, second: bitstring"])
def test_complex_input_pattern_is_rejected(tmp_path, pattern):
    output = f"""--  Process 1 (that is, process 0, with let moved downwards):
{{1}}new key: bitstring;
(
    {{2}}in(c, {pattern})
) | (
    {{3}}event done
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)

    with pytest.raises(ComplexInputPatternError, match="exactly one typed variable"):
        render_channel_skeleton(tmp_path / "model.xml", process)


def test_nested_replication_is_rejected(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{0}new key: bitstring;
(
    {1}!
        {2}!
            {3}event loop
) | (
    {4}event done
)

Translating the process into Horn clauses...
"""

    with pytest.raises(NestedReplicationError):
        render_channel_skeleton(tmp_path / "model.xml", extract_let_drifted_process(output))


def test_replicated_get_failure_loops_back_to_replication(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}!
    {3}get table(value: bitstring) suchthat value = key in
        {4}event done
) | (
    {5}event other
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"

    render_channel_skeleton(output_file, process)

    component = ET.parse(output_file).getroot().find(".//template[name='Component1']")
    replication_id = next(
        location.get("id") for location in component.findall("location")
        if location.findtext("name") == "replication"
    )
    failed_id = next(
        location.get("id") for location in component.findall("location")
        if location.findtext("name") == "get_failed"
    )
    assert any(
        transition.find("source").get("ref") == failed_id
        and transition.find("target").get("ref") == replication_id
        for transition in component.findall("transition")
    )


def test_get_failed_is_right_of_terminated(tmp_path):
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}get table(value: bitstring) suchthat value = key in
        {3}event done
) | (
    {4}event other
)

Translating the process into Horn clauses...
"""
    process = extract_let_drifted_process(output)
    output_file = tmp_path / "model.xml"
    render_channel_skeleton(output_file, process)
    component = ET.parse(output_file).getroot().find(".//template[name='Component1']")
    terminated = next(location for location in component.findall("location") if location.findtext("name") == "terminated")
    failed = next(location for location in component.findall("location") if location.findtext("name") == "get_failed")
    assert terminated.get("y") == failed.get("y")
    assert int(failed.get("x")) > int(terminated.get("x"))


