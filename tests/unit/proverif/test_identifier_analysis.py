"""Tests for linking identifiers to their local declaration/definition sites."""

from compareverif.proverif.identifier_analysis import (
    collect_declared_name_types,
    collect_declared_names,
    declared_name_types_of,
    declared_names_of,
    resolve_channel_usages,
    resolve_identifiers,
)
from compareverif.proverif.intermediate_process import IntermediateProcess, extract_let_drifted_process


def _process(body: str) -> IntermediateProcess:
    output = (
        f"--  Process 1 (that is, process 0, with let moved downwards):\n{body}\n\n"
        "Translating the process into Horn clauses...\n"
    )
    return extract_let_drifted_process(output)


def test_new_bound_channel_used_in_out_is_locally_declared():
    process = _process(
        "{1}new answer_channel: channel;\n"
        "{2}out(answer_channel, secret)"
    )

    channel_usages = resolve_channel_usages(process)
    assert len(channel_usages) == 1
    usage = channel_usages[0]
    assert usage.name == "answer_channel"
    assert usage.node.label == 2
    assert not usage.is_global
    assert usage.declaration.node.label == 1


def test_let_destructured_channel_used_in_out_is_locally_declared():
    process = _process(
        "{1}let (u: uid,scrambled: bitstring,answer_channel_1: channel) = adec(x,server_secret) in\n"
        "{2}out(answer_channel_1, secret)"
    )

    [usage] = resolve_channel_usages(process)
    assert usage.name == "answer_channel_1"
    assert not usage.is_global
    assert usage.declaration.node.label == 1


def test_undeclared_channel_is_assumed_global():
    process = _process("{1}out(server_link, secret)")

    [usage] = resolve_channel_usages(process)
    assert usage.name == "server_link"
    assert usage.is_global


def test_in_pattern_variable_is_out_of_scope_for_condition_evaluated_before_it():
    process = _process(
        "{1}in(c, x: bitstring);\n"
        "{2}out(c, x)"
    )

    usages = resolve_identifiers(process)
    x_usage = next(usage for usage in usages if usage.name == "x")
    assert not x_usage.is_global
    assert x_usage.declaration.node.label == 1


def test_get_condition_can_see_its_own_pattern_variables():
    process = _process(
        "{1}get passwd(uid1: uid,hashedpw: bitstring,salt: bitstring) suchthat "
        "((uid1 = u) && (hashedpw = hashed(pw1,salt))) in\n"
        "{2}out(c, uid1)"
    )

    usages = resolve_identifiers(process)
    uid1_in_condition = [usage for usage in usages if usage.name == "uid1"]
    assert len(uid1_in_condition) == 2
    assert all(not usage.is_global for usage in uid1_in_condition)
    assert all(usage.declaration.node.label == 1 for usage in uid1_in_condition)


def test_declaration_is_not_visible_in_else_branch():
    process = _process(
        "{1}get passwd(uid1: uid) suchthat (uid1 = u) in\n"
        "    {2}out(c, uid1)\n"
        "else\n"
        "    {3}event missing(uid1)"
    )

    usages = resolve_identifiers(process)
    else_usage = next(usage for usage in usages if usage.node.label == 3)
    assert else_usage.is_global


def test_declared_names_of_covers_new_let_in_and_get():
    assert declared_names_of("new key: bitstring;") == ["key"]
    assert declared_names_of("let x: bitstring = expr in") == ["x"]
    assert declared_names_of("let (u: uid,pw: bitstring) = adec(x,k) in") == ["u", "pw"]
    assert declared_names_of("in(c, x: bitstring);") == ["x"]
    assert (
        declared_names_of("get passwd(uid1: uid,salt: bitstring) suchthat (uid1 = u) in")
        == ["uid1", "salt"]
    )
    assert declared_names_of("out(c, x)") == []


def test_declared_name_types_cover_typed_process_bindings():
    assert declared_name_types_of("new key: skey;") == {"key": "skey"}
    assert declared_name_types_of("let (u: uid,pw: bitstring) = pair in") == {
        "u": "uid",
        "pw": "bitstring",
    }
    process = _process("{1}new key: skey;\n{2}in(c, received: bitstring)")
    assert collect_declared_name_types(process.nodes) == {
        "key": "skey",
        "received": "bitstring",
    }


def test_collect_declared_names_walks_whole_subtree():
    process = _process(
        "{1}new key: bitstring;\n"
        "{2}let x: bitstring = key in\n"
        "{3}in(c, y: bitstring)"
    )

    assert collect_declared_names(process.nodes) == ["key", "x", "y"]

