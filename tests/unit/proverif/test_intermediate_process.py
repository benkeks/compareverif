"""Tests for extraction of ProVerif's labeled intermediate process."""

import pytest

from compareverif.proverif.intermediate_process import (
    extract_let_drifted_process,
    extract_preferred_process,
)


PROVERIF_OUTPUT = """Process 0 (that is, the initial process):
{1}new key: bitstring;

--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}let value: bitstring = message in
        {3}out(c, value)
) | (
    {4}in(c, received: bitstring);
    {5}if received = message then
        {6}event accepted
    else
        {7}event rejected
)

-- Query attacker(message) in process 1.
Translating the process into Horn clauses...
"""


def test_extracts_let_drifted_process_and_labels():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert process.number == 1
    assert "let moved downwards" in process.description
    assert [node.label for node in process.labeled_nodes()] == [1, 2, 3, 4, 5, 6, 7]
    parallel = process.nodes[0].children[0]
    assert parallel.text == "parallel"
    assert [node.label for node in parallel.children] == [2, 4]
    assert parallel.children[0].children[0].label == 3
    assert parallel.children[1].children[0].label == 5


def test_extract_preferred_process_falls_back_to_initial_process():
    output = """Process 0 (that is, the initial process):
{1}out(c, secret)

Translating the process into Horn clauses...
"""

    process = extract_preferred_process(output)

    assert process.number == 0
    assert process.description == "that is, the initial process"
    assert [node.label for node in process.labeled_nodes()] == [1]


def test_render_tree_shows_labeled_process_structure():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert process.render_tree() == """Process 1: that is, process 0, with let moved downwards
`-- {1} new key: bitstring;
    `-- parallel
        |-- {2} let value: bitstring = message in
        |   `-- {3} out(c, value)
        `-- {4} in(c, received: bitstring);
            `-- {5} if received = message then
                |-- then
                |   `-- {6} event accepted
                `-- else
                    `-- {7} event rejected"""


def test_get_in_and_else_are_rendered_as_separate_branches():
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}get credentials(user: bitstring,password: bitstring) in
    {2}out(c, password)
else
    {3}event missing_credentials

Translating the process into Horn clauses...
"""

    process = extract_let_drifted_process(output)

    assert process.render_tree() == """Process 1: that is, process 0, with let moved downwards
`-- {1} get credentials(user: bitstring,password: bitstring) in
    |-- {2} out(c, password)
    `-- else
        `-- {3} event missing_credentials"""


def test_let_drifting_keeps_same_indentation_continuations_as_children():
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}let first: bitstring = a in
{2}let second: bitstring = b in
{3}event complete

Translating the process into Horn clauses...
"""

    process = extract_let_drifted_process(output)

    assert process.render_tree() == """Process 1: that is, process 0, with let moved downwards
`-- {1} let first: bitstring = a in
    `-- {2} let second: bitstring = b in
        `-- {3} event complete"""


def test_replication_is_rendered_as_replication():
    output = """--  Process 1 (that is, process 0, with let moved downwards):
{1}!
{2}out(c, secret)

Translating the process into Horn clauses...
"""

    process = extract_let_drifted_process(output)

    assert process.render_tree() == """Process 1: that is, process 0, with let moved downwards
`-- {1} replication
    `-- {2} out(c, secret)"""


def test_rejects_output_without_let_drifted_process():
    with pytest.raises(ValueError, match="let-drifted process"):
        extract_let_drifted_process("Process 0 (that is, the initial process):\n")