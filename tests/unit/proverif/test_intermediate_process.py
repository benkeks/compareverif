"""Tests for extraction of ProVerif's labeled intermediate process."""

import pytest

from compareverif.proverif.intermediate_process import extract_let_drifted_process


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
    assert [node.label for node in process.nodes[0].children] == [2, 4]
    assert process.nodes[0].children[1].children[0].label == 5


def test_render_tree_shows_labeled_process_structure():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert process.render_tree() == """Process 1: that is, process 0, with let moved downwards
`-- {1} new key: bitstring;
    |-- {2} let value: bitstring = message in
    |   `-- {3} out(c, value)
    `-- {4} in(c, received: bitstring);
        `-- {5} if received = message then
            |-- {6} event accepted
            `-- {7} else event rejected"""


def test_rejects_output_without_let_drifted_process():
    with pytest.raises(ValueError, match="let-drifted process"):
        extract_let_drifted_process("Process 0 (that is, the initial process):\n")