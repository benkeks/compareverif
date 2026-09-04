"""Tests for decomposing a process into a linear prefix and parallel components."""

import pytest

from compareverif.proverif.intermediate_process import IntermediateProcess, extract_let_drifted_process
from compareverif.proverif.process_structure import (
    UnsupportedProcessStructureError,
    decompose_process,
)


def _process(body: str) -> IntermediateProcess:
    output = (
        f"--  Process 1 (that is, process 0, with let moved downwards):\n{body}\n\n"
        "Translating the process into Horn clauses...\n"
    )
    return extract_let_drifted_process(output)


def test_decomposes_linear_prefix_and_parallel_components():
    process = _process(
        "{1}new key: bitstring;\n"
        "{2}insert singularizations(user1,singularization1);\n"
        "(\n"
        "    {3}!\n"
        "    {4}out(c, key)\n"
        ") | (\n"
        "    {5}in(c, x: bitstring)\n"
        ")"
    )

    decomposition = decompose_process(process)

    assert [node.label for node in decomposition.prefix] == [1, 2]
    assert len(decomposition.components) == 2
    assert decomposition.components[0].label == 3
    assert decomposition.components[1].label == 5


def test_raises_when_no_top_level_parallel_composition():
    process = _process("{1}new key: bitstring;\n{2}if a = b then\n    {3}out(c, key)\nelse\n    {4}event no")

    with pytest.raises(UnsupportedProcessStructureError, match="process format"):
        decompose_process(process)


def test_decomposes_prefix_only_process():
    process = _process("{1}new key: bitstring;\n{2}out(c, key)")

    decomposition = decompose_process(process)

    assert [node.label for node in decomposition.prefix] == [1, 2]
    assert decomposition.components == []


def test_decomposes_parallel_only_process():
    process = _process(
        "(\n"
        "    {1}out(c, key)\n"
        ") | (\n"
        "    {2}event done\n"
        ")"
    )

    decomposition = decompose_process(process)

    assert decomposition.prefix == []
    assert [node.label for node in decomposition.components] == [1, 2]


def test_raises_when_prefix_branches_before_parallel():
    process = _process(
        "{1}if a = b then\n"
        "    {2}event yes\n"
        "else\n"
        "    {3}event no"
    )

    with pytest.raises(UnsupportedProcessStructureError, match=r"\{1\}"):
        decompose_process(process)
