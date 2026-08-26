"""Decompose a process into a linear prefix followed by one parallel composition.

Our UPPAAL translation only supports processes of the shape
``stmt; stmt; ...; (component_1 | component_2 | ...)``: a straight-line sequence
of declarations/updates/db operations, ending in a single top-level parallel
composition. Each component becomes its own automaton in later translation
steps.
"""

from __future__ import annotations

from dataclasses import dataclass

from .intermediate_process import IntermediateProcess, ProcessSyntaxNode


class UnsupportedProcessStructureError(ValueError):
    """Raised when a process is not a linear prefix followed by one parallel composition."""


@dataclass(frozen=True)
class ProcessDecomposition:
    """A process split into its linear prefix statements and parallel components."""

    prefix: list[ProcessSyntaxNode]
    components: list[ProcessSyntaxNode]


def decompose_process(process: IntermediateProcess) -> ProcessDecomposition:
    """Split a process into its linear prefix and top-level parallel components."""
    if len(process.nodes) != 1:
        raise UnsupportedProcessStructureError(
            f"expected a single top-level process statement, found {len(process.nodes)}"
        )

    prefix: list[ProcessSyntaxNode] = []
    node = process.nodes[0]
    while True:
        if node.label is None:
            raise UnsupportedProcessStructureError(
                f"unexpected {node.text!r} branching before a top-level parallel composition"
            )
        if len(node.children) == 1 and _is_parallel(node.children[0]):
            prefix.append(node)
            return ProcessDecomposition(prefix=prefix, components=node.children[0].children)
        if len(node.children) != 1:
            raise UnsupportedProcessStructureError(
                f"statement at {{{node.label}}} has {len(node.children)} continuations; "
                "expected a linear prefix ending in one top-level parallel composition"
            )
        prefix.append(node)
        node = node.children[0]


def _is_parallel(node: ProcessSyntaxNode) -> bool:
    return node.label is None and node.text == "parallel"
