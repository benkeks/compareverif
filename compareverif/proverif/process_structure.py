"""Decompose a process into a linear prefix followed by one parallel composition.

Our UPPAAL translation only supports processes of the shape
``stmt; stmt; ...; (component_1 | component_2 | ...)``: a straight-line sequence
of declarations/updates/db operations, ending in a single top-level parallel
composition. Each component becomes its own automaton in later translation
steps.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .intermediate_process import IntermediateProcess, ProcessSyntaxNode
from .syntax_utils import IDENTIFIER_PATTERN, IDENTIFIER_RE, strip_proverif_comments


_SOURCE_TOKEN_RE = re.compile(rf'"(?:\\.|[^"\\])*"|{IDENTIFIER_PATTERN}|\|\||[^\s]')
_PROCESS_STATEMENT_NAMES = {
    "in", "out", "insert", "event", "new", "get", "if", "let", "phase", "sync", "yield", "barrier",
}


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
            "expected process format (step; step; (proc1 | proc2)), with the prefix or "
            "parallel part optionally omitted"
        )

    prefix: list[ProcessSyntaxNode] = []
    node = process.nodes[0]
    if _is_parallel(node):
        return ProcessDecomposition(prefix=[], components=node.children)
    while True:
        if node.label is None:
            raise UnsupportedProcessStructureError(
                f"unexpected {node.text!r}; expected process format "
                "(step; step; (proc1 | proc2)), with the prefix or parallel part optionally omitted"
            )
        if node.text.startswith("if "):
            return ProcessDecomposition(prefix=[], components=[process.nodes[0]])
        if len(node.children) == 1 and _is_parallel(node.children[0]):
            prefix.append(node)
            return ProcessDecomposition(prefix=prefix, components=node.children[0].children)
        if not node.children:
            prefix.append(node)
            return ProcessDecomposition(prefix=prefix, components=[])
        if len(node.children) != 1:
            # A branch cannot occur in the linear prefix. Reinterpret the whole
            # process as one component so its preceding steps remain local to it.
            return ProcessDecomposition(prefix=[], components=[process.nodes[0]])
        prefix.append(node)
        node = node.children[0]


def _is_parallel(node: ProcessSyntaxNode) -> bool:
    return node.label is None and node.text == "parallel"


def collect_source_component_macro_names(source: str) -> list[str | None]:
    """Collect positional names for direct or replicated macro calls in the main process."""
    tokens = _SOURCE_TOKEN_RE.findall(strip_proverif_comments(source))
    try:
        tokens = tokens[tokens.index("process") + 1:]
    except ValueError:
        return []
    if tokens and tokens[-1] == ".":
        tokens = tokens[:-1]
    tokens = _ungroup_source_tokens(tokens)
    if tokens and tokens[0] in {"new", "insert"}:
        tokens = _split_source_tokens(tokens, ";")[-1]
    components = _source_parallel_components(tokens)
    names: list[str | None] = []
    for component in components:
        component = _ungroup_source_tokens(component)
        if component and component[0] == "!":
            component = _ungroup_source_tokens(component[1:])
        if (
            component
            and IDENTIFIER_RE.fullmatch(component[0])
            and component[0] not in _PROCESS_STATEMENT_NAMES
            and (
                len(component) == 1
                or (
                    len(component) > 2
                    and component[1] == "("
                    and _matching_source_paren(component, 1) == len(component) - 1
                )
            )
        ):
            names.append(component[0])
        else:
            names.append(None)
    return names


def _matching_source_paren(tokens: list[str], start: int) -> int | None:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == "(":
            depth += 1
        elif tokens[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _ungroup_source_tokens(tokens: list[str]) -> list[str]:
    while tokens and tokens[0] == "(" and _matching_source_paren(tokens, 0) == len(tokens) - 1:
        tokens = tokens[1:-1]
    return tokens


def _split_source_tokens(tokens: list[str], separator: str) -> list[list[str]]:
    parts: list[list[str]] = []
    start = 0
    depth = 0
    for index, token in enumerate(tokens):
        if token in {"(", "["}:
            depth += 1
        elif token in {")", "]"}:
            depth -= 1
        elif token == separator and depth == 0:
            parts.append(tokens[start:index])
            start = index + 1
    parts.append(tokens[start:])
    return parts


def _source_parallel_components(tokens: list[str]) -> list[list[str]]:
    tokens = _ungroup_source_tokens(tokens)
    parts = _split_source_tokens(tokens, "|")
    if len(parts) == 1:
        return parts
    return [component for part in parts for component in _source_parallel_components(part)]
