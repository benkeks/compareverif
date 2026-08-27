"""Extract the labeled intermediate process emitted by ``proverif -test``."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional


_PROCESS_HEADER_RE = re.compile(r"^--\s+Process\s+(\d+)\s*\((.+)\):\s*$")
_LABELED_LINE_RE = re.compile(r"^(?P<indent>\s*)\{(?P<label>\d+)\}(?P<text>.*)$")
_PROCESS_END_RE = re.compile(r"^(?:--\s+|Translating the process into Horn clauses)")


@dataclass
class ProcessSyntaxNode:
    """One labeled statement in ProVerif's displayed intermediate process."""

    label: Optional[int]
    text: str
    indent: int
    children: list["ProcessSyntaxNode"] = field(default_factory=list)
    has_parallel_children: bool = False


@dataclass
class IntermediateProcess:
    """A labeled syntax tree for one process displayed by ProVerif."""

    number: int
    description: str
    source_lines: list[str]
    nodes: list[ProcessSyntaxNode]

    def render_tree(self) -> str:
        """Return a readable tree view of the parsed labeled process."""
        lines = [f"Process {self.number}: {self.description}"]
        for index, node in enumerate(self.nodes):
            lines.extend(_render_node(node, "", index == len(self.nodes) - 1))
        return "\n".join(lines)

    def labeled_nodes(self) -> Iterable[ProcessSyntaxNode]:
        """Yield every labeled statement in source order."""
        pending = list(reversed(self.nodes))
        while pending:
            node = pending.pop()
            if node.label is not None:
                yield node
            pending.extend(reversed(node.children))


def extract_let_drifted_process(output: str) -> IntermediateProcess:
    """Extract the final ``let moved downwards`` process from ``proverif -test`` output.

    The returned tree is deliberately concrete: labels, indentation, and source text
    are preserved while nesting reflects ProVerif's displayed indentation.
    """
    process_blocks = _find_process_blocks(output.splitlines())
    candidates = [block for block in process_blocks if "let moved downwards" in block[1]]
    if not candidates:
        raise ValueError("ProVerif output does not contain a let-drifted process")

    number, description, source_lines = candidates[-1]
    return IntermediateProcess(
        number=number,
        description=description,
        source_lines=source_lines,
        nodes=_build_indentation_tree(source_lines),
    )


def _find_process_blocks(lines: list[str]) -> list[tuple[int, str, list[str]]]:
    blocks: list[tuple[int, str, list[str]]] = []
    index = 0
    while index < len(lines):
        match = _PROCESS_HEADER_RE.match(lines[index])
        if not match:
            index += 1
            continue

        number = int(match.group(1))
        description = match.group(2)
        index += 1
        source_lines: list[str] = []
        while index < len(lines) and not _PROCESS_END_RE.match(lines[index]):
            source_lines.append(lines[index])
            index += 1
        while source_lines and not source_lines[-1].strip():
            source_lines.pop()
        blocks.append((number, description, source_lines))
    return blocks


def _build_indentation_tree(source_lines: list[str]) -> list[ProcessSyntaxNode]:
    roots: list[ProcessSyntaxNode] = []
    stack: list[ProcessSyntaxNode] = []
    parallel_boundary = False
    else_branch = False

    for line in source_lines:
        match = _LABELED_LINE_RE.match(line)
        if not match:
            structural_text = line.strip()
            parallel_boundary = "|" in structural_text
            else_branch = structural_text == "else"
            continue

        indent = len(match.group("indent"))
        text = match.group("text").strip()
        if else_branch:
            text = f"else {text}"
        node = ProcessSyntaxNode(
            label=int(match.group("label")),
            text=text,
            indent=indent,
        )
        if else_branch:
            while stack and stack[-1].indent >= indent:
                stack.pop()
        while stack and (
            stack[-1].indent > indent
            or (
                stack[-1].indent == indent
                and (
                    parallel_boundary
                    or (
                        not stack[-1].text.rstrip().endswith(";")
                        and not _expects_continuation(stack[-1].text)
                    )
                )
            )
        ):
            stack.pop()
        if stack:
            if parallel_boundary:
                stack[-1].has_parallel_children = True
            stack[-1].children.append(node)
        else:
            roots.append(node)
        stack.append(node)
        parallel_boundary = False
        else_branch = False

    _wrap_branch_continuations(roots)
    _insert_parallel_nodes(roots)
    if len(roots) > 1 and any("|" in line for line in source_lines):
        roots = [
            ProcessSyntaxNode(label=None, text="parallel", indent=0, children=roots)
        ]
    return roots


def _insert_parallel_nodes(nodes: list[ProcessSyntaxNode]) -> None:
    for node in nodes:
        _insert_parallel_nodes(node.children)
        if node.has_parallel_children:
            parallel = ProcessSyntaxNode(label=None, text="parallel", indent=node.indent)
            parallel.children = node.children
            node.children = [parallel]


def _wrap_branch_continuations(nodes: list[ProcessSyntaxNode]) -> None:
    for node in nodes:
        _wrap_branch_continuations(node.children)
        if not node.children:
            continue
        if _has_in_continuation(node.text):
            _wrap_in_and_else_branches(node)
        elif node.text.startswith("if "):
            _wrap_if_branches(node)


def _has_in_continuation(text: str) -> bool:
    return text.startswith(("let ", "get ")) and text.rstrip().endswith(" in")


def _expects_continuation(text: str) -> bool:
    return text == "!" or _has_in_continuation(text) or text.startswith("if ")


def _wrap_in_and_else_branches(node: ProcessSyntaxNode) -> None:
    success_children, else_children = _split_on_else(node.children)
    if else_children is None:
        # No else branch: keep the "in" continuation directly under the node.
        return
    node.children = success_children + [_branch_node("else", else_children)]


def _wrap_if_branches(node: ProcessSyntaxNode) -> None:
    then_children, else_children = _split_on_else(node.children)
    branches = [_branch_node("then", then_children)]
    if else_children is not None:
        branches.append(_branch_node("else", else_children))
    node.children = branches


def _split_on_else(
    children: list[ProcessSyntaxNode],
) -> tuple[list[ProcessSyntaxNode], Optional[list[ProcessSyntaxNode]]]:
    """Split children at the first "else "-prefixed node, stripping that prefix."""
    else_index = next(
        (index for index, child in enumerate(children) if child.text.startswith("else ")),
        None,
    )
    if else_index is None:
        return children, None

    else_children = children[else_index:]
    else_children[0].text = else_children[0].text.removeprefix("else ")
    return children[:else_index], else_children


def _branch_node(name: str, children: list[ProcessSyntaxNode]) -> ProcessSyntaxNode:
    return ProcessSyntaxNode(label=None, text=name, indent=children[0].indent, children=children)


def _render_node(node: ProcessSyntaxNode, prefix: str, is_last: bool) -> list[str]:
    connector = "`-- " if is_last else "|-- "
    statement = " ".join(line.strip() for line in node.text.splitlines())
    if statement == "!":
        statement = "replication"
    label = f"{{{node.label}}} " if node.label is not None else ""
    lines = [f"{prefix}{connector}{label}{statement}"]
    child_prefix = f"{prefix}{'    ' if is_last else '|   '}"
    for index, child in enumerate(node.children):
        lines.extend(_render_node(child, child_prefix, index == len(node.children) - 1))
    return lines