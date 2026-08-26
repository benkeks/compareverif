"""Link identifiers appearing in a ProVerif intermediate process to their declaration sites.

Declarations are recognized from typing information ProVerif prints at binding
positions (``new x: type``, ``let x: type = ...``, ``let (x: type, ...) = ...``,
``in(c, x: type)``, ``get table(x: type, ...) suchthat ...``). An identifier that
is never introduced by one of those forms is assumed to be a global name (a free
name, function, table, event, or constant declared outside the process).
"""

from __future__ import annotations

import re
from collections import ChainMap
from dataclasses import dataclass
from typing import Iterable, Optional

from .intermediate_process import IntermediateProcess, ProcessSyntaxNode
from .syntax_utils import find_matching_paren, split_top_level_commas

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_IDENT_RE = re.compile(_IDENT)
_TYPED_NAME_RE = re.compile(rf"({_IDENT})\s*:\s*{_IDENT}")
_TYPED_NAME_FULL_RE = re.compile(rf"^({_IDENT})\s*:\s*{_IDENT}$")
_NEW_RE = re.compile(rf"^new\s+({_IDENT})\s*:\s*{_IDENT}")
_KEYWORDS = {
    "in", "out", "new", "let", "get", "insert", "event", "if", "then", "else", "suchthat",
    "true", "false",
}


@dataclass(frozen=True)
class Declaration:
    """A local identifier declaration site."""

    name: str
    node: ProcessSyntaxNode


@dataclass(frozen=True)
class IdentifierUsage:
    """One identifier occurrence, linked to its declaration if it is locally bound."""

    name: str
    node: ProcessSyntaxNode
    declaration: Optional[Declaration]

    @property
    def is_global(self) -> bool:
        """Whether no local declaration was found (identifier assumed global)."""
        return self.declaration is None


def resolve_identifiers(process: IntermediateProcess) -> list[IdentifierUsage]:
    """Resolve every identifier usage in a process against its enclosing declarations."""
    usages: list[IdentifierUsage] = []
    for root in process.nodes:
        _resolve_node(root, ChainMap(), usages, None)
    return usages


def resolve_channel_usages(process: IntermediateProcess) -> list[IdentifierUsage]:
    """Resolve only the channel identifiers used by in(...)/out(...) statements."""
    channel_usages: list[IdentifierUsage] = []
    for root in process.nodes:
        _resolve_node(root, ChainMap(), None, channel_usages)
    return channel_usages


def declared_names_of(text: str) -> list[str]:
    """Return the names a single statement's text declares (empty if it declares none)."""
    declared_names, *_ = _analyze_statement(text)
    return declared_names


def collect_declared_names(nodes: Iterable[ProcessSyntaxNode]) -> list[str]:
    """Return every name declared anywhere within the given nodes' subtrees, in source order."""
    names: list[str] = []
    for node in nodes:
        _collect_declared_names(node, names)
    return names


def _collect_declared_names(node: ProcessSyntaxNode, names: list[str]) -> None:
    if node.label is not None:
        names.extend(declared_names_of(node.text))
    for child in node.children:
        _collect_declared_names(child, names)


def _resolve_node(
    node: ProcessSyntaxNode,
    scope: ChainMap,
    usages: Optional[list],
    channel_usages: Optional[list],
) -> None:
    if node.label is None:
        # Synthetic grouping node (parallel/then/else) declares nothing itself.
        for child in node.children:
            _resolve_node(child, scope, usages, channel_usages)
        return

    declared_names, usage_text, channel_name, self_scoped = _analyze_statement(node.text)

    own_scope = scope.new_child() if declared_names else scope
    for name in declared_names:
        own_scope[name] = Declaration(name=name, node=node)
    lookup_scope = own_scope if self_scoped else scope

    if usages is not None:
        for name in _referenced_identifiers(usage_text):
            usages.append(IdentifierUsage(name=name, node=node, declaration=lookup_scope.get(name)))
    if channel_usages is not None and channel_name is not None:
        channel_usages.append(
            IdentifierUsage(name=channel_name, node=node, declaration=lookup_scope.get(channel_name))
        )

    else_child = None
    other_children = node.children
    if node.children and node.children[-1].label is None and node.children[-1].text == "else":
        else_child, other_children = node.children[-1], node.children[:-1]

    for child in other_children:
        _resolve_node(child, own_scope, usages, channel_usages)
    if else_child is not None:
        _resolve_node(else_child, scope, usages, channel_usages)


def _referenced_identifiers(text: str) -> list[str]:
    return [match.group(0) for match in _IDENT_RE.finditer(text) if match.group(0) not in _KEYWORDS]


def _analyze_statement(text: str) -> tuple[list[str], str, Optional[str], bool]:
    """Return (declared_names, usage_text, channel_name, resolve_usage_with_own_declarations)."""
    stripped = text.strip()

    if stripped == "!":
        return [], "", None, False

    if stripped.startswith("new "):
        match = _NEW_RE.match(stripped)
        return ([match.group(1)], "", None, False) if match else ([], "", None, False)

    if stripped.startswith("if "):
        condition = stripped[len("if ") :].removesuffix(" then").strip()
        return [], condition, None, False

    if stripped.startswith("let "):
        names, expression = _analyze_let(stripped)
        return names, expression, None, False

    if stripped.startswith("in("):
        return _analyze_in(stripped)

    if stripped.startswith("out("):
        args_text = _args_text(stripped, stripped.index("("))
        return [], args_text, _first_arg(args_text), False

    if stripped.startswith("get "):
        return _analyze_get(stripped)

    if stripped.startswith("insert "):
        return [], _args_text(stripped, stripped.index("(")), None, False

    # event(...) and anything else: scan the whole statement for global references.
    return [], stripped, None, False


def _args_text(stripped: str, open_index: int) -> str:
    close_index = find_matching_paren(stripped, open_index)
    return stripped[open_index + 1 : close_index]


def _first_arg(args_text: str) -> Optional[str]:
    args = split_top_level_commas(args_text)
    return args[0] if args else None


def _analyze_let(stripped: str) -> tuple[list[str], str]:
    rest = stripped[len("let") :].lstrip()
    if rest.startswith("("):
        close_index = find_matching_paren(rest, 0)
        names = [match.group(1) for match in _TYPED_NAME_RE.finditer(rest[1:close_index])]
        remainder = rest[close_index + 1 :]
    else:
        match = _TYPED_NAME_RE.match(rest)
        if not match:
            return [], stripped
        names, remainder = [match.group(1)], rest[match.end() :]

    remainder = remainder.strip()
    if remainder.startswith("="):
        remainder = remainder[1:]
    return names, remainder.strip().removesuffix(" in").strip()


def _analyze_in(stripped: str) -> tuple[list[str], str, Optional[str], bool]:
    args_text = _args_text(stripped, stripped.index("("))
    args = split_top_level_commas(args_text)
    if not args:
        return [], args_text, None, False

    channel = args[0]
    pattern = ", ".join(args[1:])
    match = _TYPED_NAME_FULL_RE.match(pattern.strip())
    if match:
        return [match.group(1)], channel, channel, False
    return [], f"{channel} {pattern}".strip(), channel, False


def _analyze_get(stripped: str) -> tuple[list[str], str, Optional[str], bool]:
    match = re.match(rf"^get\s+{_IDENT}\s*\(", stripped)
    if not match:
        return [], stripped, None, False

    open_index = match.end() - 1
    close_index = find_matching_paren(stripped, open_index)
    args_text = stripped[open_index + 1 : close_index]
    names = [
        arg_match.group(1)
        for arg in split_top_level_commas(args_text)
        if (arg_match := _TYPED_NAME_FULL_RE.match(arg.strip()))
    ]

    remainder = stripped[close_index + 1 :].strip()
    if remainder.startswith("suchthat"):
        remainder = remainder[len("suchthat") :].strip()
    remainder = remainder.removesuffix(" in").strip()
    return names, remainder, None, True
