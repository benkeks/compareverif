"""Shared source-level declarations for ProVerif process and target analyses."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .syntax_utils import (
    IDENTIFIER_PATTERN,
    find_matching_paren,
    split_top_level_commas,
    strip_proverif_comments,
)


_VALUE_DECLARATION_RE = re.compile(
    rf"^(free|const)\s+({IDENTIFIER_PATTERN}(?:\s*,\s*{IDENTIFIER_PATTERN})*)\s*:\s*({IDENTIFIER_PATTERN})"
)
_CALLABLE_DECLARATION_RE = re.compile(rf"^(fun|table|event)\s+({IDENTIFIER_PATTERN})\s*\(")
_SIMPLE_DECLARATION_RE = re.compile(rf"^(channel|type|event)\s+({IDENTIFIER_PATTERN}(?:\s*,\s*{IDENTIFIER_PATTERN})*)")
_RESULT_TYPE_RE = re.compile(rf"^\s*:\s*({IDENTIFIER_PATTERN})")
_ATTRIBUTES_RE = re.compile(r"^\s*\[([^]]*)\]")


@dataclass(frozen=True)
class SourceDeclaration:
    name: str
    kind: str
    type_name: str | None = None
    argument_types: tuple[str, ...] = ()
    attributes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceDeclarations:
    source: str
    symbols: dict[str, SourceDeclaration]

    @property
    def value_names(self) -> list[str]:
        return [name for name, declaration in self.symbols.items() if declaration.kind in {"free", "const"}]

    @property
    def functions(self) -> dict[str, SourceDeclaration]:
        return {name: declaration for name, declaration in self.symbols.items() if declaration.kind == "fun"}


def _declaration_statements(source: str):
    start = 0
    depth = 0
    quoted = False
    escaped = False
    for index, character in enumerate(source):
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "([":
            depth += 1
        elif character in ")]":
            depth -= 1
        elif character == "." and depth == 0:
            yield source[start:index].strip()
            start = index + 1


def _attributes(text: str) -> tuple[str, ...]:
    match = _ATTRIBUTES_RE.match(text)
    return tuple(split_top_level_commas(match.group(1))) if match else ()


def parse_source_declarations(source: str) -> SourceDeclarations:
    """Collect declarations in source order, excluding nested comments and process bindings."""
    uncommented = strip_proverif_comments(source)
    symbols: dict[str, SourceDeclaration] = {}
    for statement in _declaration_statements(uncommented):
        if match := _VALUE_DECLARATION_RE.match(statement):
            kind, names, type_name = match.groups()
            attributes = _attributes(statement[match.end():])
            for name in split_top_level_commas(names):
                symbols[name] = SourceDeclaration(name, kind, type_name, attributes=attributes)
        elif match := _CALLABLE_DECLARATION_RE.match(statement):
            kind, name = match.groups()
            open_index = match.end() - 1
            close_index = find_matching_paren(statement, open_index)
            argument_types = tuple(split_top_level_commas(statement[open_index + 1:close_index]))
            remainder = statement[close_index + 1:]
            result_type = _RESULT_TYPE_RE.match(remainder)
            type_name = result_type.group(1) if result_type else None
            if result_type:
                remainder = remainder[result_type.end():]
            symbols[name] = SourceDeclaration(name, kind, type_name, argument_types, _attributes(remainder))
        elif match := _SIMPLE_DECLARATION_RE.match(statement):
            kind, names = match.groups()
            attributes = _attributes(statement[match.end():])
            for name in split_top_level_commas(names):
                symbols[name] = SourceDeclaration(
                    name, kind, "channel" if kind == "channel" else None, attributes=attributes
                )
    return SourceDeclarations(uncommented, symbols)