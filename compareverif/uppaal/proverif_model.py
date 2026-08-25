"""Build a static UPPAAL model skeleton from a parsed ProVerif intermediate process."""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from compareverif.proverif.intermediate_process import IntermediateProcess

from .document import write_document

_CHANNEL_STATEMENT_RE = re.compile(r"^(?:in|out)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,")
_TABLE_STATEMENT_RE = re.compile(r"^(?:insert|get)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TABLE_ROW_CAPACITY = 3
_TABLE_FIELD_NAMES = ["first", "second", "third", "fourth", "fifth", "sixth"]


def collect_channel_names(process: IntermediateProcess) -> list[str]:
    """Return channel names used by in(...)/out(...) statements, in first-seen order."""
    channels: list[str] = []
    seen: set[str] = set()
    for node in process.labeled_nodes():
        match = _CHANNEL_STATEMENT_RE.match(node.text)
        if not match:
            continue
        channel = match.group(1)
        if channel not in seen:
            seen.add(channel)
            channels.append(channel)
    return channels


def collect_table_arities(process: IntermediateProcess) -> dict[str, int]:
    """Return each table name used by insert/get statements mapped to its column count."""
    arities: dict[str, int] = {}
    for node in process.labeled_nodes():
        match = _TABLE_STATEMENT_RE.match(node.text)
        if not match:
            continue
        table = match.group(1)
        arguments = _extract_balanced_parens(node.text, match.end() - 1)
        arity = len(_split_top_level_commas(arguments))
        arities[table] = max(arity, arities.get(table, 0))
    return arities


def _extract_balanced_parens(text: str, open_index: int) -> str:
    """Return the contents between the "(" at open_index and its matching ")"."""
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
    return text[open_index + 1 :]


def _split_top_level_commas(text: str) -> list[str]:
    """Split text on commas that are not nested inside parentheses."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]


def _table_field_names(arity: int) -> list[str]:
    """Return arity field names, falling back to colN once the named list is exhausted."""
    if arity <= len(_TABLE_FIELD_NAMES):
        return _TABLE_FIELD_NAMES[:arity]
    return [f"col{index}" for index in range(1, arity + 1)]


def _table_declaration_lines(tables: dict[str, int]) -> list[str]:
    """Render a fixed-capacity struct array and size counter for each table."""
    lines: list[str] = []
    for table, arity in tables.items():
        fields = ", ".join(_table_field_names(arity))
        capacity_name = f"{table.upper()}_CAPACITY"
        lines.append(f"const int {capacity_name} = {_TABLE_ROW_CAPACITY};")
        lines.append(f"struct {{ int {fields}; }} {table}[{capacity_name}];")
        lines.append(f"int {table}_size = 0;")
    return lines


def render_channel_skeleton(output_file: Path, process: IntermediateProcess) -> list[str]:
    """Write a blank UPPAAL model declaring one channel and payload variable per ProVerif channel,
    plus a fixed-capacity struct array and size counter for each table used by insert/get.

    Replicated subprocesses are ignored here (this only inspects channel/table usages), and
    payloads are represented by a single global variable per channel rather than actual
    process locations/transitions, which are added in later translation steps.
    """
    channels = collect_channel_names(process)
    tables = collect_table_arities(process)

    nta = ET.Element("nta")

    declaration = ET.SubElement(nta, "declaration")
    declaration_lines = ["// Channels extracted from the ProVerif process."]
    for channel in channels:
        declaration_lines.append(f"chan {channel};")
        declaration_lines.append(f"int {channel}_p;")
    if tables:
        declaration_lines.append("\n// Tables extracted from the ProVerif process.")
        declaration_lines.extend(_table_declaration_lines(tables))
    declaration.text = "\n".join(declaration_lines) + "\n"

    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = "AttackProgress"
    location = ET.SubElement(template, "location", {"id": "attack_progress", "x": "0", "y": "0"})
    ET.SubElement(location, "name", {"x": "0", "y": "-34"}).text = "AttackProgress"
    ET.SubElement(template, "init", {"ref": "attack_progress"})

    system = ET.SubElement(nta, "system")
    system.text = "Process = AttackProgress();\nsystem Process;\n"

    queries = ET.SubElement(nta, "queries")
    query = ET.SubElement(queries, "query")
    ET.SubElement(query, "formula").text = "A[] true"
    ET.SubElement(query, "comment").text = "Blank model skeleton with ProVerif channels and tables."

    write_document(output_file, nta)
    return channels

