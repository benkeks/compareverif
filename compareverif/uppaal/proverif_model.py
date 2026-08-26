"""Build a static UPPAAL model skeleton from a parsed ProVerif intermediate process."""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from compareverif.proverif.identifier_analysis import (
    collect_declared_names,
    declared_names_of,
    resolve_channel_usages,
)
from compareverif.proverif.intermediate_process import IntermediateProcess, ProcessSyntaxNode
from compareverif.proverif.process_structure import decompose_process
from compareverif.proverif.syntax_utils import extract_balanced_parens, split_top_level_commas

from .document import write_document

_TABLE_STATEMENT_RE = re.compile(r"^(?:insert|get)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_INSERT_STATEMENT_RE = re.compile(r"^insert\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FUNCTION_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FREE_DECLARATION_RE = re.compile(r"^\s*free\s+([^:]+)\s*:", re.MULTILINE)
_TABLE_ROW_CAPACITY = 3
_TABLE_FIELD_NAMES = ["first", "second", "third", "fourth", "fifth", "sixth"]
_FORK_CHANNEL = "_fork"
_PROCESS_KEYWORDS = {"in", "out", "insert", "get", "if", "let", "event"}


class DynamicChannelError(ValueError):
    """Raised when a channel used in in(...)/out(...) is not a static, global name."""


def collect_channel_names(process: IntermediateProcess) -> list[str]:
    """Return channel names used by in(...)/out(...) statements, in first-seen order.

    Raises DynamicChannelError if a channel resolves to a local declaration (e.g. a
    `new`-restricted name or a variable bound by `let`/`in`/`get`), since the static
    translation requires all channels to be global names.
    """
    channels: list[str] = []
    seen: set[str] = set()
    for usage in resolve_channel_usages(process):
        if usage.declaration is not None:
            raise DynamicChannelError(
                f"Channel {usage.name!r} used at {{{usage.node.label}}} is dynamically bound "
                f"by {{{usage.declaration.node.label}}} ({usage.declaration.node.text}); "
                "static translation requires global channel names."
            )
        if usage.name not in seen:
            seen.add(usage.name)
            channels.append(usage.name)
    return channels


def collect_table_arities(process: IntermediateProcess) -> dict[str, int]:
    """Return each table name used by insert/get statements mapped to its column count."""
    arities: dict[str, int] = {}
    for node in process.labeled_nodes():
        match = _TABLE_STATEMENT_RE.match(node.text)
        if not match:
            continue
        table = match.group(1)
        arguments = extract_balanced_parens(node.text, match.end() - 1)
        arity = len(split_top_level_commas(arguments))
        arities[table] = max(arity, arities.get(table, 0))
    return arities


def collect_inserted_tables(nodes: list[ProcessSyntaxNode]) -> dict[str, int]:
    """Return tables inserted by the given statements, mapped to their inserted arity."""
    tables: dict[str, int] = {}
    for node in nodes:
        match = _INSERT_STATEMENT_RE.match(node.text)
        if not match:
            continue
        arguments = extract_balanced_parens(node.text, match.end() - 1)
        tables[match.group(1)] = len(split_top_level_commas(arguments))
    return tables


def collect_value_function_arities(process: IntermediateProcess) -> dict[str, int]:
    """Return value constructors appearing in process terms, mapped to their arity."""
    functions: dict[str, int] = {}
    for node in process.labeled_nodes():
        for match in _FUNCTION_CALL_RE.finditer(node.text):
            name = match.group(1)
            if name in _PROCESS_KEYWORDS or _is_statement_head(node.text, match):
                continue
            arguments = extract_balanced_parens(node.text, match.end() - 1)
            functions[name] = max(functions.get(name, 0), len(split_top_level_commas(arguments)))
    return functions


def _is_statement_head(text: str, match: re.Match[str]) -> bool:
    """Whether a function-like token is an insert/get table or an event name."""
    prefix = text[: match.start()].strip()
    return prefix in {"insert", "get", "event"}


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


def _table_insert_function_lines(tables: dict[str, int]) -> list[str]:
    """Render bounded table insertion functions for tables written in the prefix."""
    lines: list[str] = []
    for table, arity in tables.items():
        parameters = ", ".join(f"int value{index}" for index in range(1, arity + 1))
        lines.append(f"void {table}_insert({parameters}) {{")
        lines.append(f"  if ({table}_size < {table.upper()}_CAPACITY) {{")
        for index, field in enumerate(_table_field_names(arity), start=1):
            lines.append(f"    {table}[{table}_size].{field} = value{index};")
        lines.append(f"    {table}_size++;")
        lines.append("  }")
        lines.append("}")
    return lines


def _value_function_lines(functions: dict[str, int]) -> list[str]:
    """Render uninterpreted ProVerif constructors as fresh-ID UPPAAL functions."""
    lines: list[str] = []
    for name, arity in functions.items():
        parameters = ", ".join(f"int value{index}" for index in range(1, arity + 1))
        lines.append(f"int {name}({parameters}) {{ return NEW(); }}")
    return lines


def extract_global_free_names(source: str) -> list[str]:
    """Return names declared by source-level ProVerif ``free`` declarations, in order."""
    names: list[str] = []
    seen: set[str] = set()
    for declaration in _FREE_DECLARATION_RE.finditer(source):
        for name in _IDENT_RE.findall(declaration.group(1)):
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def render_channel_skeleton(
    output_file: Path,
    process: IntermediateProcess,
    *,
    global_free_names: list[str] | None = None,
) -> list[str]:
    """Write a static UPPAAL model with one automaton for the process's linear prefix and one
    for each top-level parallel component, synchronized by a global `_fork` broadcast that the
    prefix emits once it is done. Each automaton has only two locations for now (`before`/`after`
    the fork); sub-process behavior is added in later translation steps.

    Names declared in the prefix become global variables; names declared within a component are
    declared locally in that component's automaton. Also declares channels/payload variables for
    in(...)/out(...) usages and fixed-capacity struct arrays for tables used by insert/get.

    Raises DynamicChannelError if a channel used for communication is not a global name, and
    UnsupportedProcessStructureError (from compareverif.proverif.process_structure) if the
    process is not a linear prefix followed by a single top-level parallel composition.
    """
    channels = collect_channel_names(process)
    tables = collect_table_arities(process)
    value_functions = collect_value_function_arities(process)
    decomposition = decompose_process(process)
    prefix_names = [name for node in decomposition.prefix for name in declared_names_of(node.text)]
    inserted_tables = collect_inserted_tables(decomposition.prefix)
    free_prefix_names = [name for name in (global_free_names or []) if name not in prefix_names]

    nta = ET.Element("nta")

    declaration = ET.SubElement(nta, "declaration")
    declaration_lines = ["// Channels extracted from the ProVerif process."]
    for channel in channels:
        declaration_lines.append(f"chan {channel};")
        declaration_lines.append(f"int {channel}_p;")
    if tables:
        declaration_lines.append("\n// Tables extracted from the ProVerif process.")
        declaration_lines.extend(_table_declaration_lines(tables))
    if inserted_tables:
        declaration_lines.append("\n// Insert functions for tables written by the process prefix.")
        declaration_lines.extend(_table_insert_function_lines(inserted_tables))
    declaration_lines.append("\n// Names declared in the process prefix.")
    declaration_lines.extend(f"int {name};" for name in prefix_names)
    declaration_lines.append("\n// Fresh entity identifiers and free names used by the process prefix.")
    declaration_lines.extend(f"int {name} = {i};" for i, name in enumerate(free_prefix_names, start=1))
    declaration_lines.append(f"int entity_counter = {len(free_prefix_names)};")
    declaration_lines.append("int NEW() { entity_counter++; return entity_counter; }")
    if value_functions:
        declaration_lines.append("\n// ProVerif value constructors represented as fresh entity identifiers.")
        declaration_lines.extend(_value_function_lines(value_functions))
    declaration_lines.append("\n// Signals that the prefix has finished, to the parallel components.")
    declaration_lines.append(f"broadcast chan {_FORK_CHANNEL};")
    declaration.text = "\n".join(declaration_lines) + "\n"

    _add_prefix_template(
        nta,
        decomposition.prefix,
    )

    component_names = []
    for index, component in enumerate(decomposition.components, start=1):
        name = f"Component{index}"
        component_names.append(name)
        _add_two_state_template(
            nta,
            name=name,
            synchronisation=f"{_FORK_CHANNEL}?",
            comment=_pretty_statement(component),
            local_names=collect_declared_names([component]),
        )

    system = ET.SubElement(nta, "system")
    system.text = "system " + ", ".join(["Prefix", *component_names]) + ";\n"

    queries = ET.SubElement(nta, "queries")
    query = ET.SubElement(queries, "query")
    ET.SubElement(query, "formula").text = "A[] true"
    ET.SubElement(query, "comment").text = (
        "Blank per-process skeleton: prefix and parallel components synchronized via "
        f"{_FORK_CHANNEL}."
    )

    write_document(output_file, nta)
    return channels


def _pretty_statement(node: ProcessSyntaxNode) -> str:
    """Return a short label for a statement, spelling out replication for readability."""
    return "replication" if node.text == "!" else node.text


def _add_prefix_template(nta: ET.Element, prefix: list[ProcessSyntaxNode]) -> None:
    """Add the linear prefix automaton, ending by broadcasting the fork event."""
    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = "Prefix"
    ET.SubElement(template, "declaration").text = "// No locally declared names.\n"

    location_ids = [
        "Prefix_before",
        *(f"Prefix_step_{index}" for index in range(1, len(prefix))),
        "Prefix_after",
    ]
    for index, location_id in enumerate(location_ids):
        location_y = index * 160
        location = ET.SubElement(template, "location", {"id": location_id, "x": "0", "y": str(location_y)})
        name = "before" if index == 0 else "after" if index == len(location_ids) - 1 else f"step_{index}"
        ET.SubElement(location, "name", {"x": "20", "y": str(location_y - 24)}).text = name
    ET.SubElement(template, "init", {"ref": "Prefix_before"})

    if not prefix:
        _add_transition(
            template,
            location_ids[0],
            location_ids[-1],
            synchronisation=f"{_FORK_CHANNEL}!",
            comment="Prefix complete.",
            label_x=30,
            label_y=55,
        )
        return

    for index, node in enumerate(prefix):
        _add_transition(
            template,
            location_ids[index],
            location_ids[index + 1],
            assignment=_prefix_assignment(node),
            synchronisation=f"{_FORK_CHANNEL}!" if index == len(prefix) - 1 else None,
            comment=_pretty_statement(node),
            label_x=30,
            label_y=index * 160 + 40,
        )


def _prefix_assignment(node: ProcessSyntaxNode) -> str | None:
    """Translate supported prefix statements to their UPPAAL update, ignoring other prefix steps."""
    names = declared_names_of(node.text)
    if node.text.startswith("new ") and len(names) == 1:
        return f"{names[0]} = NEW()"

    match = _INSERT_STATEMENT_RE.match(node.text)
    if match:
        arguments = extract_balanced_parens(node.text, match.end() - 1)
        return f"{match.group(1)}_insert({', '.join(split_top_level_commas(arguments))})"
    return None


def _add_transition(
    template: ET.Element,
    source: str,
    target: str,
    *,
    assignment: str | None = None,
    synchronisation: str | None = None,
    comment: str,
    label_x: int = 60,
    label_y: int = -50,
) -> None:
    """Add one transition and its optional update/synchronization labels."""
    transition = ET.SubElement(template, "transition")
    ET.SubElement(transition, "source", {"ref": source})
    ET.SubElement(transition, "target", {"ref": target})
    if assignment:
        ET.SubElement(transition, "label", {"kind": "assignment", "x": str(label_x), "y": str(label_y)}).text = assignment
    if synchronisation:
        ET.SubElement(transition, "label", {"kind": "synchronisation", "x": str(label_x), "y": str(label_y + 25)}).text = synchronisation
    ET.SubElement(transition, "label", {"kind": "comments", "x": str(label_x), "y": str(label_y + 50)}).text = comment


def _add_two_state_template(
    nta: ET.Element,
    *,
    name: str,
    synchronisation: str,
    comment: str,
    local_names: list[str] | None = None,
) -> None:
    """Add a template with just a "before"/"after" location pair joined by a fork transition."""
    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = name
    if local_names:
        declaration_text = "// Locally declared names.\n" + "\n".join(f"int {n};" for n in local_names)
    else:
        declaration_text = "// No locally declared names."
    ET.SubElement(template, "declaration").text = declaration_text + "\n"

    before_id, after_id = f"{name}_before", f"{name}_after"
    before = ET.SubElement(template, "location", {"id": before_id, "x": "0", "y": "0"})
    ET.SubElement(before, "name", {"x": "20", "y": "-24"}).text = "before"
    after = ET.SubElement(template, "location", {"id": after_id, "x": "0", "y": "160"})
    ET.SubElement(after, "name", {"x": "20", "y": "136"}).text = "after"
    ET.SubElement(template, "init", {"ref": before_id})

    _add_transition(
        template,
        before_id,
        after_id,
        synchronisation=synchronisation,
        comment=comment,
        label_x=30,
        label_y=55,
    )


