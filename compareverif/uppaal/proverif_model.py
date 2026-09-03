"""Build a static UPPAAL model skeleton from a parsed ProVerif intermediate process."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping
from xml.etree import ElementTree as ET

from compareverif.proverif.identifier_analysis import (
    collect_declared_names,
    declared_names_of,
    resolve_channel_usages,
)
from compareverif.proverif.intermediate_process import IntermediateProcess, ProcessSyntaxNode
from compareverif.proverif.attack_process import AttackProcess
from compareverif.proverif.process_structure import decompose_process
from compareverif.proverif.syntax_utils import (
    extract_balanced_parens,
    find_matching_paren,
    split_top_level_commas,
)

from .document import write_document

_TABLE_STATEMENT_RE = re.compile(r"^(?:insert|get)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_INSERT_STATEMENT_RE = re.compile(r"^insert\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_FUNCTION_CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_FREE_DECLARATION_RE = re.compile(r"^\s*free\s+([^:]+)\s*:", re.MULTILINE)
_FUNCTION_DECLARATION_RE = re.compile(
    r"^\s*fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)(?:\s*:\s*[^.\[]+)?\s*(\[data\])?\s*\.",
    re.MULTILINE,
)
_GLOBAL_IDENTIFIER_RE = re.compile(
    r"^\s*(?:fun|table|event|channel)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)
_REDUCTION_RE = re.compile(r"\breduc\b")
_COMMENT_RE = re.compile(r"\(\*.*?\*\)", re.DOTALL)
_TABLE_ROW_CAPACITY = 3
_TABLE_FIELD_NAMES = ["first", "second", "third", "fourth", "fifth", "sixth"]
_FORK_CHANNEL = "_fork"
_DATA_TYPE_DECLARATION = "typedef int [-1, (1 << 31) - 1] data;"
# In --wide-data mode, `data` is four unsigned 16-bit UPPAAL ints instead of one bounded
# int, modeling 64 bits. DATA_SHL/DATA_SHR/DATA_OR/DATA_AND replace the native <<, >>, |,
# & operators used by the packing/selector functions below; DATA_FROM_INT converts a plain
# int (e.g. entity_counter, a constructor tag) into this representation.
_WIDE_DATA_PREAMBLE_LINES = [
    "typedef struct {",
    "  int[0, 65535] b0;",
    "  int[0, 65535] b16;",
    "  int[0, 65535] b32;",
    "  int[0, 65535] b48;",
    "} data;",
    "const data DATA_ZERO = {0, 0, 0, 0};",
    "const data DATA_NONE = {65535, 65535, 65535, 65535};",
    "data DATA_FROM_INT(int value) {",
    "  data result = {0, 0, 0, 0};",
    "  if (value < 0 || value >= 65535) return DATA_NONE;",
    "  result.b0 = value;",
    "  return result;",
    "}",
    "int DATA_BIT(data value, int bit) {",
    "  if (bit < 16) return (value.b0 >> bit) & 1;",
    "  if (bit < 32) return (value.b16 >> (bit - 16)) & 1;",
    "  if (bit < 48) return (value.b32 >> (bit - 32)) & 1;",
    "  return (value.b48 >> (bit - 48)) & 1;",
    "}",
    "data DATA_SET_BIT(data value, int bit) {",
    "  if (bit < 16) value.b0 = value.b0 | (1 << bit);",
    "  else if (bit < 32) value.b16 = value.b16 | (1 << (bit - 16));",
    "  else if (bit < 48) value.b32 = value.b32 | (1 << (bit - 32));",
    "  else value.b48 = value.b48 | (1 << (bit - 48));",
    "  return value;",
    "}",
    "data DATA_SHL(data value, int amount) {",
    "  data result = {0, 0, 0, 0};",
    "  int bit;",
    "  for (bit = 0; bit < 64; bit++) {",
    "    int source_bit = bit - amount;",
    "    if (source_bit >= 0 && source_bit < 64 && DATA_BIT(value, source_bit)) result = DATA_SET_BIT(result, bit);",
    "  }",
    "  return result;",
    "}",
    "data DATA_SHR(data value, int amount) {",
    "  data result = {0, 0, 0, 0};",
    "  int bit;",
    "  for (bit = 0; bit < 64; bit++) {",
    "    int source_bit = bit + amount;",
    "    if (source_bit < 64 && DATA_BIT(value, source_bit)) result = DATA_SET_BIT(result, bit);",
    "  }",
    "  return result;",
    "}",
    "data DATA_OR(data a, data b) {",
    "  data result;",
    "  result.b0 = a.b0 | b.b0;",
    "  result.b16 = a.b16 | b.b16;",
    "  result.b32 = a.b32 | b.b32;",
    "  result.b48 = a.b48 | b.b48;",
    "  return result;",
    "}",
    "data DATA_AND(data a, data b) {",
    "  data result;",
    "  result.b0 = a.b0 & b.b0;",
    "  result.b16 = a.b16 & b.b16;",
    "  result.b32 = a.b32 & b.b32;",
    "  result.b48 = a.b48 & b.b48;",
    "  return result;",
    "}",
    "data DATA_ONES_MASK(int bits) {",
    "  data result = {0, 0, 0, 0};",
    "  int bit;",
    "  for (bit = 0; bit < 64; bit++) {",
    "    if (bit < bits) result = DATA_SET_BIT(result, bit);",
    "  }",
    "  return result;",
    "}",
]


def _data_declaration_lines(wide_data: bool) -> list[str]:
    """Return the `data` typedef, plus wide-data bitwise helpers if `wide_data` is set."""
    if not wide_data:
        return [_DATA_TYPE_DECLARATION]
    return list(_WIDE_DATA_PREAMBLE_LINES)
_PROCESS_KEYWORDS = {
    "in",
    "out",
    "insert",
    "get",
    "if",
    "let",
    "event",
    "suchthat",
    "then",
    "else",
}
_PROVERIF_KEYWORDS = _PROCESS_KEYWORDS | {
    "attacker",
    "channel",
    "data",
    "event",
    "free",
    "fun",
    "private",
    "query",
    "reduc",
    "table",
    "type",
}
_EVENT_RE = re.compile(r"^event\s+([A-Za-z_][A-Za-z0-9_]*)(?:\s*\((.*)\))?$")
_GET_RE = re.compile(r"^get\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TYPED_VARIABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*:\s*[A-Za-z_][A-Za-z0-9_]*$")
_SECONDS_PATTERN_RE = re.compile(r"^seconds\s*\(\s*(\d+)\s*\)$")
_LET_SINGLE_RE = re.compile(r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=]+?=\s*(.+?)\s+in$")


class DynamicChannelError(ValueError):
    """Raised when a channel used in in(...)/out(...) is not a static, global name."""


class NestedReplicationError(ValueError):
    """Raised when a process component contains nested replication."""


class TupleDataError(ValueError):
    """Raised when a statement uses tuple data in a binding or as a function argument."""


class ComplexInputPatternError(ValueError):
    """Raised when an input statement does not bind one typed variable."""


class UnsupportedGetConditionError(ValueError):
    """Raised when a get condition is not a simple key match."""


class UnsupportedConstructorArityError(ValueError):
    """Raised when constructor packing cannot represent a declared arity."""


class ConstructorTagOverflowError(ValueError):
    """Raised when more than fifteen constructors require four-bit tags."""


class ConstructorWidthWarning(UserWarning):
    """Warn when a constructor term needs more than seven packed components."""


class GlobalNameCountWarning(UserWarning):
    """Warn when too many global names may exceed the packed data model."""


class UnsupportedSelectorRuleError(ValueError):
    """Raised when a reduction rule cannot be translated to a packed selector."""


class ReservedTranslationNameError(ValueError):
    """Raised when a source declaration uses an ALL_CAPS translation-reserved name."""


class GeneratedNameCollisionWarning(UserWarning):
    """Warn when generated UPPAAL identifiers occur in the ProVerif input."""


@dataclass(frozen=True)
class Term:
    """A variable or function application from a ProVerif reduction rule."""

    name: str
    arguments: list["Term"]


@dataclass(frozen=True)
class ReductionRule:
    """One parsed ``selector(pattern) = result`` ProVerif reduction rule."""

    selector: str
    arguments: list[Term]
    result: Term


def analyze_constructor_widths(
    process: IntermediateProcess,
    functions: ProVerifFunctions,
) -> list[tuple[int | None, int, str]]:
    """Return packed component widths for constructor terms appearing in the process."""
    widths: list[tuple[int | None, int, str]] = []
    constructors = set(functions.constructors)
    for node in process.labeled_nodes():
        for match in _FUNCTION_CALL_RE.finditer(node.text):
            if match.start() and node.text[match.start() - 1].isalnum():
                continue
            if match.group(1) in _PROCESS_KEYWORDS or _is_statement_head(node.text, match):
                continue
            close_index = find_matching_paren(node.text, match.end() - 1)
            term_text = node.text[match.start() : close_index + 1]
            term = _parse_term(term_text)
            if term.name != match.group(1) or not _term_contains_constructor(term, constructors):
                continue
            width = _constructor_term_width(term, constructors)
            if width is not None:
                widths.append((node.label, width, term_text.strip()))
    return widths


def _term_contains_constructor(term: Term, constructors: set[str]) -> bool:
    return term.name in constructors or any(
        _term_contains_constructor(argument, constructors) for argument in term.arguments
    )


def _constructor_term_width(term: Term, constructors: set[str]) -> int | None:
    if not term.arguments:
        return 1
    argument_widths = [
        _constructor_term_width(argument, constructors) or 1 for argument in term.arguments
    ]
    if term.name not in constructors:
        return max(argument_widths)
    if len(term.arguments) > 2:
        raise UnsupportedConstructorArityError(
            f"Constructor {term.name!r} has arity {len(term.arguments)}; "
            "bit packing supports at most two arguments."
        )
    return (1 if len(term.arguments) == 1 else 2) + sum(argument_widths)


@dataclass(frozen=True)
class ProVerifFunctions:
    """Source-declared constructors and selectors in declaration order."""

    constructors: list[str]
    selectors: list[str]
    arities: dict[str, int]
    rules: dict[str, ReductionRule]
    data_functions: list[str] = field(default_factory=list)


class InvalidAttackerCostInputError(ValueError):
    """Raised when an attacker cost input does not match the configured resource model."""


def _reject_tuple_data(process: IntermediateProcess) -> None:
    """Raise TupleDataError if any statement contains a tuple literal (grouped, comma-separated
    parentheses that are not a function/table/event call's argument list)."""
    for node in process.labeled_nodes():
        tuple_contents = _find_tuple_literal(node.text)
        if tuple_contents is not None:
            raise TupleDataError(
                f"Tuple data ({tuple_contents}) at {{{node.label}}} ({node.text}) is not allowed; "
                "tuples are not supported in bindings or function arguments."
            )


def _reject_complex_input_patterns(
    process: IntermediateProcess,
    time_channels: set[str],
    attacker_cost_channel: str | None = None,
    attacker_resources: set[str] | None = None,
) -> None:
    """Require each input to bind one typed variable or use a configured timing channel."""
    for node in process.labeled_nodes():
        if not node.text.startswith("in("):
            continue
        arguments = split_top_level_commas(extract_balanced_parens(node.text, node.text.index("(")))
        if len(arguments) != 2 or not (
            _TYPED_VARIABLE_RE.fullmatch(arguments[1])
            or (
                _SECONDS_PATTERN_RE.fullmatch(arguments[1])
                and arguments[0] in time_channels
            )
            or _is_attacker_cost_input(
                arguments, attacker_cost_channel, attacker_resources or set()
            )
        ):
            raise ComplexInputPatternError(
                f"Input pattern at {{{node.label}}} ({node.text}) is not allowed; "
                "an input must bind exactly one typed variable or use seconds(n)."
            )


def _is_attacker_cost_input(
    arguments: list[str], attacker_cost_channel: str | None, attacker_resources: set[str]
) -> bool:
    if len(arguments) != 2 or arguments[0] != attacker_cost_channel:
        return False
    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\((\d+)\)", arguments[1])
    if match is None:
        raise InvalidAttackerCostInputError(
            f"Attacker cost input on channel {attacker_cost_channel!r} must use resource(n)."
        )
    if match.group(1) not in attacker_resources:
        raise InvalidAttackerCostInputError(
            f"Attacker cost resource {match.group(1)!r} is not listed in attacker_resources."
        )
    return True


def _validate_attacker_resources(
    resources: Iterable[str], functions: ProVerifFunctions
) -> None:
    unknown = sorted(set(resources) - set(functions.data_functions))
    if unknown:
        raise InvalidAttackerCostInputError(
            "UPPAAL attacker_resources must name declared ProVerif [data] functions: "
            f"{', '.join(unknown)}."
        )


def _find_tuple_literal(text: str) -> str | None:
    """Return the contents of the first tuple literal found in text, or None if there is none.

    A "(...)" is treated as a tuple literal (rather than a function/table/event call's argument
    list) when the character directly preceding it is not an identifier character.
    """
    index = 0
    while True:
        paren_index = text.find("(", index)
        if paren_index == -1:
            return None
        preceding = text[paren_index - 1] if paren_index > 0 else ""
        if preceding.isalnum() or preceding == "_":
            index = paren_index + 1
            continue
        contents = extract_balanced_parens(text, paren_index)
        if len(split_top_level_commas(contents)) > 1:
            return contents
        index = paren_index + 1


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


def collect_inserted_tables(nodes: Iterable[ProcessSyntaxNode]) -> dict[str, int]:
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
            if name == "seconds" and _seconds_input(node.text, {"tick"}) is not None:
                continue
            if name in _PROCESS_KEYWORDS or _is_statement_head(node.text, match):
                continue
            arguments = extract_balanced_parens(node.text, match.end() - 1)
            functions[name] = max(functions.get(name, 0), len(split_top_level_commas(arguments)))
    return functions


def collect_event_names(process: IntermediateProcess) -> list[str]:
    """Return event names in first-seen order."""
    names: list[str] = []
    for node in process.labeled_nodes():
        if (match := _EVENT_RE.match(node.text)) and match.group(1) not in names:
            names.append(match.group(1))
    return names


def collect_timing_channels(
    process: IntermediateProcess, time_channels: set[str] | None = None
) -> set[str]:
    """Return configured channels used by seconds input annotations."""
    time_channels = time_channels or {"tick"}
    channels: set[str] = set()
    for node in process.labeled_nodes():
        if _seconds_input(node.text, time_channels) is not None:
            arguments = extract_balanced_parens(node.text, node.text.index("("))
            channels.add(split_top_level_commas(arguments)[0])
    return channels


def collect_leak_channels(process: IntermediateProcess) -> set[str]:
    """Return channels used by ``out(leak, value)`` statements."""
    channels: set[str] = set()
    for node in process.labeled_nodes():
        if not node.text.startswith("out("):
            continue
        arguments = split_top_level_commas(extract_balanced_parens(node.text, node.text.index("(")))
        if arguments and arguments[0] == "leak":
            channels.add("leak")
    return channels


def contains_replication(process: IntermediateProcess) -> bool:
    """Return whether the process contains a replication node."""
    return any(node.text == "!" for node in process.labeled_nodes())


def _is_statement_head(text: str, match: re.Match[str]) -> bool:
    """Whether a function-like token is an insert/get table or an event name."""
    prefix = text[: match.start()].strip()
    return prefix in {"insert", "get", "event"}


def _table_field_names(arity: int) -> list[str]:
    """Return arity field names, falling back to colN once the named list is exhausted."""
    if arity <= len(_TABLE_FIELD_NAMES):
        return _TABLE_FIELD_NAMES[:arity]
    return [f"col{index}" for index in range(1, arity + 1)]


def _table_declaration_lines(
    tables: dict[str, int], table_capacities: dict[str, int] | None = None
) -> list[str]:
    """Render a fixed-capacity struct array and size counter for each table."""
    lines: list[str] = []
    table_capacities = table_capacities or {}
    for table, arity in tables.items():
        fields = ", ".join(_table_field_names(arity))
        capacity_name = f"{table.upper()}_CAPACITY"
        lines.append(
            f"const int {capacity_name} = "
            f"{table_capacities.get(table, _TABLE_ROW_CAPACITY)};"
        )
        lines.append(f"struct {{ data {fields}; }} {table}[{capacity_name}];")
        lines.append(f"int {table}_size = 0;")
    return lines


def _table_insert_function_lines(tables: dict[str, int]) -> list[str]:
    """Render bounded table insertion functions for tables written in the prefix."""
    lines: list[str] = []
    for table, arity in tables.items():
        parameters = ", ".join(f"data value{index}" for index in range(1, arity + 1))
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
        parameters = ", ".join(f"data value{index}" for index in range(1, arity + 1))
        lines.append(f"data {name}({parameters}) {{ return NEW(); }}")
    return lines


def _table_getter_lines(
    getters: dict[tuple[str, tuple[str, ...]], set[int]], wide_data: bool = False
) -> list[str]:
    """Render table lookup helpers keyed by the named struct fields."""
    not_found = "DATA_NONE" if wide_data else "-1"
    lines: list[str] = []
    for (table, fields), result_indexes in getters.items():
        for result_index in result_indexes:
            suffix = f"{_table_field_names(result_index + 1)[result_index]}_by_{'_'.join(fields)}"
            parameters = ", ".join(f"data value{index}" for index in range(1, len(fields) + 1))
            lines.append(f"data {table}_get_{suffix}({parameters}) {{")
            lines.append("  int index;")
            lines.append(f"  for (index = 0; index < {table}_size; index++) {{")
            conditions = " && ".join(
                f"{table}[index].{field} == value{index}"
                for index, field in enumerate(fields, start=1)
            )
            lines.append(f"    if ({conditions}) return {table}[index].{_table_field_names(result_index + 1)[result_index]};")
            lines.append("  }")
            lines.append(f"  return {not_found};")
            lines.append("}")
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


def reject_reserved_global_names(source: str) -> None:
    """Reject ALL_CAPS source declarations because translation-generated names use that form."""
    uncommented_source = _COMMENT_RE.sub("", source)
    names = [
        name
        for declaration in _FREE_DECLARATION_RE.finditer(uncommented_source)
        for name in _IDENT_RE.findall(declaration.group(1))
    ]
    names.extend(match.group(1) for match in _GLOBAL_IDENTIFIER_RE.finditer(uncommented_source))
    reserved = sorted({name for name in names if name.upper() == name})
    if reserved:
        raise ReservedTranslationNameError(
            f"ALL_CAPS names are reserved for the UPPAAL translation: {', '.join(reserved)}."
        )


def _warn_generated_name_collisions(source: str, generated_names: set[str]) -> None:
    input_names = {
        name
        for name in _IDENT_RE.findall(_COMMENT_RE.sub("", source))
        if name not in _PROVERIF_KEYWORDS
    }
    collisions = sorted(generated_names & input_names)
    if collisions:
        warnings.warn(
            "The UPPAAL translation generates names already present in the ProVerif input: "
            f"{', '.join(collisions)}.",
            GeneratedNameCollisionWarning,
            stacklevel=3,
        )


def _generated_location_names(
    process: IntermediateProcess, time_channels: set[str]
) -> set[str]:
    """Return generated location labels that must not shadow source identifiers."""
    names = {"before", "entry", "terminated", "forked", "replication", "get_failed"}
    for node in process.labeled_nodes():
        names.add(f"step_{node.label}")
        if _seconds_input(node.text, time_channels) is not None:
            names.add(f"step_{node.label}_after")
    return names


def extract_proverif_functions(source: str) -> ProVerifFunctions:
    """Classify declared functions as constructors or reduc-rule selectors."""
    uncommented_source = _COMMENT_RE.sub("", source)
    rules = _extract_reduction_rules(uncommented_source)
    selector_matches = [(rule.selector, rule.arguments) for rule in rules]
    selectors = _ordered_unique([name for name, _ in selector_matches])
    selector_set = set(selectors)
    declared_matches = _FUNCTION_DECLARATION_RE.findall(uncommented_source)
    declared = _ordered_unique([name for name, _, _ in declared_matches])
    arities = {
        name: len(split_top_level_commas(arguments))
        for name, arguments, _ in declared_matches
    }
    arities.update({rule.selector: len(rule.arguments) for rule in rules})
    return ProVerifFunctions(
        constructors=[name for name in declared if name not in selector_set and name != "seconds"],
        selectors=[name for name in selectors if name != "seconds"],
        arities=arities,
        rules={rule.selector: rule for rule in rules if rule.selector != "seconds"},
        data_functions=[name for name, _, annotation in declared_matches if annotation],
    )


def _ordered_unique(names: list[str]) -> list[str]:
    return list(dict.fromkeys(names))


def _extract_reduction_rules(source: str) -> list[ReductionRule]:
    """Return parsed selector reduction rules from uncommented ProVerif source."""
    rules: list[ReductionRule] = []
    for reduction in _REDUCTION_RE.finditer(source):
        semicolon = source.find(";", reduction.end())
        period = source.find(".", semicolon + 1)
        if semicolon == -1 or period == -1:
            continue
        equation = source[semicolon + 1 : period].strip()
        equality = _find_top_level_equality(equation)
        if equality is None:
            continue
        left, right = equality
        selector = _parse_term(left)
        if not selector.arguments:
            continue
        rules.append(
            ReductionRule(selector.name, selector.arguments, _parse_term(right))
        )
    return rules


def _find_top_level_equality(text: str) -> tuple[str, str] | None:
    depth = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "=" and depth == 0:
            return text[:index].strip(), text[index + 1 :].strip()
    return None


def _parse_term(text: str) -> Term:
    """Parse a simple ProVerif variable or nested function application."""
    stripped = text.strip()
    match = _FUNCTION_CALL_RE.match(stripped)
    if match is None or extract_balanced_parens(stripped, match.end() - 1) != stripped[match.end() : -1]:
        return Term(stripped, [])
    arguments = extract_balanced_parens(stripped, match.end() - 1)
    return Term(match.group(1), [_parse_term(argument) for argument in split_top_level_commas(arguments)])


def _function_declaration_lines(functions: ProVerifFunctions, wide_data: bool = False) -> list[str]:
    """Render source-declared ProVerif functions and constructor identities."""
    if len(functions.constructors) > 15:
        raise ConstructorTagOverflowError(
            "Constructor bit packing supports at most fifteen datatype IDs."
        )
    lines = ["// ProVerif constructors."]
    if any(functions.arities[name] == 2 for name in functions.constructors):
        lines.extend(_pair_packing_function_lines(wide_data))
    for index, name in enumerate(functions.constructors, start=1):
        lines.append(f"const int {name.upper()} = {index};")
        lines.append(_constructor_function(name, functions.arities[name], wide_data))
    lines.append("// ProVerif selectors defined by reduc rules.")
    if functions.selectors:
        lines.extend(_selector_packing_function_lines(wide_data))
    constructor_tags = {name: index for index, name in enumerate(functions.constructors, start=1)}
    for name in functions.selectors:
        if name in functions.rules:
            lines.append(_selector_function(name, functions.rules[name], constructor_tags, wide_data))
        else:
            lines.append(_function_stub(name, functions.arities[name]))
    return lines


def _pair_packing_function_lines(wide_data: bool = False) -> list[str]:
    """Render the shared binary-constructor bit packing helper."""
    if not wide_data:
        return [
            "data BUILD_PAIR(int datatype_id, data first, data second) {",
            "  int first_width = 1;",
            "  while ((first >> (first_width * 4)) > 0) first_width++;",
            "  return datatype_id | (first_width << 4) | (first << 8) | "
            "(second << (8 + (first_width * 4)));",
            "}",
        ]
    return [
        "data BUILD_PAIR(int datatype_id, data first, data second) {",
        "  int first_width = 1;",
        "  while (DATA_SHR(first, first_width * 4) != DATA_ZERO) first_width++;",
        "  return DATA_OR(DATA_OR("
        "DATA_FROM_INT(datatype_id | (first_width << 4)), "
        "DATA_SHL(first, 8)), "
        "DATA_SHL(second, 8 + (first_width * 4)));",
        "}",
    ]


def _selector_packing_function_lines(wide_data: bool = False) -> list[str]:
    """Render helpers used to inspect packed constructor values."""
    if not wide_data:
        return [
            "int TYPE_TAG(data value) { return value & 15; }",
            "data UNWRAP(data value) { return value >> 4; }",
            "int PAIR_FIRST_WIDTH(data value) { return (value >> 4) & 15; }",
            "data PAIR_FIRST(data value) {",
            "  return (value >> 8) & ((1 << (PAIR_FIRST_WIDTH(value) * 4)) - 1);",
            "}",
            "data PAIR_SECOND(data value) {",
            "  return value >> (8 + (PAIR_FIRST_WIDTH(value) * 4));",
            "}",
        ]
    return [
        "int TYPE_TAG(data value) { return DATA_AND(value, DATA_FROM_INT(15)).b0; }",
        "data UNWRAP(data value) { return DATA_SHR(value, 4); }",
        "int PAIR_FIRST_WIDTH(data value) {",
        "  return DATA_AND(DATA_SHR(value, 4), DATA_FROM_INT(15)).b0;",
        "}",
        "data PAIR_FIRST(data value) {",
        "  return DATA_AND(DATA_SHR(value, 8), DATA_ONES_MASK(PAIR_FIRST_WIDTH(value) * 4));",
        "}",
        "data PAIR_SECOND(data value) {",
        "  return DATA_SHR(value, 8 + (PAIR_FIRST_WIDTH(value) * 4));",
        "}",
    ]


def _constructor_function(name: str, arity: int, wide_data: bool = False) -> str:
    """Render a constructor using its low four bits as a datatype ID."""
    parameters = ", ".join(f"data value{index}" for index in range(1, arity + 1))
    datatype_id = name.upper()
    if arity == 0:
        return_expr = f"DATA_FROM_INT({datatype_id})" if wide_data else datatype_id
        return f"data {name}() {{ return {return_expr}; }}"
    if arity == 1:
        if wide_data:
            return_expr = f"DATA_OR(DATA_FROM_INT({datatype_id}), DATA_SHL(value1, 4))"
        else:
            return_expr = f"{datatype_id} + (value1 << 4)"
        return f"data {name}({parameters}) {{ return {return_expr}; }}"
    if arity == 2:
        return f"data {name}({parameters}) {{ return BUILD_PAIR({datatype_id}, value1, value2); }}"
    raise UnsupportedConstructorArityError(
        f"Constructor {name!r} has arity {arity}; bit packing supports at most two arguments."
    )


def _selector_function(
    name: str,
    rule: ReductionRule,
    constructor_tags: dict[str, int],
    wide_data: bool = False,
) -> str:
    """Render a selector that checks its packed reduction pattern."""
    parameters = ", ".join(f"data value{index}" for index in range(1, len(rule.arguments) + 1))
    bindings: dict[str, str] = {}
    conditions: list[str] = []
    for index, pattern in enumerate(rule.arguments, start=1):
        _match_selector_term(pattern, f"value{index}", bindings, conditions, constructor_tags)
    result = _render_selector_result(rule.result, bindings)
    condition = " && ".join(conditions) if conditions else "true"
    not_found = "DATA_NONE" if wide_data else "-1"
    return f"data {name}({parameters}) {{ if ({condition}) return {result}; return {not_found}; }}"


def _match_selector_term(
    term: Term,
    value: str,
    bindings: dict[str, str],
    conditions: list[str],
    constructor_tags: dict[str, int],
) -> None:
    if not term.arguments:
        previous = bindings.get(term.name)
        if previous is None:
            bindings[term.name] = value
        else:
            conditions.append(f"{value} == {previous}")
        return
    if term.name not in constructor_tags:
        raise UnsupportedSelectorRuleError(
            f"Selector pattern uses unknown constructor {term.name!r}."
        )
    conditions.append(f"TYPE_TAG({value}) == {term.name.upper()}")
    if len(term.arguments) == 1:
        _match_selector_term(term.arguments[0], f"UNWRAP({value})", bindings, conditions, constructor_tags)
    elif len(term.arguments) == 2:
        _match_selector_term(term.arguments[0], f"PAIR_FIRST({value})", bindings, conditions, constructor_tags)
        _match_selector_term(term.arguments[1], f"PAIR_SECOND({value})", bindings, conditions, constructor_tags)
    else:
        raise UnsupportedSelectorRuleError(
            f"Selector pattern constructor {term.name!r} has unsupported arity {len(term.arguments)}."
        )


def _render_selector_result(term: Term, bindings: dict[str, str]) -> str:
    if not term.arguments:
        if term.name not in bindings:
            raise UnsupportedSelectorRuleError(
                f"Selector result references unbound variable {term.name!r}."
            )
        return bindings[term.name]
    return f"{term.name}({', '.join(_render_selector_result(argument, bindings) for argument in term.arguments)})"


def _function_stub(name: str, arity: int) -> str:
    parameters = ", ".join(f"data value{index}" for index in range(1, arity + 1))
    return f"data {name}({parameters}) {{ return NEW(); }}"


def render_channel_skeleton(
    output_file: Path,
    process: IntermediateProcess,
    *,
    global_free_names: list[str] | None = None,
    proverif_functions: ProVerifFunctions | None = None,
    attack_processes: list[AttackProcess] | None = None,
    input_source: str | None = None,
    non_blocking_channels: Iterable[str] = ("leak",),
    time_channels: Iterable[str] = ("tick",),
    additional_queries: Iterable[str] = (),
    table_capacities: dict[str, int] | None = None,
    attacker_resources: Mapping[str, int] | None = None,
    attacker_cost_channel: str = "cost",
    wide_data: bool = False,
) -> list[str]:
    """Write a static UPPAAL model with one automaton for the process's linear prefix and one
    for each top-level parallel component, synchronized by a global `_fork` broadcast that the
    prefix emits once it is done. Each automaton has only two locations for now (`before`/`after`
    the fork); sub-process behavior is added in later translation steps.

    Names declared in the prefix become global variables; names declared within a component are
    declared locally in that component's automaton. Also declares channels/payload variables for
    in(...)/out(...) usages and fixed-capacity struct arrays for tables used by insert/get.

    If `wide_data` is set, `data` is modeled as four native (16-bit) ints instead of one bounded
    int, and the packing/selector/NEW functions use DATA_SHL/DATA_SHR/DATA_OR/DATA_AND helpers
    instead of native shift/bitwise operators.

    Raises DynamicChannelError if a channel used for communication is not a global name, and
    UnsupportedProcessStructureError (from compareverif.proverif.process_structure) if the
    process is not a linear prefix followed by a single top-level parallel composition, and
    TupleDataError if any statement uses tuple data in a binding or as a function argument.
    """
    attack_processes = attack_processes or []
    all_process_nodes = [*process.nodes, *(attack.nodes[0] for attack in attack_processes if attack.nodes)]
    all_process = IntermediateProcess(0, "process and attacks", [], all_process_nodes)
    non_blocking_channel_names = set(non_blocking_channels)
    time_channel_names = set(time_channels)
    attacker_resource_budgets = dict(attacker_resources or {})
    attacker_resource_names = set(attacker_resource_budgets)
    _reject_tuple_data(all_process)
    _reject_complex_input_patterns(
        all_process,
        time_channel_names,
        attacker_cost_channel,
        attacker_resource_names,
    )
    channels = [
        channel
        for channel in collect_channel_names(all_process)
        if channel != attacker_cost_channel
    ]
    events = collect_event_names(all_process)
    timing_channels = collect_timing_channels(process, time_channel_names)
    tables = collect_table_arities(process)
    value_functions = {} if proverif_functions is not None else collect_value_function_arities(process)
    function_metadata = proverif_functions or ProVerifFunctions(
        constructors=list(value_functions), selectors=[], arities=value_functions, rules={}
    )
    _validate_attacker_resources(attacker_resource_names, function_metadata)
    if len(function_metadata.constructors) > 15:
        raise ConstructorTagOverflowError(
            "Constructor bit packing supports at most fifteen datatype IDs."
        )
    component_limit = 15 if wide_data else 7
    for label, width, term in analyze_constructor_widths(process, function_metadata):
        if width > component_limit:
            warnings.warn(
                f"Constructor term {term!r} at {{{label}}} requires {width} packed "
                f"components, exceeding the {component_limit}-component data limit. "
                "This will lead to undefined behavior in the UPPAAL model. "
                "Use --wide-data to support up to 15 components.",
                ConstructorWidthWarning,
                stacklevel=2,
            )
    decomposition = decompose_process(process)
    prefix_names = [name for node in decomposition.prefix for name in declared_names_of(node.text)]
    inserted_tables = collect_inserted_tables(process.labeled_nodes())
    getters = _collect_table_getters(process, tables)
    if input_source is not None:
        generated_names = {
            "data",
            "entity_counter",
            "NEW",
            _FORK_CHANNEL,
            "Prefix",
            *(f"Component{index}" for index, _ in enumerate(decomposition.components, start=1)),
            *(f"{channel}_p" for channel in channels),
            *(f"{event}_p" for event in events),
        }
        generated_names.update(_generated_location_names(all_process, time_channel_names))
        for attack_process in attack_processes:
            if not attack_process.nodes:
                continue
            attack_name = f"AttackOnQuery{attack_process.query_number}"
            generated_names.update(
                {
                    attack_name,
                    f"{attack_name}_entry",
                    f"{attack_name}_success",
                    f"{attack_name}_failed",
                    "success",
                    "failed",
                }
            )
        for table in tables:
            generated_names.update({f"{table}_size", f"{table.upper()}_CAPACITY"})
        for table in inserted_tables:
            generated_names.add(f"{table}_insert")
        for (table, fields), result_indexes in getters.items():
            for result_index in result_indexes:
                suffix = f"{_table_field_names(result_index + 1)[result_index]}_by_{'_'.join(fields)}"
                generated_names.add(f"{table}_get_{suffix}")
        _warn_generated_name_collisions(input_source, generated_names)
    free_prefix_names = [
        name
        for name in (global_free_names or [])
        if name not in prefix_names and name not in channels
    ]
    global_name_count = len(prefix_names) + len(free_prefix_names)
    if global_name_count > 15:
        warnings.warn(
            f"The translated process creates {global_name_count} global names; "
            "the packed data model may not work properly with more than 15 names.",
            GlobalNameCountWarning,
            stacklevel=2,
        )

    nta = ET.Element("nta")

    declaration = ET.SubElement(nta, "declaration")
    declaration_lines = [
        *_data_declaration_lines(wide_data),
        "\n// Channels extracted from the ProVerif process.",
    ]
    for channel in channels:
        declaration_lines.append(
            f"broadcast chan {channel};"
            if channel in non_blocking_channel_names or channel in timing_channels
            else f"chan {channel};"
        )
        declaration_lines.append(f"data {channel}_p;")
    if events:
        declaration_lines.append("\n// Events emitted by the ProVerif process.")
        for event in events:
            declaration_lines.append(f"broadcast chan {event};")
            declaration_lines.append(f"data {event}_p;")
    if tables:
        declaration_lines.append("\n// Tables extracted from the ProVerif process.")
        declaration_lines.extend(_table_declaration_lines(tables, table_capacities))
    if inserted_tables:
        declaration_lines.append("\n// Insert functions for tables written by the process prefix.")
        declaration_lines.extend(_table_insert_function_lines(inserted_tables))
    if getters:
        declaration_lines.append("\n// Table lookup functions used by get statements.")
        declaration_lines.extend(_table_getter_lines(getters, wide_data))
    declaration_lines.append("\n// Names declared in the process prefix.")
    declaration_lines.extend(f"data {name};" for name in prefix_names)
    declaration_lines.append("\n// Fresh entity identifiers and free names used by the process prefix.")
    declaration_lines.extend(
        f"data {name} = {{ {i}, 0, 0, 0 }};" if wide_data else f"data {name} = {i};"
        for i, name in enumerate(free_prefix_names, start=1)
    )
    declaration_lines.append(f"int entity_counter = {len(free_prefix_names)};")
    new_return = "DATA_FROM_INT(entity_counter)" if wide_data else "entity_counter"
    declaration_lines.append(f"data NEW() {{ entity_counter++; return {new_return}; }}")
    if proverif_functions is not None:
        declaration_lines.append("\n// Functions declared by the ProVerif source.")
        declaration_lines.extend(_function_declaration_lines(proverif_functions, wide_data))
    if value_functions:
        declaration_lines.append("\n// ProVerif value constructors represented as fresh entity identifiers.")
        declaration_lines.extend(_value_function_lines(value_functions))
    declaration_lines.append("\n// Signals that the prefix has finished, to the parallel components.")
    declaration_lines.append(f"broadcast chan {_FORK_CHANNEL};")
    declaration.text = "\n".join(declaration_lines) + "\n"

    _add_prefix_template(
        nta,
        decomposition.prefix,
        attacker_cost_channel=attacker_cost_channel,
        attacker_resources=attacker_resource_names,
    )

    component_names = []
    for index, component in enumerate(decomposition.components, start=1):
        name = f"Component{index}"
        component_names.append(name)
        _add_component_template(
            nta,
            name=name,
            component=component,
            wide_data=wide_data,
            time_channels=time_channel_names,
            attacker_cost_channel=attacker_cost_channel,
            attacker_resources=attacker_resource_budgets,
        )

    attack_names = []
    for attack_process in attack_processes:
        if not attack_process.nodes:
            continue
        name = f"AttackOnQuery{attack_process.query_number}"
        attack_names.append(name)
        _add_attack_template(
            nta,
            name=name,
            attack_process=attack_process,
            wide_data=wide_data,
            attacker_cost_channel=attacker_cost_channel,
            attacker_resources=attacker_resource_budgets,
        )

    system = ET.SubElement(nta, "system")
    system.text = "system " + ", ".join(["Prefix", *component_names, *attack_names]) + ";\n"

    queries = ET.SubElement(nta, "queries")
    for attack_process in attack_processes:
        attack_name = f"AttackOnQuery{attack_process.query_number}"
        query = ET.SubElement(queries, "query")
        ET.SubElement(query, "formula").text = f"E<> {attack_name}.success"
        ET.SubElement(query, "comment").text = (
            f"Replay ProVerif attack trace for query {attack_process.query_number}: "
            f"{attack_process.query}"
        )
    for additional_query in additional_queries:
        query = ET.SubElement(queries, "query")
        ET.SubElement(query, "formula").text = additional_query
        ET.SubElement(query, "comment").text = ""

    write_document(output_file, nta)
    return channels


def _pretty_statement(node: ProcessSyntaxNode) -> str:
    """Return a short label for a statement, spelling out replication for readability."""
    return "replication" if node.text == "!" else node.text


def _add_prefix_template(
    nta: ET.Element,
    prefix: list[ProcessSyntaxNode],
    *,
    attacker_cost_channel: str | None = None,
    attacker_resources: Mapping[str, int] | None = None,
) -> None:
    """Add the linear prefix automaton, ending by broadcasting the fork event."""
    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = "Prefix"
    ET.SubElement(template, "declaration").text = "// No locally declared names.\n"

    location_ids = [*(f"Prefix_step_{index}" for index in range(1, len(prefix) + 1)), "Prefix_terminated", "Prefix_forked"]
    for index, location_id in enumerate(location_ids):
        location_y = index * 160
        location = ET.SubElement(template, "location", {"id": location_id, "x": "0", "y": str(location_y)})
        name = "terminated" if location_id == "Prefix_terminated" else "forked" if location_id == "Prefix_forked" else f"step_{index}"
        ET.SubElement(location, "name", {"x": "20", "y": str(location_y - 24)}).text = name
    ET.SubElement(template, "init", {"ref": location_ids[0]})

    if not prefix:
        location_ids = ["Prefix_terminated", "Prefix_forked"]

    for index, node in enumerate(prefix):
        synchronisation, assignment = _statement_effect(
            node.text,
            attacker_cost_channel=attacker_cost_channel,
            attacker_resources=attacker_resources,
        )
        _add_transition(
            template,
            location_ids[index],
            location_ids[index + 1] if index + 1 < len(prefix) else "Prefix_terminated",
            assignment=assignment,
            synchronisation=synchronisation,
            comment=_pretty_statement(node),
            label_x=30,
            label_y=index * 160 + 40,
        )
    _add_transition(
        template,
        "Prefix_terminated",
        "Prefix_forked",
        synchronisation=f"{_FORK_CHANNEL}!",
        comment="Prefix complete.",
        label_x=30,
        label_y=len(prefix) * 160 + 40,
    )
    _order_template_children(template)


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
    guard: str | None = None,
    assignment: str | None = None,
    synchronisation: str | None = None,
    comment: str,
    label_x: int = 60,
    label_y: int = -50,
) -> ET.Element:
    """Add one transition and its optional update/synchronization labels."""
    transition = ET.SubElement(template, "transition")
    ET.SubElement(transition, "source", {"ref": source})
    ET.SubElement(transition, "target", {"ref": target})
    if guard:
        ET.SubElement(transition, "label", {"kind": "guard", "x": str(label_x), "y": str(label_y)}).text = guard
        label_y += 25
    if assignment:
        ET.SubElement(transition, "label", {"kind": "assignment", "x": str(label_x), "y": str(label_y)}).text = assignment
    if synchronisation:
        ET.SubElement(transition, "label", {"kind": "synchronisation", "x": str(label_x), "y": str(label_y + 25)}).text = synchronisation
    ET.SubElement(transition, "label", {"kind": "comments", "x": str(label_x), "y": str(label_y + 50)}).text = comment
    return transition


def _statement_effect(
    text: str,
    *,
    attacker_cost_channel: str | None = None,
    attacker_resources: set[str] | None = None,
) -> tuple[str | None, str | None]:
    """Return synchronization and update labels for a non-branching statement."""
    cost_action = _attacker_cost_action(
        text, attacker_cost_channel, attacker_resources or set()
    )
    if cost_action is not None:
        return (None, None)
    if text.startswith("out("):
        args = split_top_level_commas(extract_balanced_parens(text, text.index("(")))
        return (f"{args[0]}!", f"{args[0]}_p = {args[1]}" if len(args) > 1 else None)
    if text.startswith("in("):
        args = split_top_level_commas(extract_balanced_parens(text, text.index("(")))
        if _is_attacker_cost_input(args, attacker_cost_channel, attacker_resources or set()):
            return (None, None)
        name = args[1].split(":", 1)[0].strip() if len(args) > 1 else ""
        return (f"{args[0]}?", f"{name} = {args[0]}_p" if name else None)
    if (event := _EVENT_RE.match(text)):
        payload = event.group(2)
        return (f"{event.group(1)}!", f"{event.group(1)}_p = {payload}" if payload else None)
    if (match := _LET_SINGLE_RE.match(text)):
        return (None, f"{match.group(1)} = {match.group(2)}")
    return (None, _prefix_assignment(ProcessSyntaxNode(label=None, text=text, indent=0)))


def _attacker_cost_action(
    text: str, attacker_cost_channel: str | None, attacker_resources: set[str]
) -> tuple[str, str, int] | None:
    match = re.fullmatch(
        r"(in|out)\(([^,]+),\s*([A-Za-z_][A-Za-z0-9_]*)\((\d+)\)\);?",
        text,
    )
    if match is None or match.group(2).strip() != attacker_cost_channel:
        return None
    direction, resource, amount = match.group(1), match.group(3), match.group(4)
    if resource not in attacker_resources:
        raise InvalidAttackerCostInputError(
            f"Attacker cost resource {resource!r} is not listed in attacker_resources."
        )
    return direction, resource, int(amount)


def _collect_table_getters(process: IntermediateProcess, tables: dict[str, int]) -> dict[tuple[str, tuple[str, ...]], set[int]]:
    """Return each lookup shape and its selected result column index."""
    getters: dict[tuple[str, tuple[str, ...]], set[int]] = {}
    for node in process.labeled_nodes():
        if not node.text.startswith("get "):
            continue
        table, fields, _, result_indexes = _get_parts(node.text)
        if table in tables:
            getters.setdefault((table, tuple(fields)), set()).update(result_indexes)
    return getters


def _get_translation(text: str) -> list[tuple[str, str]]:
    """Return getter invocations and destination variables for a get statement."""
    table, fields, values, result_indexes = _get_parts(text)
    variables = _get_variables(text)
    return [
        (
            f"{table}_get_{_table_field_names(index + 1)[index]}_by_{'_'.join(fields)}({', '.join(values)})",
            variables[index],
        )
        for index in result_indexes
    ]


def _get_parts(text: str) -> tuple[str, list[str], list[str], list[int]]:
    match = _GET_RE.match(text)
    if not match:
        raise ValueError(f"Cannot translate get statement: {text}")
    table = match.group(1)
    arguments = split_top_level_commas(extract_balanced_parens(text, match.end() - 1))
    variables = [argument.split(":", 1)[0].strip() for argument in arguments]
    condition = text.split("suchthat", 1)[1].rsplit(" in", 1)[0] if "suchthat" in text else ""
    field_names = _table_field_names(len(arguments))
    keyed: list[tuple[str, str]] = []
    equalities = _top_level_equalities(condition)
    for equality in equalities:
        left, right = _split_top_level_equality(equality)
        if left == variables[0]:
            keyed.append((field_names[variables.index(left)], right))
        elif right == variables[0]:
            keyed.append((field_names[variables.index(right)], left))
        else:
            raise UnsupportedGetConditionError(
                f"Get condition {equality!r} in ({text}) matches beyond the first key."
            )
    if len(keyed) != len(equalities):
        raise UnsupportedGetConditionError(
            f"Get condition in ({text}) contains matching logic beyond key matching."
        )
    keyed_fields = [field for field, _ in keyed]
    result_indexes = [index for index in range(len(arguments)) if field_names[index] not in keyed_fields]
    return table, keyed_fields, [value for _, value in keyed], result_indexes


def _is_data_term(term: str) -> bool:
    return bool(_IDENT_RE.fullmatch(term)) or "(" in term


def _get_variables(text: str) -> list[str]:
    match = _GET_RE.match(text)
    return [argument.split(":", 1)[0].strip() for argument in split_top_level_commas(extract_balanced_parens(text, match.end() - 1))] if match else []


def _top_level_equalities(condition: str) -> list[str]:
    """Return equality clauses after removing only grouping parentheses."""
    normalized = _strip_grouping_parentheses(condition)
    return [_strip_grouping_parentheses(part) for part in normalized.split("&&")]


def _strip_grouping_parentheses(text: str) -> str:
    """Remove enclosing parentheses only when they wrap the full text."""
    stripped = text.strip()
    while stripped.startswith("(") and extract_balanced_parens(stripped, 0) == stripped[1:-1]:
        stripped = stripped[1:-1].strip()
    return stripped


def _split_top_level_equality(equality: str) -> tuple[str, str]:
    """Split one equality without losing nested terms on either side."""
    depth = 0
    for index, character in enumerate(equality):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "=" and depth == 0:
            return equality[:index].strip(), equality[index + 1 :].strip()
    raise ValueError(f"Cannot translate get condition equality: {equality}")


def _uppaal_condition(condition: str) -> str:
    """Translate ProVerif equality syntax to UPPAAL's equality operator."""
    return re.sub(r"(?<![=!<>])=(?!=)", "==", condition)


def _seconds_input(text: str, time_channels: set[str]) -> str | None:
    """Return the delay for an ``in(channel, seconds(delay))`` statement."""
    if not text.startswith("in("):
        return None
    arguments = split_top_level_commas(extract_balanced_parens(text, text.index("(")))
    if len(arguments) != 2:
        return None
    match = _SECONDS_PATTERN_RE.fullmatch(arguments[1])
    return match.group(1) if match and arguments[0] in time_channels else None


def _has_seconds_input(component: ProcessSyntaxNode, time_channels: set[str]) -> bool:
    """Whether a component subtree contains a timed input pattern."""
    return any(_seconds_input(node.text, time_channels) is not None for node in _walk_nodes(component))


def _walk_nodes(node: ProcessSyntaxNode):
    yield node
    for child in node.children:
        yield from _walk_nodes(child)


def _add_component_template(
    nta: ET.Element,
    *,
    name: str,
    component: ProcessSyntaxNode,
    wide_data: bool = False,
    time_channels: set[str],
    attacker_cost_channel: str | None = None,
    attacker_resources: set[str] | None = None,
) -> None:
    """Add a component automaton beginning after the prefix broadcast."""
    _reject_nested_replication(component)
    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = name
    local_names = collect_declared_names([component])
    declaration_lines = ["// Locally declared names."]
    declaration_lines.extend(f"data {local_name};" for local_name in local_names)
    if _has_seconds_input(component, time_channels):
        declaration_lines.append("clock seconds_clock;")
    if len(declaration_lines) == 1:
        declaration_text = "// No locally declared names."
    else:
        declaration_text = "\n".join(declaration_lines)
    ET.SubElement(template, "declaration").text = declaration_text + "\n"

    before_id, entry_id = f"{name}_before", f"{name}_entry"
    terminates = component.text != "!"
    terminal_id = f"{name}_terminated" if terminates else f"{name}_replication"
    before = ET.SubElement(template, "location", {"id": before_id, "x": "0", "y": "0"})
    ET.SubElement(before, "name", {"x": "20", "y": "-24"}).text = "before"
    entry = ET.SubElement(template, "location", {"id": entry_id, "x": "0", "y": "160"})
    ET.SubElement(entry, "name", {"x": "20", "y": "136"}).text = "entry"
    if terminates:
        terminated = ET.SubElement(template, "location", {"id": terminal_id, "x": "0", "y": "320"})
        ET.SubElement(terminated, "name", {"x": "20", "y": "296"}).text = "terminated"
    ET.SubElement(template, "init", {"ref": before_id})

    _add_transition(
        template,
        before_id,
        entry_id,
        synchronisation=f"{_FORK_CHANNEL}?",
        comment="Wait for prefix completion.",
        label_x=30,
        label_y=55,
    )
    builder = _ComponentBuilder(
        template,
        name,
        wide_data=wide_data,
        time_channels=time_channels,
        attacker_cost_channel=attacker_cost_channel,
        attacker_resources=attacker_resources,
    )
    builder.compile_node(component, entry_id, terminal_id)
    builder.finalize_layout(terminal_id if terminates else None)
    _order_template_children(template)


def _add_attack_template(
    nta: ET.Element,
    *,
    name: str,
    attack_process: AttackProcess,
    wide_data: bool = False,
    attacker_cost_channel: str | None = None,
    attacker_resources: set[str] | None = None,
) -> None:
    """Add an attacker process automaton that succeeds only when its final test holds."""
    component = attack_process.nodes[0]
    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = name
    local_names = collect_declared_names([component])
    declaration_lines = ["// Locally declared attacker names."]
    declaration_lines.extend(f"data {local_name};" for local_name in local_names)
    cost_resources = _attack_cost_resources(
        component, attacker_cost_channel, set(attacker_resources or {})
    )
    if cost_resources:
        declaration_lines.append("// Attacker resource counters.")
        declaration_lines.extend(
            f"int {resource} = {attacker_resources[resource]};"
            for resource in sorted(cost_resources)
        )
    ET.SubElement(template, "declaration").text = "\n".join(declaration_lines) + "\n"

    entry_id = f"{name}_entry"
    success_id, failed_id = f"{name}_success", f"{name}_failed"
    for location_id, title, y in (
        (entry_id, "entry", 0),
        (success_id, "success", 160),
        (failed_id, "failed", 160),
    ):
        location = ET.SubElement(
            template, "location", {"id": location_id, "x": "0" if title != "failed" else "260", "y": str(y)}
        )
        ET.SubElement(location, "name", {"x": "20" if title != "failed" else "280", "y": str(y - 24)}).text = title
    ET.SubElement(template, "init", {"ref": entry_id})
    builder = _ComponentBuilder(
        template,
        name,
        wide_data=wide_data,
        condition_failure_target=failed_id,
        attacker_cost_channel=attacker_cost_channel,
        attacker_resources=cost_resources,
    )
    builder.compile_node(component, entry_id, success_id)
    builder.finalize_layout(success_id)
    _order_template_children(template)


def _attack_cost_resources(
    component: ProcessSyntaxNode,
    attacker_cost_channel: str | None,
    attacker_resources: set[str],
) -> set[str]:
    return {
        action[1]
        for node in _walk_nodes(component)
        if (action := _attacker_cost_action(node.text, attacker_cost_channel, attacker_resources))
        is not None
    }


def _order_template_children(template: ET.Element) -> None:
    """Order template children according to the UPPAAL XML schema."""
    order = {"name": 0, "parameter": 1, "declaration": 2, "location": 3, "init": 4, "transition": 5}
    children = list(template)
    template[:] = [
        child
        for _, child in sorted(
            enumerate(children), key=lambda item: (order.get(item[1].tag, 99), item[0])
        )
    ]


class _ComponentBuilder:
    """Emit a small vertical UPPAAL control-flow graph from syntax-tree nodes."""

    def __init__(
        self,
        template: ET.Element,
        name: str,
        *,
        wide_data: bool = False,
        condition_failure_target: str | None = None,
        time_channels: set[str] | None = None,
        attacker_cost_channel: str | None = None,
        attacker_resources: set[str] | None = None,
    ):
        self.template = template
        self.name = name
        self.not_found = "DATA_NONE" if wide_data else "-1"
        self.location_count = 2
        self.loop_targets: set[str] = set()
        self.condition_failure_target = condition_failure_target
        self.time_channels = time_channels or set()
        self.attacker_cost_channel = attacker_cost_channel
        self.attacker_resources = attacker_resources or set()
        self.location_elements = {
            location.get("id"): location for location in template.findall("location")
        }
        self.location_y = {
            location_id: int(location.get("y", "0"))
            for location_id, location in self.location_elements.items()
        }
        self.location_x = {
            location_id: int(location.get("x", "0"))
            for location_id, location in self.location_elements.items()
        }
        self.transition_elements: list[tuple[ET.Element, str, str]] = []

    def location(self, title: str, *, urgent: bool = False, invariant: str | None = None, x: int = 0) -> str:
        location_id = f"{self.name}_node_{self.location_count}"
        y = self.location_count * 160
        location = ET.SubElement(self.template, "location", {"id": location_id, "x": str(x), "y": str(y)})
        ET.SubElement(location, "name", {"x": str(x + 20), "y": str(y - 24)}).text = title
        if invariant:
            ET.SubElement(location, "label", {"kind": "invariant", "x": "20", "y": str(y + 20)}).text = invariant
        if urgent:
            ET.SubElement(location, "urgent")
        self.location_count += 1
        self.location_y[location_id] = y
        self.location_x[location_id] = x
        self.location_elements[location_id] = location
        return location_id

    def finalize_layout(self, terminal_id: str | None) -> None:
        """Place terminal states below the process and failed lookups to their right."""
        terminal_candidates = {
            location_id
            for location_id, location in self.location_elements.items()
            if location.findtext("name") == "get_failed"
        }
        process_y = [
            y
            for location_id, y in self.location_y.items()
            if location_id not in terminal_candidates and location_id != terminal_id
        ]
        bottom_y = max(process_y, default=0) + 160
        if terminal_id is not None:
            self._move_location(terminal_id, 0, bottom_y)
            failed_x, failed_y = 260, bottom_y
        else:
            failed_x, failed_y = 260, bottom_y
        for location_id in terminal_candidates:
            self._move_location(location_id, failed_x, failed_y)
        for transition, source, target in self.transition_elements:
            source_x, source_y = self.location_x[source], self.location_y[source]
            target_x, target_y = self.location_x[target], self.location_y[target]
            self._position_transition_labels(
                transition,
                (source_x + target_x) // 2 + (20 if target_x >= source_x else -80),
                (source_y + target_y) // 2,
            )

    def _move_location(self, location_id: str, x: int, y: int) -> None:
        location = self.location_elements[location_id]
        location.set("x", str(x))
        location.set("y", str(y))
        name = location.find("name")
        if name is not None:
            name.set("x", str(x + 20))
            name.set("y", str(y - 24))
        for label in location.findall("label"):
            label.set("x", str(x + 20))
            label.set("y", str(y + 20))
        self.location_x[location_id] = x
        self.location_y[location_id] = y

    @staticmethod
    def _position_transition_labels(transition: ET.Element, x: int, y: int) -> None:
        current_y = y
        for kind in ("guard", "assignment", "synchronisation", "comments"):
            label = transition.find(f"label[@kind='{kind}']")
            if label is not None:
                label.set("x", str(x))
                label.set("y", str(current_y))
                current_y += 25 if kind != "comments" else 50

    def compile_node(
        self,
        node: ProcessSyntaxNode,
        source: str,
        target: str,
        *,
        guard: str | None = None,
        x: int = 0,
    ) -> None:
        if node.label is None:
            self.compile_children(node.children, source, target, guard=guard, x=x)
            return
        if node.text == "!":
            replication = self.location("replication", x=-260)
            self.loop_targets.add(replication)
            self.transition(source, replication, guard=guard, comment="replication")
            loop_target = replication if target == f"{self.name}_replication" else target
            self.compile_children(node.children, replication, loop_target, x=x)
            return
        if node.text.startswith("if "):
            condition = _uppaal_condition(node.text[len("if ") :].removesuffix(" then").strip())
            then_branch = next((child for child in node.children if child.text == "then"), None)
            else_branch = next((child for child in node.children if child.text == "else"), None)
            if then_branch:
                self.compile_children(then_branch.children, source, target, guard=condition, x=-260)
            elif (else_index := next((index for index, child in enumerate(node.children) if child.text.startswith("else ")), None)) is not None:
                self.compile_children(node.children[:else_index], source, target, guard=condition, x=-260)
                alternative = node.children[else_index]
                alternative.text = alternative.text.removeprefix("else ")
                self.compile_children([alternative, *node.children[else_index + 1 :]], source, target, guard=f"!({condition})", x=260)
                return
            if else_branch:
                self.compile_children(else_branch.children, source, target, guard=f"!({condition})", x=260)
            elif then_branch:
                self.transition(
                    source,
                    self.condition_failure_target or target,
                    guard=f"!({condition})",
                    comment="if condition failed",
                )
            return
        if node.text.startswith("get "):
            self.compile_get(node, source, target, guard, x=x)
            return
        if seconds := _seconds_input(node.text, self.time_channels):
            self.compile_seconds_input(node, source, target, seconds, guard, x=x)
            return

        if self.condition_failure_target is not None and (
            cost_action := _attacker_cost_action(
                node.text, self.attacker_cost_channel, self.attacker_resources
            )
        ) is not None:
            self.compile_cost_action(node, source, target, cost_action, guard, x=x)
            return

        next_location = self.location(f"step_{node.label}", x=x)
        synchronisation, assignment = _statement_effect(
            node.text,
            attacker_cost_channel=self.attacker_cost_channel,
            attacker_resources=self.attacker_resources,
        )
        self.transition(source, next_location, guard=guard, assignment=assignment, synchronisation=synchronisation, comment=_pretty_statement(node))
        if node.children:
            self.compile_children(node.children, next_location, target, x=x)
        else:
            self.transition(next_location, target, comment="continue")

    def compile_cost_action(
        self,
        node: ProcessSyntaxNode,
        source: str,
        target: str,
        cost_action: tuple[str, str, int],
        guard: str | None,
        *,
        x: int = 0,
    ) -> None:
        direction, resource, amount = cost_action
        next_location = self.location(f"step_{node.label}", x=x)
        cost_guard = f"{resource} >= {amount}" if direction == "out" else None
        if guard and cost_guard:
            cost_guard = f"({guard}) && ({cost_guard})"
        elif guard:
            cost_guard = guard
        assignment = f"{resource} {'-=' if direction == 'out' else '+='} {amount}"
        self.transition(
            source,
            next_location,
            guard=cost_guard,
            assignment=assignment,
            comment=_pretty_statement(node),
        )
        if node.children:
            self.compile_children(node.children, next_location, target, x=x)
        else:
            self.transition(next_location, target, comment="continue")

    def compile_seconds_input(
        self,
        node: ProcessSyntaxNode,
        source: str,
        target: str,
        seconds: str,
        guard: str | None,
        x: int = 0,
    ) -> None:
        channel = split_top_level_commas(extract_balanced_parens(node.text, node.text.index("(")))[0]
        wait_location = self.location(f"step_{node.label}", invariant=f"seconds_clock <= {seconds}", x=x)
        next_location = self.location(f"step_{node.label}_after", x=x) if node.children else target
        self.transition(
            source,
            wait_location,
            guard=guard,
            assignment="seconds_clock = 0",
            synchronisation=f"{channel}!",
            comment="Start timed transition.",
        )
        self.transition(
            wait_location,
            next_location,
            guard=f"seconds_clock == {seconds}",
            comment=f"Wait {seconds} seconds.",
        )
        if node.children:
            self.compile_children(node.children, next_location, target, x=x)

    def compile_children(self, children: list[ProcessSyntaxNode], source: str, target: str, *, guard: str | None = None, x: int = 0) -> None:
        if not children:
            self.transition(source, target, guard=guard, comment="continue")
            return
        self.compile_node(children[0], source, target, guard=guard, x=x)

    def compile_get(self, node: ProcessSyntaxNode, source: str, target: str, guard: str | None, *, x: int = 0) -> None:
        translations = _get_translation(node.text)
        getters = [getter for getter, _ in translations]
        success_guard = " && ".join(f"{getter} != {self.not_found}" for getter in getters)
        if guard:
            success_guard = f"({guard}) && ({success_guard})"
        next_location = self.location(f"step_{node.label}", x=x)
        assignment = ", ".join(f"{result_name} = {getter}" for getter, result_name in translations)
        self.transition(source, next_location, guard=success_guard, assignment=assignment, comment=_pretty_statement(node))
        normal_children = [child for child in node.children if child.text != "else"]
        self.compile_children(normal_children, next_location, target)
        else_branch = next((child for child in node.children if child.text == "else"), None)
        failure_target = self.location("get_failed", x=x) if else_branch is None else None
        failure_guard = " || ".join(f"{getter} == {self.not_found}" for getter in getters)
        if guard:
            failure_guard = f"({guard}) && ({failure_guard})"
        if else_branch:
            self.compile_children(else_branch.children, source, target, guard=failure_guard, x=-x if x else 260)
        else:
            self.transition(source, failure_target, guard=failure_guard, comment="get failed")
            if target in self.loop_targets:
                self.transition(failure_target, target, comment="retry after get failure")

    def transition(self, source: str, target: str, *, guard: str | None = None, assignment: str | None = None, synchronisation: str | None = None, comment: str) -> None:
        source_y = self.location_y[source]
        target_y = self.location_y[target]
        source_x = self.location_x[source]
        target_x = self.location_x[target]
        transition = _add_transition(
            self.template,
            source,
            target,
            guard=guard,
            assignment=assignment,
            synchronisation=synchronisation,
            comment=comment,
            label_x=(source_x + target_x) // 2 + (20 if target_x >= source_x else -80),
            label_y=(source_y + target_y) // 2,
        )
        self.transition_elements.append((transition, source, target))


def _reject_nested_replication(node: ProcessSyntaxNode, inside_replication: bool = False) -> None:
    replicated = node.text == "!"
    if replicated and inside_replication:
        raise NestedReplicationError("Nested replication is not supported by the UPPAAL translation.")
    for child in node.children:
        _reject_nested_replication(child, inside_replication or replicated)


