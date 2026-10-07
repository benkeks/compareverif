"""Extract attacker processes from ProVerif long attack traces."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

from .declarations import SourceDeclarations, parse_source_declarations
from .identifier_analysis import collect_declared_name_types
from .intermediate_process import ProcessSyntaxNode, extract_let_drifted_process
from .syntax_utils import (
    IDENTIFIER_PATTERN,
    IDENTIFIER_RE,
    find_matching_paren,
    split_top_level_commas,
)


_QUERY_RE = re.compile(r"^-- Query (.+) in process \d+\.$")
_OUTPUT_RE = re.compile(
    r"^\d+(?:st|nd|rd|th) process: out\((?P<channel>[^,]+), (?P<variable>~M(?:_\d+)?)\) "
    r"with \2 = (?P<term>.+) done$"
)
_INPUT_RE = re.compile(
    r"^\d+(?:st|nd|rd|th) process: in\((?P<channel>[^,]+), [^)]+\) done with message (?P<term>.+?)(?: = .+)?$"
)
_COST_ACTION_RE = re.compile(
    r"^\d+(?:st|nd|rd|th) process: (?P<direction>in|out)\("
    rf"(?P<channel>[^,]+), (?P<resource>{IDENTIFIER_PATTERN})\((?P<amount>\d+)\)\) "
    r"done(?: with message (?P=resource)\((?P=amount)\))?$"
)
_EVENT_PREFIX_RE = re.compile(
    rf"^\d+(?:st|nd|rd|th) process: event (?P<event>{IDENTIFIER_PATTERN})"
)
_ATTACKER_MESSAGE_RE = re.compile(r"^The attacker has the message (?P<term>.+) = (?P<goal>.+)\.$")
_APPLICATION_RE = re.compile(rf"^({IDENTIFIER_PATTERN})\(")
_FAILED_QUERY_RESULT_RE = re.compile(r"^RESULT .+ is false\.$")


class UntranslatedAttackWarning(UserWarning):
    """Raised when ProVerif found an attack that cannot be translated."""


@dataclass(frozen=True)
class AttackProcess:
    """A ProVerif process that mirrors one successful attacker trace."""

    query: str
    query_number: int
    nodes: tuple[ProcessSyntaxNode, ...]

    def render(self) -> str:
        """Render the process statements in ProVerif syntax."""
        return "\n".join(self.statements)

    @property
    def statements(self) -> tuple[str, ...]:
        """Return the pretty-printed statements for callers using the old API."""
        return tuple(statement for node in self.nodes for statement in _flatten_statements(node))


def extract_attack_processes(
    trace: str, source: str = "", *, attacker_cost_channel: str = "cost",
    source_declarations: SourceDeclarations | None = None,
) -> list[AttackProcess]:
    """Return attacker processes for successful queries in a long trace.

    The function deliberately operates only on ProVerif text and does not depend
    on any target backend. ``source`` supplies global names and types;
    ``source_declarations`` can supply a shared catalogue including libraries.
    """
    declarations = source_declarations or parse_source_declarations(source)
    global_names = declarations.symbols
    bound_name_types = _trace_bound_name_types(trace)
    processes: list[AttackProcess] = []
    current_query: str | None = None
    statements: list[str] = []
    substitutions: dict[str, str] = {}
    fresh_names: set[str] = set()
    in_attacker_knowledge = False
    event_input_count = 0
    query_number = 0

    for line in _logical_lines(trace.splitlines()):
        query_match = _QUERY_RE.match(line)
        if query_match:
            query_number += 1
            current_query = query_match.group(1)
            statements = []
            substitutions = {}
            fresh_names = set()
            in_attacker_knowledge = False
            event_input_count = 0
            continue

        if current_query is None:
            continue

        cost_action_match = _COST_ACTION_RE.match(line)
        if (
            cost_action_match
            and cost_action_match.group("channel") == attacker_cost_channel
        ):
            mirrored_direction = "out" if cost_action_match.group("direction") == "in" else "in"
            statements.append(
                f"{mirrored_direction}({attacker_cost_channel}, "
                f"{cost_action_match.group('resource')}({cost_action_match.group('amount')}));"
            )
            continue

        output_match = _OUTPUT_RE.match(line)
        if output_match:
            if output_match.group("channel") == attacker_cost_channel:
                cost_term = output_match.group("term")
                if re.fullmatch(rf"{IDENTIFIER_PATTERN}\(\d+\)", cost_term):
                    statements.append(f"in({attacker_cost_channel}, {cost_term});")
                    continue
            variable = output_match.group("variable")
            attacker_variable = "attack_" + variable[1:]
            substitutions[variable] = attacker_variable
            term = output_match.group("term")
            statements.append(
                f"in({output_match.group('channel')}, {attacker_variable}: "
                f"{_term_type(term, declarations)});"
            )
            continue

        input_match = _INPUT_RE.match(line)
        if input_match:
            term = _replace_attacker_terms(
                input_match.group("term"), substitutions, fresh_names
            )
            statements.append(f"out({input_match.group('channel')}, {term});")
            continue

        event_name = _trace_event_name(line)
        if event_name is not None:
            event_input_count += 1
            statements.append(
                f"in({event_name}, attack_event_{event_input_count}: bitstring);"
            )
            continue

        if line == "Additional knowledge of the attacker:":
            in_attacker_knowledge = True
            continue

        if line.startswith("---"):
            in_attacker_knowledge = False
            continue

        if (
            in_attacker_knowledge
            and IDENTIFIER_RE.fullmatch(line)
            and line not in global_names
            and line not in bound_name_types
        ):
            fresh_names.add(line)
            continue

        message_match = _ATTACKER_MESSAGE_RE.match(line)
        if message_match:
            goal = _normalise_goal(message_match.group("goal"))
            term = _replace_attacker_terms(
                message_match.group("term"), substitutions, fresh_names
            )
            fresh_statements = [
                f"new attack_{name}: {_fresh_type(name, trace, declarations)};"
                for name in sorted(fresh_names)
            ]
            success_event = f"event attack_breaks_query_{query_number}()"
            processes.append(
                AttackProcess(
                    query=current_query,
                    query_number=query_number,
                    nodes=_build_process_nodes(
                        [*fresh_statements, *statements,
                        f"if {term} = {goal} then", success_event]
                    ),
                )
            )
            current_query = None

        if current_query is not None and _FAILED_QUERY_RESULT_RE.match(line):
            if event_input_count:
                fresh_statements = [
                    f"new attack_{name}: {_fresh_type(name, trace, declarations)};"
                    for name in sorted(fresh_names)
                ]
                processes.append(
                    AttackProcess(
                        query=current_query,
                        query_number=query_number,
                        nodes=_build_process_nodes(
                            [*fresh_statements, *statements, f"event attack_breaks_query_{query_number}()"]
                        ),
                    )
                )
            else:
                warnings.warn(
                    f"Skipping unsupported ProVerif attack for query: {current_query}",
                    UntranslatedAttackWarning,
                    stacklevel=2,
                )
            current_query = None

    return processes


def _build_process_nodes(statements: list[str]) -> tuple[ProcessSyntaxNode, ...]:
    """Build the linear attacker process as a continuation syntax tree."""
    if not statements:
        return ()
    if not statements[-2].startswith("if "):
        nodes = [
            ProcessSyntaxNode(label=index, text=text, indent=0)
            for index, text in enumerate(statements, start=1)
        ]
        for node, child in zip(nodes, nodes[1:]):
            node.children = [child]
        return tuple(nodes[:1])
    nodes = [
        ProcessSyntaxNode(label=index, text=text, indent=0)
        for index, text in enumerate(statements[:-1], start=1)
    ]
    success_event = ProcessSyntaxNode(label=len(statements), text=statements[-1], indent=4)
    then_branch = ProcessSyntaxNode(label=None, text="then", indent=0, children=[success_event])
    nodes[-1].children = [then_branch]
    for node, child in zip(nodes, nodes[1:]):
        if not node.children:
            node.children = [child]
    return tuple(nodes[:1])


def _flatten_statements(node: ProcessSyntaxNode) -> list[str]:
    if node.text.startswith("if "):
        then_branch = next(child for child in node.children if child.text == "then")
        return [f"{node.text} {_flatten_statements(then_branch.children[0])[0]}"]
    if not node.children:
        return [node.text]
    return [node.text, *_flatten_statements(node.children[0])]


def _trace_event_name(line: str) -> str | None:
    """Recognize an executed event with an optional balanced argument list."""
    match = _EVENT_PREFIX_RE.match(line)
    if match is None:
        return None
    remainder = line[match.end():].strip()
    if remainder.startswith("("):
        close_index = find_matching_paren(remainder, 0)
        if remainder[close_index] != ")":
            return None
        remainder = remainder[close_index + 1:].strip()
    if re.fullmatch(r"executed(?:; it is a goal)?", remainder) is None:
        return None
    return match.group("event")


def _logical_lines(lines: list[str]) -> list[str]:
    """Join ProVerif's terminal-wrapped trace lines."""
    logical_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if logical_lines and _is_wrapped_trace_line(logical_lines[-1]) and stripped:
            event_continuation = _EVENT_PREFIX_RE.match(logical_lines[-1]) is not None
            if event_continuation and (
                stripped.startswith(("RESULT ", "-- Query ", "---"))
                or re.match(r"^\d+(?:st|nd|rd|th) process:", stripped)
            ):
                logical_lines.append(stripped)
                continue
            separator = " " if event_continuation else ""
            logical_lines[-1] += separator + stripped
        else:
            logical_lines.append(stripped)
    return logical_lines


def _is_wrapped_trace_line(line: str) -> bool:
    if _EVENT_PREFIX_RE.match(line):
        return not line.endswith((" executed", " executed; it is a goal"))
    if line.startswith("The attacker has the message "):
        return not line.endswith(".")
    if re.match(r"^\d+(?:st|nd|rd|th) process: out\(", line):
        return not line.endswith(" done")
    if re.match(r"^\d+(?:st|nd|rd|th) process: in\(", line):
        return not line.endswith(" done") and " done with message " not in line
    return False


def _trace_bound_name_types(trace: str) -> dict[str, str]:
    try:
        process = extract_let_drifted_process(trace)
    except ValueError:
        return {}
    return collect_declared_name_types(process.nodes)


def _term_type(term: str, declarations: SourceDeclarations) -> str:
    match = _APPLICATION_RE.match(term)
    name = match.group(1) if match else term.strip()
    declaration = declarations.symbols.get(name)
    return (declaration.type_name or "bitstring") if declaration else "bitstring"


def _fresh_type(
    name: str,
    trace: str,
    declarations: SourceDeclarations,
) -> str:
    inferred_types = _argument_type_constraints(name, trace, declarations)
    return inferred_types.pop() if len(inferred_types) == 1 else "bitstring"


def _argument_type_constraints(
    name: str, trace: str, declarations: SourceDeclarations
) -> set[str]:
    inferred_types: set[str] = set()
    for function, declaration in declarations.functions.items():
        for match in re.finditer(rf"\b{function}\(([^()]*)\)", trace):
            for index, argument in enumerate(split_top_level_commas(match.group(1))):
                if argument == name and index < len(declaration.argument_types):
                    inferred_types.add(declaration.argument_types[index])
    return inferred_types


def _replace_attacker_terms(
    term: str, substitutions: dict[str, str], fresh_names: set[str]
) -> str:
    for original, replacement in substitutions.items():
        term = term.replace(original, replacement)
    for name in fresh_names:
        term = re.sub(rf"\b{re.escape(name)}\b", f"attack_{name}", term)
    return term


def _normalise_goal(goal: str) -> str:
    return goal[:-2] if goal.endswith("[]") else goal