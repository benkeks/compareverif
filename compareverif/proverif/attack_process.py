"""Extract attacker processes from ProVerif long attack traces."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .identifier_analysis import collect_declared_name_types
from .intermediate_process import ProcessSyntaxNode, extract_let_drifted_process
from .syntax_utils import split_top_level_commas


_QUERY_RE = re.compile(r"^-- Query (.+) in process \d+\.$")
_OUTPUT_RE = re.compile(
    r"^\d+(?:st|nd|rd|th) process: out\((?P<channel>[^,]+), (?P<variable>~M(?:_\d+)?)\) "
    r"with \2 = (?P<term>.+) done$"
)
_INPUT_RE = re.compile(
    r"^\d+(?:st|nd|rd|th) process: in\((?P<channel>[^,]+), [^)]+\) done with message (?P<term>.+?)(?: = .+)?$"
)
_ATTACKER_MESSAGE_RE = re.compile(r"^The attacker has the message (?P<term>.+) = (?P<goal>.+)\.$")
_FREE_RE = re.compile(r"^\s*free\s+(\w+)\s*:\s*(\w+)", re.MULTILINE)
_FUNCTION_RE = re.compile(r"^\s*fun\s+(\w+)\s*\(([^)]*)\)\s*:\s*(\w+)", re.MULTILINE)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
_APPLICATION_RE = re.compile(r"^(\w+)\(")


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


def extract_attack_processes(trace: str, source: str = "") -> list[AttackProcess]:
    """Return attacker processes for successful queries in a long trace.

    The function deliberately operates only on ProVerif text and does not depend
    on any target backend.  ``source`` is optional and only improves type
    inference for intercepted messages and initial fresh attacker names.
    """
    global_names, function_signatures = _parse_source_symbols(source)
    bound_name_types = _trace_bound_name_types(trace)
    processes: list[AttackProcess] = []
    current_query: str | None = None
    statements: list[str] = []
    substitutions: dict[str, str] = {}
    fresh_names: set[str] = set()
    in_attacker_knowledge = False
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
            continue

        if current_query is None:
            continue

        output_match = _OUTPUT_RE.match(line)
        if output_match:
            variable = output_match.group("variable")
            attacker_variable = "attack_" + variable[1:]
            substitutions[variable] = attacker_variable
            term = output_match.group("term")
            statements.append(
                f"in({output_match.group('channel')}, {attacker_variable}: "
                f"{_term_type(term, function_signatures)});"
            )
            continue

        input_match = _INPUT_RE.match(line)
        if input_match:
            term = _replace_attacker_terms(
                input_match.group("term"), substitutions, fresh_names
            )
            statements.append(f"out({input_match.group('channel')}, {term});")
            continue

        if line == "Additional knowledge of the attacker:":
            in_attacker_knowledge = True
            continue

        if line.startswith("---"):
            in_attacker_knowledge = False
            continue

        if (
            in_attacker_knowledge
            and _IDENTIFIER_RE.match(line)
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
                f"new attack_{name}: {_fresh_type(name, trace, function_signatures)};"
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

    return processes


def _build_process_nodes(statements: list[str]) -> tuple[ProcessSyntaxNode, ...]:
    """Build the linear attacker process as a continuation syntax tree."""
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


def _logical_lines(lines: list[str]) -> list[str]:
    """Join ProVerif's terminal-wrapped trace lines."""
    logical_lines: list[str] = []
    for line in lines:
        stripped = line.strip()
        if logical_lines and _is_wrapped_trace_line(logical_lines[-1]) and stripped:
            logical_lines[-1] += stripped
        else:
            logical_lines.append(stripped)
    return logical_lines


def _is_wrapped_trace_line(line: str) -> bool:
    if line.startswith("The attacker has the message "):
        return not line.endswith(".")
    if re.match(r"^\d+(?:st|nd|rd|th) process: out\(", line):
        return not line.endswith(" done")
    if re.match(r"^\d+(?:st|nd|rd|th) process: in\(", line):
        return " done with message " not in line
    return False


def _parse_source_symbols(source: str) -> tuple[set[str], dict[str, tuple[list[str], str]]]:
    global_names = {match.group(1) for match in _FREE_RE.finditer(source)}
    global_names.update(
        match.group(1)
        for match in re.finditer(r"^\s*channel\s+(\w+)", source, re.MULTILINE)
    )
    function_signatures = {
        match.group(1): (
            [argument.strip() for argument in match.group(2).split(",") if argument.strip()],
            match.group(3),
        )
        for match in _FUNCTION_RE.finditer(source)
    }
    return global_names, function_signatures


def _trace_bound_name_types(trace: str) -> dict[str, str]:
    try:
        process = extract_let_drifted_process(trace)
    except ValueError:
        return {}
    return collect_declared_name_types(process.nodes)


def _term_type(term: str, function_signatures: dict[str, tuple[list[str], str]]) -> str:
    match = _APPLICATION_RE.match(term)
    return function_signatures.get(match.group(1), ([], "bitstring"))[1] if match else "bitstring"


def _fresh_type(
    name: str,
    trace: str,
    function_signatures: dict[str, tuple[list[str], str]],
) -> str:
    inferred_types = _argument_type_constraints(name, trace, function_signatures)
    return inferred_types.pop() if len(inferred_types) == 1 else "bitstring"


def _argument_type_constraints(
    name: str, trace: str, function_signatures: dict[str, tuple[list[str], str]]
) -> set[str]:
    inferred_types: set[str] = set()
    for function, (argument_types, _) in function_signatures.items():
        for match in re.finditer(rf"\b{function}\(([^()]*)\)", trace):
            for index, argument in enumerate(split_top_level_commas(match.group(1))):
                if argument == name and index < len(argument_types):
                    inferred_types.add(argument_types[index])
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