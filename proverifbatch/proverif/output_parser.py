"""Parse ProVerif console output for clauses and derivations."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set


@dataclass
class Clause:
    """Represents a ProVerif clause."""

    head: str
    body: List[str] = field(default_factory=list)
    original_text: str = ""
    clause_number: Optional[int] = None
    clause_scope: Optional[int] = None  # Query-scope identifier for this clause list
    is_initial: bool = False  # True if clause is listed under "Initial clauses:"
    capabilities: Set[str] = field(default_factory=set)  # Capabilities that introduce this clause

    def __repr__(self) -> str:
        if self.body:
            return f"{self.head} :- {', '.join(self.body)}"
        return self.head


@dataclass
class Derivation:
    """Represents a ProVerif derivation step."""

    conclusion: str
    premises: List[str] = field(default_factory=list)
    rule_name: Optional[str] = None
    indent_level: int = 0  # Track nesting depth for tree structure
    clause_number: Optional[int] = None  # Track which clause was used
    query: Optional[str] = None  # The query this derivation belongs to
    query_scope: Optional[int] = None  # Query-scope identifier for clause numbering

    def __repr__(self) -> str:
        indent = "  " * self.indent_level
        if self.premises:
            premises_str = ", ".join(self.premises)
            return f"{indent}{premises_str} => {self.conclusion}"
        return f"{indent}{self.conclusion}"


@dataclass
class ProVerifOutput:
    """Represents extracted ProVerif output."""

    clauses: List[Clause] = field(default_factory=list)
    derivations: List[Derivation] = field(default_factory=list)
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)
    query: Optional[str] = None  # The query being checked
    query_tag: Optional[str] = None  # Human-readable tag for the query


class ProVerifOutputParser:
    """Parses ProVerif output to extract clauses and derivations."""

    # Pattern to match clause lines: "Clause N: body -> head" or "Clause N: body"
    CLAUSE_LINE_PATTERN = re.compile(r"^Clause\s+(\d+):\s*(.+)$")

    # Pattern to match derivation lines (attack traces)
    DERIVATION_PATTERN = re.compile(r"^(.+?)\s*=>\s*(.+?)(?:\s*\(Rule:\s*(.+?)\))?\s*$")

    def __init__(self):
        self.output = ProVerifOutput()
        self.queries_seen = []  # Track all queries in order

    def parse(self, raw_output: str) -> ProVerifOutput:
        """
        Parse ProVerif output to extract clauses and derivations.

        Args:
            raw_output: Raw console output from ProVerif

        Returns:
            ProVerifOutput object with extracted clauses and derivations
        """
        self.output = ProVerifOutput()
        self.queries_seen = []
        self.output.raw_output = raw_output
        lines = raw_output.split("\n")

        current_section = None
        i = 0
        in_derivation_block = False
        current_query = None  # Track the most recent query for the next derivation/clauses
        current_query_scope: Optional[int] = None
        query_scope_counter = -1
        in_initial_clauses = False

        while i < len(lines):
            line = lines[i].rstrip()

            # Extract query information from "goal reachable" line (appears right before Derivation:)
            # This is more accurate than "Starting query" which may be for a different query
            if line.strip().startswith("goal reachable: "):
                goal_text = line.strip().replace("goal reachable: ", "").strip()
                current_query = goal_text
            elif line.strip().startswith("Starting query ") and not current_query:
                # Fallback to "Starting query" if we haven't seen "goal reachable" yet
                query_text = line.strip().replace("Starting query ", "").strip()
                current_query = query_text
            elif line.strip().startswith("-- Query "):
                query_text = line.strip().replace("-- Query ", "").strip()
                current_query = query_text
                query_scope_counter += 1
                current_query_scope = query_scope_counter

            # Detect start of derivation section
            if line.strip() == "Derivation:":
                # Store the query for this derivation
                if current_query and not self.output.query:
                    self.output.query = current_query

                in_derivation_block = True
                current_section = "derivations"
                i += 1
                # Collect all lines in the derivation block until we hit a section marker
                derivation_lines = []
                while i < len(lines):
                    deriv_line = lines[i].rstrip()
                    # Stop at section markers
                    if (
                        deriv_line.strip().startswith("-- Query ")
                        or
                        deriv_line.strip().startswith("Initial state")
                        or deriv_line.strip().startswith("Additional knowledge")
                        or "---" in deriv_line
                        or "RESULT" in deriv_line
                        or "Verification summary" in deriv_line
                    ):
                        break
                    if deriv_line.strip():  # Only non-empty lines
                        derivation_lines.append(deriv_line)
                    i += 1

                # Parse all collected derivation lines with the current query
                self._parse_derivation_block(
                    derivation_lines, current_query, current_query_scope
                )
                in_derivation_block = False
                continue

            # Detect section headers for clauses
            if "Initial clauses:" in line:
                in_derivation_block = False
                current_section = "clauses"
                in_initial_clauses = True
                i += 1
                continue
            if "clauses:" in line.lower():
                in_derivation_block = False
                current_section = "clauses"
                in_initial_clauses = False
                i += 1
                continue

            # Stop collecting clauses when we reach completion phase
            if "Completing..." in line or "Starting query" in line:
                current_section = None
                in_initial_clauses = False
                i += 1
                continue

            # Process clause lines (can appear anywhere before "Completing...")
            # With verboseClauses explained, completed clauses can appear after "--" markers
            match = self.CLAUSE_LINE_PATTERN.match(line)
            if match:
                clause_id = match.group(1)
                clause_content = match.group(2)
                self._parse_clause_line(
                    clause_content,
                    int(clause_id),
                    clause_scope=current_query_scope,
                    is_initial=in_initial_clauses,
                )
                i += 1
                continue

            i += 1

        return self.output

    def _parse_clause_line(
        self,
        clause_str: str,
        clause_number: Optional[int] = None,
        clause_scope: Optional[int] = None,
        is_initial: bool = False,
    ) -> None:
        """
        Parse a clause line in format: premises -> conclusion or just conclusion.

        Args:
            clause_str: The clause content (without "Clause N:" prefix)
            clause_number: The clause number from ProVerif output
            clause_scope: Query-scope identifier for this clause list
            is_initial: True if clause is listed under "Initial clauses:"
        """
        clause_str = clause_str.strip().rstrip(".")

        # Split by -> to separate premises and conclusion
        if "->" in clause_str:
            parts = clause_str.split("->")
            if len(parts) == 2:
                premises_str = parts[0].strip()
                conclusion = parts[1].strip()
                premises = [p.strip() for p in premises_str.split("&&")]
                clause = Clause(
                    head=conclusion,
                    body=premises,
                    original_text=clause_str,
                    clause_number=clause_number,
                    clause_scope=clause_scope,
                    is_initial=is_initial,
                )
            else:
                clause = Clause(
                    head=clause_str,
                    original_text=clause_str,
                    clause_number=clause_number,
                    clause_scope=clause_scope,
                    is_initial=is_initial,
                )
        else:
            clause = Clause(
                head=clause_str,
                original_text=clause_str,
                clause_number=clause_number,
                clause_scope=clause_scope,
                is_initial=is_initial,
            )

        self.output.clauses.append(clause)

    def _parse_derivation_block(
        self,
        lines: List[str],
        query: Optional[str] = None,
        query_scope: Optional[int] = None,
    ) -> None:
        """
        Parse a block of derivation lines (tree-structured with indentation from explainDerivation = false).

        Args:
            lines: List of lines from the derivation section
            query: The query this derivation block belongs to
            query_scope: Query-scope identifier for clause numbering
        """
        # Track unique queries
        if query and query not in self.queries_seen:
            self.queries_seen.append(query)

        # With explainDerivation = false, ProVerif outputs a tree-structured derivation with indentation
        for line in lines:
            # Preserve original indentation
            stripped_line = line.lstrip()
            if not stripped_line:
                continue

            # Calculate indentation level (4 spaces = 1 level)
            indent_level = (len(line) - len(stripped_line)) // 4

            # Extract goal facts (e.g., "goal  event(server_user_authenticated(user1[]))")
            if stripped_line.startswith("goal "):
                match = re.search(r"goal\s+(.+?)$", stripped_line)
                if match:
                    fact = match.group(1).strip()
                    derivation = Derivation(
                        conclusion=fact,
                        premises=[],
                        rule_name="goal",
                        indent_level=indent_level,
                        query=query,
                        query_scope=query_scope,
                    )
                    self.output.derivations.append(derivation)

            # Extract clause references (e.g., "clause 26 event(...)")
            elif stripped_line.startswith("clause "):
                match = re.search(r"clause\s+(\d+)\s+(.+?)$", stripped_line)
                if match:
                    clause_num = int(match.group(1))
                    fact = match.group(2).strip()
                    derivation = Derivation(
                        conclusion=fact,
                        premises=[],
                        rule_name="clause",
                        indent_level=indent_level,
                        clause_number=clause_num,
                        query=query,
                        query_scope=query_scope,
                    )
                    self.output.derivations.append(derivation)

            # Extract application/transformation steps (e.g., "apply 1-proj-2-tuple attacker(...)")
            elif stripped_line.startswith("apply "):
                match = re.search(r"apply\s+(\S+)\s+(.+?)$", stripped_line)
                if match:
                    operation = match.group(1)
                    fact = match.group(2).strip()
                    derivation = Derivation(
                        conclusion=fact,
                        premises=[],
                        rule_name=f"apply {operation}",
                        indent_level=indent_level,
                        query=query,
                        query_scope=query_scope,
                    )
                    self.output.derivations.append(derivation)

            # Extract duplicate operations
            elif stripped_line.startswith("duplicate "):
                match = re.search(r"duplicate\s+(.+?)$", stripped_line)
                if match:
                    fact = match.group(1).strip()
                    derivation = Derivation(
                        conclusion=fact,
                        premises=[],
                        rule_name="duplicate",
                        indent_level=indent_level,
                        query=query,
                        query_scope=query_scope,
                    )
                    self.output.derivations.append(derivation)

            # Extract initial knowledge facts
            elif stripped_line.startswith("initial knowledge "):
                match = re.search(r"initial knowledge\s+(.+?)$", stripped_line)
                if match:
                    fact = match.group(1).strip()
                    derivation = Derivation(
                        conclusion=fact,
                        premises=[],
                        rule_name="initial",
                        indent_level=indent_level,
                    )
                    self.output.derivations.append(derivation)
