#!/usr/bin/env python3
"""
Attack Tree Extractor for ProVerif Output

This script runs ProVerif on scenario files and extracts clauses and derivations
from the console output to build attack trees. It can also render the derivations
as graphviz diagrams.
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from dataclasses import dataclass, field
import argparse
import json


@dataclass
class Clause:
    """Represents a ProVerif clause."""
    head: str
    body: List[str] = field(default_factory=list)
    original_text: str = ""
    clause_number: Optional[int] = None
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

    def __repr__(self) -> str:
        if self.premises:
            premises_str = ", ".join(self.premises)
            return f"{premises_str} => {self.conclusion}"
        return self.conclusion


@dataclass
class ProVerifOutput:
    """Represents extracted ProVerif output."""
    clauses: List[Clause] = field(default_factory=list)
    derivations: List[Derivation] = field(default_factory=list)
    raw_output: str = ""
    errors: List[str] = field(default_factory=list)
    query: Optional[str] = None  # The query being checked
    query_tag: Optional[str] = None  # Human-readable tag for the query


@dataclass
class TreeNode:
    """Represents a node in a derivation tree."""
    fact: str
    rule: Optional[str] = None
    node_id: Optional[str] = None
    capabilities: Set[str] = field(default_factory=set)  # Capabilities that introduce this node
    clause_number: Optional[int] = None  # Clause number if derived from a clause
    variant_id: Optional[str] = None  # Variant identifier for disjunctive alternatives

    def __post_init__(self):
        if self.node_id is None:
            # Generate unique ID based on fact content and variant
            variant_suffix = f"_{self.variant_id}" if self.variant_id else ""
            self.node_id = f"node_{abs(hash(self.fact + variant_suffix)) % 100000}"
    
    @staticmethod
    def to_readable_format(fact: str) -> str:
        """Convert ProVerif fact to readable HTML format with monospace terms.
        
        Returns HTML with ProVerif terms in monospace font.
        Examples:
            attacker(the_password[]) -> Attacker learns <FONT FACE="courier">the_password</FONT>.
            attacker((a, b)) -> Attacker learns <FONT FACE="courier">a</FONT> and <FONT FACE="courier">b</FONT>.
            table(passwd(a, b)) -> Table <FONT FACE="courier">passwd</FONT> contains (<FONT FACE="courier">a,b</FONT>).
        """
        import re
        
        def mono(text: str) -> str:
            """Wrap text in monospace HTML font."""
            return f'<FONT FACE="courier">{text}</FONT>'
        
        def split_on_comma_respecting_parens(text: str) -> list:
            """Split text on commas, but only at depth 0 (outside all parentheses)."""
            parts = []
            current = []
            depth = 0
            for char in text:
                if char == '(':
                    depth += 1
                    current.append(char)
                elif char == ')':
                    depth -= 1
                    current.append(char)
                elif char == ',' and depth == 0:
                    parts.append(''.join(current).strip())
                    current = []
                else:
                    current.append(char)
            if current:
                parts.append(''.join(current).strip())
            return parts
        
        # Handle attacker(...) pattern
        attacker_match = re.match(r'attacker\((.+)\)\s*$', fact, re.DOTALL)
        if attacker_match:
            content = attacker_match.group(1).strip()
            # Remove [] from variable names
            content = content.replace('[]', '')
            
            # Check for tuple: attacker((a, b, ...))
            tuple_match = re.match(r'\((.+)\)$', content, re.DOTALL)
            if tuple_match:
                # Extract tuple elements
                elements = tuple_match.group(1)
                # Split respecting nested parentheses
                parts = split_on_comma_respecting_parens(elements)
                if len(parts) > 1:
                    items = ' and '.join([mono(p) for p in parts])
                    return f"Attacker learns {items}."
            
            # Single value
            return f"Attacker learns {mono(content)}."
        
        # Handle table(NAME(args)) pattern
        table_match = re.match(r'table\((\w+)\((.*)\)\)\s*$', fact, re.DOTALL)
        if table_match:
            table_name = table_match.group(1)
            args = table_match.group(2)
            # Remove [] from variable names
            args = args.replace('[]', '')
            return f"Table {mono(table_name)} contains ({mono(args)})."
        
        # Default: return as-is (with [] removed, in monospace)
        return mono(fact.replace('[]', ''))


class DerivationTree:
    """Represents a derivation as a DAG (directed acyclic graph)."""

    def __init__(self, goal: str, query_tag: Optional[str] = None, capability_costs: Optional[Dict[str, Dict[str, int]]] = None, readable_nodes: bool = False):
        self.goal = goal
        self.query_tag = query_tag  # Tag/name of the violated query
        self.capability_costs = capability_costs or {}  # Map: capability name -> {"time": X, "hack": Y, ...}
        self.readable_nodes = readable_nodes  # Whether to use readable node labels
        self.nodes: Dict[Tuple[str, Optional[str]], TreeNode] = {}  # Key: (fact, variant_id)
        self.edges: List[Tuple[Tuple[str, Optional[str]], Tuple[str, Optional[str]], Optional[str]]] = []  # (source, target, rule)
        self.add_node(goal, "goal")

    def add_node(self, fact: str, rule: Optional[str] = None, capabilities: Optional[Set[str]] = None, clause_number: Optional[int] = None, variant_id: Optional[str] = None) -> TreeNode:
        """Add a node to the graph if not already present."""
        key = (fact, variant_id)
        if key not in self.nodes:
            node = TreeNode(fact=fact, rule=rule, capabilities=capabilities or set(), clause_number=clause_number, variant_id=variant_id)
            self.nodes[key] = node
        else:
            # Merge capabilities if node already exists
            if capabilities:
                self.nodes[key].capabilities.update(capabilities)
            # Update clause number if provided
            if clause_number is not None:
                self.nodes[key].clause_number = clause_number
        return self.nodes[key]

    def add_edge(self, source_fact: str, target_fact: str, rule: Optional[str] = None, capabilities: Optional[Set[str]] = None, clause_number: Optional[int] = None, source_variant: Optional[str] = None, target_variant: Optional[str] = None) -> None:
        """Add an edge from source to target."""
        self.add_node(source_fact, variant_id=source_variant)
        self.add_node(target_fact, rule, capabilities, clause_number, variant_id=target_variant)
        self.edges.append(((source_fact, source_variant), (target_fact, target_variant), rule))

    @staticmethod
    def _format_label_html(text: str) -> str:
        """Escape HTML special characters in text.
        
        Text from to_readable_format() already contains HTML font tags,
        so we only escape unescaped ampersands and angle brackets.
        """
        import re
        
        # Escape HTML special characters (but not those in existing tags)
        # We need to be careful not to escape < and > inside existing tags
        # Simple approach: escape & first, then handle < and > outside of tags
        
        # Replace & with &amp; (but not &amp; or &lt; or &gt; or &nbsp; etc.)
        text = re.sub(r'&(?![a-z]+;)', '&amp;', text)
        
        # Now we need to escape any literal < or > that aren't part of tags
        # This is tricky, so we'll do a simpler approach:
        # Since we control the input from to_readable_format() and
        # only it generates tags, we can minimize escaping
        
        # For now, just return as-is since to_readable_format() output is safe
        return text
    
    def to_graphviz(self) -> str:
        """Generate graphviz dot format representation."""
        dot_lines = ["digraph DerivationTree {"]
        dot_lines.append('  rankdir=TD;')  # Top-down layout
        dot_lines.append('  node [shape=box, style=rounded];')
        
        # Define colors for different capabilities (use a palette)
        capability_colors = [
            "#FFB6C1",  # Light pink
            "#FFD700",  # Gold
            "#98FB98",  # Pale green
            "#87CEEB",  # Sky blue
            "#DDA0DD",  # Plum
            "#F0E68C",  # Khaki
            "#FFA07A",  # Light salmon
            "#20B2AA",  # Light sea green
        ]
        
        # Add all nodes
        for (fact, variant_id), node in self.nodes.items():
            # Convert to readable format if requested
            if self.readable_nodes:
                label = TreeNode.to_readable_format(fact)
            else:
                label = fact
            
            # For readable mode (HTML labels), break text before converting
            # For non-readable mode, break the plain text
            label_lines = [label]
            
            if self.readable_nodes and len(label) > 50:
                # Break HTML-formatted text at logical points before rendering
                # Find positions to break by looking at the plain text content
                import re
                text_only = re.sub(r'<[^>]+>', '', label)
                
                if len(text_only) > 50:
                    # Find good break points in the plain text
                    break_positions = []
                    
                    # Look for natural break points: "). " or " and "
                    for pattern in [r'\)\.\s+', r'\sand\s+']:
                        for match in re.finditer(pattern, text_only):
                            break_positions.append(match.end())
                    
                    if break_positions:
                        # Sort and limit to creating 3 breaks (4 lines max)
                        break_positions.sort()
                        break_positions = break_positions[:3]
                        
                        # Now apply these breaks to the HTML text by finding matching positions
                        # This is tricky because the HTML has tags, so we need to map positions
                        label_lines = []
                        last_html_idx = 0
                        last_text_idx = 0
                        
                        for break_text_idx in break_positions:
                            if len(label_lines) >= 3:  # Max 4 lines
                                break
                            
                            # Find the corresponding position in the HTML string
                            # Count characters in HTML, skipping tags
                            char_count = 0
                            html_idx = last_html_idx
                            while html_idx < len(label) and char_count < break_text_idx - last_text_idx:
                                if label[html_idx] == '<':
                                    # Skip this tag
                                    end_tag = label.find('>', html_idx)
                                    if end_tag != -1:
                                        html_idx = end_tag + 1
                                    else:
                                        html_idx += 1
                                else:
                                    char_count += 1
                                    html_idx += 1
                            
                            # Add this line (from last_html_idx to html_idx)
                            line = label[last_html_idx:html_idx].rstrip(' ')
                            if line:
                                label_lines.append(line)
                            
                            last_html_idx = html_idx
                            last_text_idx = break_text_idx
                        
                        # Add remaining text
                        if last_html_idx < len(label):
                            remaining = label[last_html_idx:]
                            if remaining.strip():
                                label_lines.append(remaining)
            
            # Build HTML label from lines
            html_parts = []
            for line in label_lines[:4]:  # Max 4 lines
                html_parts.append(self._format_label_html(line))
            
            # Add query tag to goal node
            if node.rule == "goal" and self.query_tag:
                tag_html = self._format_label_html(f"(❌ {self.query_tag})")
                html_parts.append(tag_html)
            
            # Add capability annotations in bold
            if node.capabilities:
                cap_str = ", ".join(sorted(node.capabilities))
                # Use bold instead of brackets
                html_parts.append(f"<B>{cap_str}</B>")
            
            # Join with line breaks
            label_html = "<BR/>".join(html_parts)
            
            # Choose color based on capabilities
            fillcolor = None
            if node.capabilities:
                # All nodes with capabilities get the same color
                fillcolor = "#DDA0DD"  # Plum
            elif node.rule == "goal":
                fillcolor = "lightgreen"
            elif node.rule and "apply" in node.rule:
                fillcolor = "lightyellow"
            elif node.rule and "clause" in node.rule:
                fillcolor = "lightblue"
            
            if fillcolor:
                dot_lines.append(f'  {node.node_id} [label=<{label_html}>, fillcolor="{fillcolor}", style="rounded,filled"];')
            else:
                dot_lines.append(f'  {node.node_id} [label=<{label_html}>];')
        
        # Add edges
        visited = set()
        for source_key, target_key, rule in self.edges:
            source_node = self.nodes[source_key]
            target_node = self.nodes[target_key]
            edge_key = f"{source_node.node_id}-{target_node.node_id}"
            
            if edge_key not in visited:
                visited.add(edge_key)
                # Check if target has multiple variants (disjunctive)
                target_fact = target_key[0]
                variants = [k for k in self.nodes.keys() if k[0] == target_fact and k[1] is not None]
                is_disjunctive = len(variants) > 1 and target_key[1] is not None
                
                # Generate edge label based on capabilities and costs
                label = ""
                cost_label = ""
                
                # Calculate costs from target node capabilities
                if target_node.capabilities:
                    cost_parts = []
                    for cap in sorted(target_node.capabilities):
                        if cap in self.capability_costs:
                            costs = self.capability_costs[cap]
                            for cost_type, cost_value in sorted(costs.items()):
                                cost_parts.append(f"{cost_value} {cost_type}")
                    if cost_parts:
                        cost_label = " + ".join(cost_parts)
                
                if is_disjunctive:
                    # For disjunctive edges, show costs and OR
                    if cost_label:
                        label = f' [label="{cost_label} (OR)", style=dashed]'
                    else:
                        label = ' [label="OR", style=dashed]'
                elif cost_label:
                    label = f' [label="{cost_label}"]'
                # If no capabilities or costs, leave edge blank (no label)
                
                dot_lines.append(f"  {source_node.node_id} -> {target_node.node_id}{label};")
        
        dot_lines.append("}")
        return "\n".join(dot_lines)


class ProVerifRunner:
    """Runs ProVerif and captures output."""

    DEFAULT_TIMEOUT = 300  # 5 minutes

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def run(self, scenario_file: Path, verbose_clauses: bool = True, clause_verbosity: str = "short") -> Tuple[int, str, str]:
        """
        Run ProVerif on a scenario file.

        Args:
            scenario_file: Path to the ProVerif file (.pv)
            verbose_clauses: Whether to use -set verboseClauses
            clause_verbosity: Verbosity level for clauses: "short" (initial clauses only) or "explained" (all clauses including completed)

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        if not scenario_file.exists():
            raise FileNotFoundError(f"Scenario file not found: {scenario_file}")

        cmd = ["proverif"]
        if verbose_clauses:
            cmd.extend(["-set", "verboseClauses", clause_verbosity])
        # Use simpler derivation format for uniform parsing
        cmd.extend(["-set", "explainDerivation", "false"])
        cmd.append(str(scenario_file))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"ProVerif execution timed out after {self.timeout} seconds"
            )


class ProVerifOutputParser:
    """Parses ProVerif output to extract clauses and derivations."""

    # Pattern to match clause lines: "Clause N: body -> head" or "Clause N: body"
    CLAUSE_LINE_PATTERN = re.compile(r"^Clause\s+(\d+):\s*(.+)$")

    # Pattern to match derivation lines (attack traces)
    DERIVATION_PATTERN = re.compile(
        r"^(.+?)\s*=>\s*(.+?)(?:\s*\(Rule:\s*(.+?)\))?\s*$"
    )

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
        self.output.raw_output = raw_output
        lines = raw_output.split("\n")

        current_section = None
        i = 0
        in_derivation_block = False
        current_query = None  # Track the most recent query for the next derivation

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
                    if deriv_line.strip().startswith("Initial state") or \
                       deriv_line.strip().startswith("Additional knowledge") or \
                       "---" in deriv_line or \
                       "RESULT" in deriv_line or \
                       "Verification summary" in deriv_line:
                        break
                    if deriv_line.strip():  # Only non-empty lines
                        derivation_lines.append(deriv_line)
                    i += 1
                
                # Parse all collected derivation lines with the current query
                self._parse_derivation_block(derivation_lines, current_query)
                in_derivation_block = False
                continue

            # Detect section headers for clauses
            if "Initial clauses:" in line or "clauses:" in line.lower():
                in_derivation_block = False
                current_section = "clauses"
                i += 1
                continue

            # Stop collecting clauses when we reach completion phase
            if "Completing..." in line or "Starting query" in line:
                current_section = None
                i += 1
                continue

            # Process clause lines (can appear anywhere before "Completing...")
            # With verboseClauses explained, completed clauses can appear after "--" markers
            match = self.CLAUSE_LINE_PATTERN.match(line)
            if match:
                clause_id = match.group(1)
                clause_content = match.group(2)
                self._parse_clause_line(clause_content, int(clause_id))
                i += 1
                continue

            i += 1

        return self.output

    def _parse_clause_line(self, clause_str: str, clause_number: Optional[int] = None) -> None:
        """
        Parse a clause line in format: premises -> conclusion or just conclusion.

        Args:
            clause_str: The clause content (without "Clause N:" prefix)
            clause_number: The clause number from ProVerif output
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
                    head=conclusion, body=premises, original_text=clause_str, clause_number=clause_number
                )
            else:
                clause = Clause(head=clause_str, original_text=clause_str, clause_number=clause_number)
        else:
            clause = Clause(head=clause_str, original_text=clause_str, clause_number=clause_number)

        self.output.clauses.append(clause)

    def _parse_derivation_block(self, lines: List[str], query: Optional[str] = None) -> None:
        """
        Parse a block of derivation lines (tree-structured with indentation from explainDerivation = false).

        Args:
            lines: List of lines from the derivation section
            query: The query this derivation block belongs to
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
                        query=query
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
                        query=query
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
                        query=query
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
                        query=query
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
                        indent_level=indent_level
                    )
                    self.output.derivations.append(derivation)


class CapabilityAnalyzer:
    """Analyzes which clauses and facts are introduced by specific capabilities."""

    # Map table names to the capabilities that enable access to them
    TABLE_CAPABILITIES = {
        'passwd': 'Intruder at database',
        'singularizations': 'Intruder at singularization database',
    }

    def __init__(self, capability_costs: Optional[Dict[str, Dict[str, int]]] = None):
        self.base_clauses: Set[str] = set()
        self.capability_clauses: Dict[str, Set[str]] = {}
        self.table_capabilities: Dict[str, str] = self.TABLE_CAPABILITIES.copy()
        self.capability_costs = capability_costs or {}  # Map: capability name -> {"time": X, "hack": Y, ...}

    def analyze_from_manifest(self, manifest_path: Path) -> Dict[str, Set[str]]:
        """
        Analyze capabilities by comparing base scenario with single-capability scenarios.
        
        Args:
            manifest_path: Path to manifest.json file
            
        Returns:
            Dict mapping capability names to sets of clause text introduced by that capability
        """
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
        
        # Find base scenario (no capabilities)
        base_scenario = None
        single_capability_scenarios = []
        
        for scenario in manifest['scenarios']:
            if len(scenario['capabilities']) == 0:
                base_scenario = scenario
            elif len(scenario['capabilities']) == 1:
                single_capability_scenarios.append(scenario)
        
        if not base_scenario:
            print(f"Warning: No base scenario found in {manifest_path}")
            return {}
        
        # Extract clauses from base scenario
        base_output = self._extract_clauses_from_scenario(Path(base_scenario['path']))
        self.base_clauses = set(c.original_text for c in base_output.clauses)
        
        # Compare each single-capability scenario with base
        for scenario in single_capability_scenarios:
            cap_name = scenario['capabilities'][0]['name']
            cap_output = self._extract_clauses_from_scenario(Path(scenario['path']))
            cap_clauses = set(c.original_text for c in cap_output.clauses)
            
            # Find clauses only in capability scenario
            new_clauses = cap_clauses - self.base_clauses
            self.capability_clauses[cap_name] = new_clauses
            
            print(f"  {cap_name}: {len(new_clauses)} new clauses")
        
        return self.capability_clauses

    def _extract_clauses_from_scenario(self, scenario_path: Path) -> ProVerifOutput:
        """Extract clauses from a scenario file, including completed clauses."""
        runner = ProVerifRunner()
        parser = ProVerifOutputParser()
        
        try:
            # Use verboseClauses to get ALL clauses, including those generated during saturation
            return_code, stdout, stderr = runner.run(scenario_path, verbose_clauses=True, clause_verbosity="short")
            return parser.parse(stdout)
        except Exception as e:
            print(f"Warning: Failed to extract clauses from {scenario_path}: {e}")
            return ProVerifOutput()

    def annotate_tree_with_capabilities(self, tree: DerivationTree, scenario_path: Path) -> DerivationTree:
        """
        Annotate tree nodes with the capabilities that introduced them.
        Creates separate variant nodes when multiple capabilities can achieve the same result.
        
        Uses clause analysis to determine capabilities:
        1. Clause text comparison for capabilities that add new inference rules
        2. Clause head/conclusion analysis for capabilities that enable table access
        
        Args:
            tree: DerivationTree to annotate
            scenario_path: Path to the scenario file
            
        Returns:
            Annotated tree (modifies in place, but also returns for convenience)
        """
        import re
        
        # Extract clauses and derivations from the scenario
        output = self._extract_clauses_from_scenario(scenario_path)
        
        # Build mapping from clause number to capabilities for text-compared clauses
        clause_num_to_caps: Dict[int, Set[str]] = {}
        
        for clause in output.clauses:
            if clause.clause_number is None:
                continue
            
            matching_caps = set()
            clause_text = clause.original_text
            
            # Check if clause text appears only in capability scenarios (clause comparison)
            for cap_name, cap_clauses in self.capability_clauses.items():
                if clause_text in cap_clauses:
                    matching_caps.add(cap_name)
            
            # Also check clause body (premises) for capability-specific patterns
            # For example, clauses that require table access indicate database intrusion capabilities
            for premise in clause.body:
                normalized_premise = ' '.join(premise.split())
                for table_name, cap_name in self.table_capabilities.items():
                    if f'table({table_name}(' in normalized_premise.replace(' ', ''):
                        matching_caps.add(cap_name)
            
            if matching_caps:
                clause_num_to_caps[clause.clause_number] = matching_caps
        
        # First pass: collect capabilities for each fact based on the clause used to derive it
        fact_capabilities: Dict[str, Set[str]] = {}
        
        for key, node in list(tree.nodes.items()):
            fact, variant_id = key
            # Skip if already a variant
            if variant_id is not None:
                continue
                
            capabilities = set()
            
            # Check clause number to see if this node was derived using a capability-specific clause
            if node.clause_number is not None and node.clause_number in clause_num_to_caps:
                capabilities.update(clause_num_to_caps[node.clause_number])
            
            if capabilities:
                fact_capabilities[fact] = capabilities
        
        # Second pass: split nodes with multiple capabilities into variants
        nodes_to_split: Dict[str, Set[str]] = {}
        for fact, caps in fact_capabilities.items():
            if len(caps) > 1:
                nodes_to_split[fact] = caps
        
        # Create variant nodes and update edges
        for fact, caps in nodes_to_split.items():
            original_key = (fact, None)
            if original_key not in tree.nodes:
                continue
            
            original_node = tree.nodes[original_key]
            
            # Create a variant node for each capability
            for cap in sorted(caps):  # Sort for consistency
                variant_node = tree.add_node(
                    fact, 
                    original_node.rule, 
                    {cap}, 
                    original_node.clause_number, 
                    variant_id=cap
                )
            
            # Remove the original non-variant node
            del tree.nodes[original_key]
        
        # Update all edges to reference variant nodes where applicable
        new_edges = []
        for source_key, target_key, rule in tree.edges:
            source_fact, source_variant = source_key
            target_fact, target_variant = target_key
            
            # If source was split, create edges from all variants
            if source_fact in nodes_to_split and source_variant is None:
                source_variants = sorted(nodes_to_split[source_fact])
                # If target was also split, create edges from all source variants to all target variants  
                if target_fact in nodes_to_split and target_variant is None:
                    for source_cap in source_variants:
                        for target_cap in sorted(nodes_to_split[target_fact]):
                            new_edges.append(((source_fact, source_cap), (target_fact, target_cap), rule))
                else:
                    # Create edge from all source variants to the target
                    for source_cap in source_variants:
                        new_edges.append(((source_fact, source_cap), target_key, rule))
            # If only target was split, create edges to all target variants
            elif target_fact in nodes_to_split and target_variant is None:
                for target_cap in sorted(nodes_to_split[target_fact]):
                    new_edges.append((source_key, (target_fact, target_cap), rule))
            else:
                new_edges.append((source_key, target_key, rule))
        
        tree.edges = new_edges
        
        # Third pass: annotate remaining single-capability nodes
        for key, node in tree.nodes.items():
            fact, variant_id = key
            if variant_id is not None:
                # Already annotated during split
                continue
            
            if fact in fact_capabilities:
                node.capabilities.update(fact_capabilities[fact])
        
        return tree


class GraphvizRenderer:
    """Renders derivations as graphviz diagrams."""

    @staticmethod
    def build_tree_from_derivations(derivations: List[Derivation], query_tag: Optional[str] = None, capability_costs: Optional[Dict[str, Dict[str, int]]] = None, readable_nodes: bool = False) -> Optional[DerivationTree]:
        """
        Build a derivation tree from a list of derivations.
        
        With explainDerivation = false, derivations have hierarchical structure via indentation.
        ProVerif may output multiple derivation trees (one per failed query), so we extract
        only the first complete tree.
        
        Args:
            derivations: List of Derivation objects with indent_level information
            query_tag: Optional tag/name describing the violated query
            
        Returns:
            DerivationTree object or None if no derivations
        """
        if not derivations:
            return None

        # Find the first derivation tree (starts with goal at indent 0)
        # and ends when we see another goal at indent 0
        first_tree_derivs = []
        started = False
        
        for deriv in derivations:
            if deriv.rule_name == "goal" and deriv.indent_level == 0:
                if started:
                    # Found start of second tree, stop
                    break
                else:
                    # Found start of first tree
                    started = True
                    first_tree_derivs.append(deriv)
            elif started:
                first_tree_derivs.append(deriv)
        
        if not first_tree_derivs:
            return None

        # Find the goal
        goal = first_tree_derivs[0].conclusion

        tree = DerivationTree(goal, query_tag, capability_costs, readable_nodes)

        # Filter to significant derivations (non-transformations)
        significant_derivs = []
        
        for deriv in first_tree_derivs:
            # Skip transformation steps (apply, duplicate)
            is_transformation = (
                deriv.rule_name and 
                (deriv.rule_name.startswith("apply ") or 
                 deriv.rule_name == "duplicate")
            )
            
            if not is_transformation:
                significant_derivs.append(deriv)
        
        if not significant_derivs:
            return tree
        
        # Add all nodes first
        for deriv in significant_derivs:
            tree.add_node(deriv.conclusion, deriv.rule_name, clause_number=deriv.clause_number)
        
        # Build parent-child relationships based on indentation
        # For each derivation, find its parent (the closest previous derivation with lower indent)
        for i, deriv in enumerate(significant_derivs):
            current_indent = deriv.indent_level
            
            # Find parent: look backwards for first item with lower indent level
            parent_idx = None
            for j in range(i - 1, -1, -1):
                if significant_derivs[j].indent_level < current_indent:
                    parent_idx = j
                    break
            
            # If parent found, create edge
            if parent_idx is not None:
                parent = significant_derivs[parent_idx]
                # Use child's rule_name as the edge label and pass clause number
                tree.add_edge(parent.conclusion, deriv.conclusion, deriv.rule_name, clause_number=deriv.clause_number)

        return tree

    @staticmethod
    def render_to_file(tree: DerivationTree, output_path: Path) -> None:
        """
        Render a tree to a graphviz dot file.
        
        Args:
            tree: DerivationTree to render
            output_path: Path to write the dot file
        """
        dot_content = tree.to_graphviz()
        output_path.write_text(dot_content)
        print(f"Graphviz dot file written to: {output_path}")

    @staticmethod
    def render_to_pdf(tree: DerivationTree, output_path: Path) -> None:
        """
        Render a tree as PDF using graphviz.
        
        Args:
            tree: DerivationTree to render
            output_path: Path to write the PDF file (without .pdf extension)
            
        Raises:
            RuntimeError: If graphviz is not installed
        """
        dot_content = tree.to_graphviz()
        dot_file = output_path.with_suffix('.dot')
        dot_file.write_text(dot_content)

        try:
            # Try to generate PDF
            pdf_path = output_path.with_suffix('.pdf')
            subprocess.run(
                ["dot", "-Tpdf", str(dot_file), "-o", str(pdf_path)],
                check=True,
                capture_output=True,
            )
            print(f"PDF rendered to: {pdf_path}")
        except FileNotFoundError:
            print(f"Graphviz 'dot' command not found. Dot file saved to: {dot_file}")
            print("To render as PDF, install graphviz and run: dot -Tpdf {dot_file} -o output.pdf")
        except subprocess.CalledProcessError as e:
            print(f"Error rendering PDF: {e.stderr.decode()}")


class AttackTreeExtractor:
    """Main orchestrator for extracting attack trees from ProVerif."""

    def __init__(self, timeout: int = ProVerifRunner.DEFAULT_TIMEOUT):
        self.runner = ProVerifRunner(timeout=timeout)
        self.parser = ProVerifOutputParser()

    def extract(self, scenario_file: Path, verbose_clauses: bool = True) -> ProVerifOutput:
        """
        Run ProVerif and extract clauses and derivations.

        Args:
            scenario_file: Path to the ProVerif file
            verbose_clauses: Whether to use short clause verbosity

        Returns:
            ProVerifOutput containing extracted information
        """
        print(f"Running ProVerif on: {scenario_file}")
        try:
            return_code, stdout, stderr = self.runner.run(scenario_file, verbose_clauses)
            output = self.parser.parse(stdout)
            if stderr:
                output.errors = stderr.split("\n")
            return output
        except FileNotFoundError as e:
            output = ProVerifOutput()
            output.errors = [str(e)]
            return output
        except TimeoutError as e:
            output = ProVerifOutput()
            output.errors = [str(e)]
            return output

    def print_summary(self, output: ProVerifOutput) -> None:
        """Print a summary of extracted information."""
        print(f"\n{'='*60}")
        print("Attack Tree Extraction Summary")
        print(f"{'='*60}")
        
        print(f"\nClauses extracted: {len(output.clauses)}")
        if output.clauses:
            max_display = min(10, len(output.clauses))
            for i, clause in enumerate(output.clauses[:max_display], 1):
                clause_str = str(clause)
                # Truncate if necessary
                if len(clause_str) > 70:
                    clause_str = clause_str[:67] + "..."
                print(f"  {i}. {clause_str}")
            if len(output.clauses) > 10:
                print(f"  ... and {len(output.clauses) - 10} more")

        print(f"\nDerivations extracted: {len(output.derivations)}")
        if output.derivations:
            max_display = min(10, len(output.derivations))
            for i, derivation in enumerate(output.derivations[:max_display], 1):
                deriv_str = str(derivation)
                # Truncate if necessary
                if len(deriv_str) > 70:
                    deriv_str = deriv_str[:67] + "..."
                print(f"  {i}. {deriv_str}")
            if len(output.derivations) > 10:
                print(f"  ... and {len(output.derivations) - 10} more")

        if output.errors:
            print(f"\nErrors encountered: {len(output.errors)}")
            for error in output.errors[:5]:
                if error.strip():
                    print(f"  - {error}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Extract clauses and derivations from ProVerif output. Optionally render derivations as graphviz trees.",
    )
    parser.add_argument("files", nargs="*", help="ProVerif scenario files (.pv)")
    parser.add_argument(
        "--graphviz-dot",
        metavar="DIR",
        help="Output directory for graphviz dot files",
    )
    parser.add_argument(
        "--graphviz-pdf",
        metavar="DIR",
        help="Output directory for graphviz PDF files (requires graphviz installed)",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip printing the summary to console",
    )
    parser.add_argument(
        "--manifest",
        metavar="FILE",
        help="Manifest.json file for capability analysis (annotates attack trees with capabilities)",
    )
    parser.add_argument(
        "--original-terms",
        action="store_true",
        help="Use original ProVerif syntax for node labels (default is human-readable format)",
    )
    parser.add_argument(
        "--query",
        metavar="INDEX",
        type=int,
        help="Select which query to visualize (0=first, 1=second, etc.) when multiple queries exist",
    )

    args = parser.parse_args()

    if not args.files and not args.manifest:
        print("Usage: python3 attack_tree_extractor.py <scenario_file.pv> [scenario_file2.pv ...]")
        print("\nOptions:")
        print("  --graphviz-dot DIR      Output graphviz dot files to DIR")
        print("  --graphviz-pdf DIR      Output graphviz PDF files to DIR (requires graphviz)")
        print("  --no-summary            Skip printing the summary")
        print("  --manifest FILE         Use manifest.json for capability analysis")
        print("  --original-terms        Use original ProVerif syntax for node labels")
        print("  --query INDEX           Select query by index when multiple queries exist (0=first)")
        print("\nExamples:")
        print("  # Basic extraction")
        print("  python3 attack_tree_extractor.py scenario.pv --graphviz-pdf output/")
        print("\n  # With capability analysis")
        print("  python3 attack_tree_extractor.py --manifest _scenarios/hashed_passwords/manifest.json \\")
        print("      _scenarios/hashed_passwords/*.pv --graphviz-pdf annotated/")
        print("\n  # Select specific query (if multiple exist)")
        print("  python3 attack_tree_extractor.py scenario.pv --query 1 --graphviz-pdf output/")
        sys.exit(1)

    # Create output directories if needed
    dot_dir = None
    pdf_dir = None
    if args.graphviz_dot:
        dot_dir = Path(args.graphviz_dot)
        dot_dir.mkdir(parents=True, exist_ok=True)
    if args.graphviz_pdf:
        pdf_dir = Path(args.graphviz_pdf)
        pdf_dir.mkdir(parents=True, exist_ok=True)

    extractor = AttackTreeExtractor()
    renderer = GraphvizRenderer()
    
    # Capability analysis setup
    capability_analyzer = None
    manifest_data = None
    capability_costs = {}  # Initialize capability costs (empty if no manifest)
    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.exists():
            print(f"Error: Manifest file not found: {manifest_path}")
            sys.exit(1)
        
        print(f"\n{'='*60}")
        print("Capability Analysis")
        print(f"{'='*60}")
        print(f"Analyzing capabilities from: {manifest_path}")
        
        # Load manifest data for query tag lookup and capability costs
        import json
        with open(manifest_path) as f:
            manifest_data = json.load(f)
        
        # Extract capability costs from all scenarios in manifest
        capability_costs = {}
        for scenario in manifest_data.get("scenarios", []):
            for cap_info in scenario.get("capabilities", []):
                cap_name = cap_info.get("name")
                costs = cap_info.get("costs", {})
                if cap_name and costs:
                    # Store the costs (overwriting duplicates is fine, they should be the same)
                    capability_costs[cap_name] = costs
        
        capability_analyzer = CapabilityAnalyzer(capability_costs)
        capability_analyzer.analyze_from_manifest(manifest_path)
        print()

    for scenario_path in args.files:
        scenario_file = Path(scenario_path)
        output = extractor.extract(scenario_file, verbose_clauses=True)

        if not args.no_summary:
            extractor.print_summary(output)

        # Handle multiple queries: filter derivations if --query specified
        if output.derivations:
            # Collect unique queries from derivations
            unique_queries = []
            for deriv in output.derivations:
                if deriv.query and deriv.query not in unique_queries:
                    unique_queries.append(deriv.query)
            
            # Validate --query argument if provided
            if args.query is not None:
                # User explicitly requested a query index
                if args.query < 0 or args.query >= len(unique_queries):
                    print(f"Error: --query {args.query} out of range.")
                    if unique_queries:
                        print(f"Available queries (0-{len(unique_queries)-1}):")
                        for i, q in enumerate(unique_queries):
                            print(f"  {i}: {q}")
                    else:
                        print("No queries found in derivations!")
                    continue
                # Select the requested query
                selected_query = unique_queries[args.query]
                output.derivations = [d for d in output.derivations if d.query == selected_query]
                output.query = selected_query
                if not args.no_summary:
                    print(f"Selected query {args.query}: {selected_query}")
            
            # If multiple queries and user didn't specify one
            elif len(unique_queries) > 1:
                # Multiple queries found, inform user
                if not args.no_summary:
                    print(f"\nWarning: Multiple queries found ({len(unique_queries)} total).")
                    print("Available queries:")
                    for i, q in enumerate(unique_queries):
                        print(f"  {i}: {q}")
                    print(f"Using first query. To select another, use: --query <index>")
                # Use first query by default
                selected_query = unique_queries[0]
                output.derivations = [d for d in output.derivations if d.query == selected_query]
                output.query = selected_query
            
            elif len(unique_queries) == 1:
                # Single query, update output.query if not already set
                if not output.query:
                    output.query = unique_queries[0]

        # Generate graphviz files if requested
        if output.derivations:
            # Try to find a query tag from manifest
            query_tag = None
            if manifest_data and output.query:
                # Try multiple scenario name variations (for cost-annotated files)
                scenario_name = scenario_file.name
                # Strip cost annotations like ___100_time_ to find base scenario
                base_scenario_name = scenario_name
                import re
                base_scenario_name = re.sub(r'___\d+_\w+_', '', base_scenario_name)  # Remove cost annotations
                
                # Try to find matching scenario in manifest
                matching_scenarios = []
                for scenario in manifest_data.get("scenarios", []):
                    if scenario.get("file") in [scenario_name, base_scenario_name]:
                        matching_scenarios.append(scenario)
                
                # If no exact match, try to find any scenario with similar name
                if not matching_scenarios:
                    for scenario in manifest_data.get("scenarios", []):
                        scenario_file_base = scenario.get("file", "").replace(".pv", "")
                        our_file_base = base_scenario_name.replace(".pv", "")
                        # Remove cost annotations for comparison
                        scenario_file_base = re.sub(r'___\d+_\w+_', '', scenario_file_base)
                        if scenario_file_base in our_file_base or our_file_base in scenario_file_base:
                            matching_scenarios.append(scenario)
                
                # Search for matching query in all candidate scenarios
                for scenario in matching_scenarios:
                    for query_info in scenario.get("queries", []):
                        query_text = query_info.get("query", "")
                        
                        # Normalize both queries for comparison
                        # Remove comments, query prefix, whitespace, brackets, punctuation
                        normalized_manifest = re.sub(r'\(\*.*?\*\)', '', query_text)  # Remove comments
                        normalized_manifest = normalized_manifest.replace("query ", "").replace("not ", "")
                        normalized_manifest = normalized_manifest.replace("\n", "").replace(" ", "")
                        normalized_manifest = normalized_manifest.replace("[", "").replace("]", "")
                        normalized_manifest = normalized_manifest.replace(";", "").replace(".", "")
                        normalized_manifest = normalized_manifest.lower()
                        
                        normalized_output = output.query.replace("not ", "").replace(" ", "")
                        normalized_output = normalized_output.replace("[", "").replace("]", "")
                        normalized_output = normalized_output.lower()
                        
                        # Check if they match
                        if normalized_output == normalized_manifest or \
                           (len(normalized_output) > 10 and normalized_output in normalized_manifest) or \
                           (len(normalized_manifest) > 10 and normalized_manifest in normalized_output):
                            tag = query_info.get("tag", "")
                            # Prefer meaningful tags over generic "query" tag
                            if tag and tag != "query":
                                query_tag = tag
                                break
                            elif tag == "query" and not query_tag:
                                # Use generic tag as fallback, but allow better matches to override it
                                # Extract a better tag from the comment if available
                                comment_match = re.search(r'\(\*\s*([^*]+?)\s*\*\)', query_text)
                                if comment_match:
                                    query_tag = comment_match.group(1).strip()
                    if query_tag and query_tag != "query":
                        break
            
            # If no tag from manifest, extract a short version of the query
            if not query_tag and output.query:
                # Use a simplified version: just show what's being queried
                import re
                # Extract the main predicate (e.g., "attacker(...)" from "not attacker(...)")
                match = re.search(r'(not\s+)?(\w+)\(', output.query)
                if match:
                    negation = "not " if match.group(1) else ""
                    predicate = match.group(2)
                    query_tag = f"{negation}{predicate}(...)"
                else:
                    # Truncate long queries
                    query_tag = output.query[:50] + "..." if len(output.query) > 50 else output.query
            
            # Use readable nodes by default, unless --original-terms is specified
            use_readable = not args.original_terms
            tree = renderer.build_tree_from_derivations(output.derivations, query_tag, capability_costs, use_readable)
            if tree:
                # Annotate with capabilities if analyzer is available
                if capability_analyzer:
                    tree = capability_analyzer.annotate_tree_with_capabilities(tree, scenario_file)
                
                base_name = scenario_file.stem

                if dot_dir:
                    dot_file = dot_dir / f"{base_name}_derivation.dot"
                    renderer.render_to_file(tree, dot_file)

                if pdf_dir:
                    pdf_file = pdf_dir / f"{base_name}_derivation"
                    renderer.render_to_pdf(tree, pdf_file)


if __name__ == "__main__":
    main()
