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


@dataclass
class Clause:
    """Represents a ProVerif clause."""
    head: str
    body: List[str] = field(default_factory=list)
    original_text: str = ""

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


@dataclass
class TreeNode:
    """Represents a node in a derivation tree."""
    fact: str
    rule: Optional[str] = None
    node_id: Optional[str] = None

    def __post_init__(self):
        if self.node_id is None:
            # Generate unique ID based on fact content
            self.node_id = f"node_{abs(hash(self.fact)) % 100000}"


class DerivationTree:
    """Represents a derivation as a DAG (directed acyclic graph)."""

    def __init__(self, goal: str):
        self.goal = goal
        self.nodes: Dict[str, TreeNode] = {}
        self.edges: List[Tuple[str, str, Optional[str]]] = []  # (source, target, rule)
        self.add_node(goal, "goal")

    def add_node(self, fact: str, rule: Optional[str] = None) -> TreeNode:
        """Add a node to the graph if not already present."""
        if fact not in self.nodes:
            node = TreeNode(fact=fact, rule=rule)
            self.nodes[fact] = node
        return self.nodes[fact]

    def add_edge(self, source_fact: str, target_fact: str, rule: Optional[str] = None) -> None:
        """Add an edge from source to target."""
        self.add_node(source_fact)
        self.add_node(target_fact, rule)
        self.edges.append((source_fact, target_fact, rule))

    def to_graphviz(self) -> str:
        """Generate graphviz dot format representation."""
        dot_lines = ["digraph DerivationTree {"]
        dot_lines.append('  rankdir=TD;')  # Top-down layout
        dot_lines.append('  node [shape=box, style=rounded];')
        
        # Add all nodes
        for fact, node in self.nodes.items():
            # Truncate long facts for display
            label = fact if len(fact) <= 50 else fact[:47] + "..."
            label = label.replace('"', '\\"')
            
            # Use different colors for goal
            if node.rule == "goal":
                dot_lines.append(f'  {node.node_id} [label="{label}", fillcolor=lightgreen, style="rounded,filled"];')
            elif node.rule and "apply" in node.rule:
                dot_lines.append(f'  {node.node_id} [label="{label}", fillcolor=lightyellow, style="rounded,filled"];')
            elif node.rule and "clause" in node.rule:
                dot_lines.append(f'  {node.node_id} [label="{label}", fillcolor=lightblue, style="rounded,filled"];')
            else:
                dot_lines.append(f'  {node.node_id} [label="{label}"];')
        
        # Add edges
        visited = set()
        for source_fact, target_fact, rule in self.edges:
            source_node = self.nodes[source_fact]
            target_node = self.nodes[target_fact]
            edge_key = f"{source_node.node_id}-{target_node.node_id}"
            
            if edge_key not in visited:
                visited.add(edge_key)
                label = ""
                if rule:
                    label = f' [label="{rule}"]'
                dot_lines.append(f"  {source_node.node_id} -> {target_node.node_id}{label};")
        
        dot_lines.append("}")
        return "\n".join(dot_lines)


class ProVerifRunner:
    """Runs ProVerif and captures output."""

    DEFAULT_TIMEOUT = 300  # 5 minutes

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def run(self, scenario_file: Path, verbose_clauses: bool = True) -> Tuple[int, str, str]:
        """
        Run ProVerif on a scenario file.

        Args:
            scenario_file: Path to the ProVerif file (.pv)
            verbose_clauses: Whether to use -set verboseClauses short

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        if not scenario_file.exists():
            raise FileNotFoundError(f"Scenario file not found: {scenario_file}")

        cmd = ["proverif"]
        if verbose_clauses:
            cmd.extend(["-set", "verboseClauses", "short"])
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

        while i < len(lines):
            line = lines[i].rstrip()

            # Detect start of derivation section
            if line.strip() == "Derivation:":
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
                
                # Parse all collected derivation lines
                self._parse_derivation_block(derivation_lines)
                in_derivation_block = False
                continue

            # Detect section headers for clauses
            if "Initial clauses:" in line or "clauses:" in line.lower():
                in_derivation_block = False
                current_section = "clauses"
                i += 1
                continue

            # Stop collecting clauses at section break
            if current_section == "clauses" and ("--" == line.strip() or (line.startswith("--") and len(line) <= 3)):
                current_section = None
                i += 1
                continue

            # Process clause lines
            if current_section == "clauses":
                match = self.CLAUSE_LINE_PATTERN.match(line)
                if match:
                    clause_id = match.group(1)
                    clause_content = match.group(2)
                    self._parse_clause_line(clause_content)
                elif line.startswith("Abbreviations:"):
                    # Skip abbreviations block
                    current_section = None
                i += 1
                continue

            i += 1

        return self.output

    def _parse_clause_line(self, clause_str: str) -> None:
        """
        Parse a clause line in format: premises -> conclusion or just conclusion.

        Args:
            clause_str: The clause content (without "Clause N:" prefix)
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
                    head=conclusion, body=premises, original_text=clause_str
                )
            else:
                clause = Clause(head=clause_str, original_text=clause_str)
        else:
            clause = Clause(head=clause_str, original_text=clause_str)

        self.output.clauses.append(clause)

    def _parse_derivation_block(self, lines: List[str]) -> None:
        """
        Parse a block of derivation lines (tree-structured with indentation from explainDerivation = false).

        Args:
            lines: List of lines from the derivation section
        """
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
                        indent_level=indent_level
                    )
                    self.output.derivations.append(derivation)
            
            # Extract clause references (e.g., "clause 26 event(...)")
            elif stripped_line.startswith("clause "):
                match = re.search(r"clause\s+\d+\s+(.+?)$", stripped_line)
                if match:
                    fact = match.group(1).strip()
                    derivation = Derivation(
                        conclusion=fact,
                        premises=[],
                        rule_name="clause",
                        indent_level=indent_level
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
                        indent_level=indent_level
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
                        indent_level=indent_level
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


class GraphvizRenderer:
    """Renders derivations as graphviz diagrams."""

    @staticmethod
    def build_tree_from_derivations(derivations: List[Derivation]) -> Optional[DerivationTree]:
        """
        Build a derivation tree from a list of derivations.
        
        With explainDerivation = false, derivations have hierarchical structure via indentation.
        ProVerif may output multiple derivation trees (one per failed query), so we extract
        only the first complete tree.
        
        Args:
            derivations: List of Derivation objects with indent_level information
            
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

        tree = DerivationTree(goal)

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
            tree.add_node(deriv.conclusion, deriv.rule_name)
        
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
                # Use child's rule_name as the edge label
                tree.add_edge(parent.conclusion, deriv.conclusion, deriv.rule_name)

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

    args = parser.parse_args()

    if not args.files:
        print("Usage: python3 attack_tree_extractor.py <scenario_file.pv> [scenario_file2.pv ...]")
        print("\nOptions:")
        print("  --graphviz-dot DIR      Output graphviz dot files to DIR")
        print("  --graphviz-pdf DIR      Output graphviz PDF files to DIR (requires graphviz)")
        print("  --no-summary            Skip printing the summary")
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

    for scenario_path in args.files:
        scenario_file = Path(scenario_path)
        output = extractor.extract(scenario_file, verbose_clauses=True)

        if not args.no_summary:
            extractor.print_summary(output)

        # Generate graphviz files if requested
        if output.derivations:
            tree = renderer.build_tree_from_derivations(output.derivations)
            if tree:
                base_name = scenario_file.stem

                if dot_dir:
                    dot_file = dot_dir / f"{base_name}_derivation.dot"
                    renderer.render_to_file(tree, dot_file)

                if pdf_dir:
                    pdf_file = pdf_dir / f"{base_name}_derivation"
                    renderer.render_to_pdf(tree, pdf_file)


if __name__ == "__main__":
    main()
