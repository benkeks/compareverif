"""Render attack trees to graphviz format."""

import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from src.proverif import Derivation
from .models import DerivationTree


class GraphvizRenderer:
    """Renders derivations as graphviz diagrams."""

    @staticmethod
    def build_tree_from_derivations(
        derivations: List[Derivation],
        query_tag: Optional[str] = None,
        capability_costs: Optional[Dict[str, Dict[str, int]]] = None,
        readable_nodes: bool = False,
        show_clause_ids: bool = False,
    ) -> Optional[DerivationTree]:
        """
        Build a derivation tree from a list of derivations.

        With explainDerivation = false, derivations have hierarchical structure via indentation.
        ProVerif may output multiple derivation trees (one per failed query), so we extract
        only the first complete tree.

        Args:
            derivations: List of Derivation objects with indent_level information
            query_tag: Optional tag/name describing the violated query
            capability_costs: Dict mapping capability names to cost dicts
            readable_nodes: Whether to use readable format for nodes
            show_clause_ids: Whether to show clause numbers

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

        tree = DerivationTree(
            goal, query_tag, capability_costs, readable_nodes, show_clause_ids
        )

        # Separate derivations into different categories
        all_derivs = first_tree_derivs

        # Add all nodes (including duplicates and transformations)
        for deriv in all_derivs:
            # Skip "apply" transformations - they don't represent real derivation steps
            if deriv.rule_name and deriv.rule_name.startswith("apply "):
                continue
            tree.add_node(
                deriv.conclusion,
                deriv.rule_name,
                clause_number=deriv.clause_number,
                clause_scope=deriv.query_scope,
            )

        # Build parent-child relationships based on indentation
        # For each derivation, find its parent (the closest previous derivation with lower indent)
        for i, deriv in enumerate(all_derivs):
            # Skip "apply" transformations
            if deriv.rule_name and deriv.rule_name.startswith("apply "):
                continue

            current_indent = deriv.indent_level

            # Find parent: look backwards for first item with lower indent level, skipping apply steps
            parent_idx = None
            for j in range(i - 1, -1, -1):
                if all_derivs[j].rule_name and all_derivs[j].rule_name.startswith(
                    "apply "
                ):
                    continue
                if all_derivs[j].indent_level < current_indent:
                    parent_idx = j
                    break

            # If parent found and it's not a self-loop, create edge
            if parent_idx is not None:
                parent = all_derivs[parent_idx]
                # Don't create self-loops
                if parent.conclusion != deriv.conclusion:
                    tree.add_edge(
                        parent.conclusion,
                        deriv.conclusion,
                        deriv.rule_name,
                        clause_number=deriv.clause_number,
                        clause_scope=deriv.query_scope,
                    )

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
        dot_file = output_path.with_suffix(".dot")
        dot_file.write_text(dot_content)

        try:
            # Try to generate PDF
            pdf_path = output_path.with_suffix(".pdf")
            subprocess.run(
                ["dot", "-Tpdf", str(dot_file), "-o", str(pdf_path)],
                check=True,
                capture_output=True,
            )
            print(f"PDF rendered to: {pdf_path}")
        except FileNotFoundError:
            print(f"Graphviz 'dot' command not found. Dot file saved to: {dot_file}")
            print(
                "To render as PDF, install graphviz and run: dot -Tpdf {dot_file} -o output.pdf"
            )
        except subprocess.CalledProcessError as e:
            print(f"Error rendering PDF: {e.stderr.decode()}")
