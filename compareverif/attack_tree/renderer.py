"""Render attack trees to graphviz format."""

import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

from compareverif.proverif import Derivation
from .analyzer import DerivationTreeAnalyzer
from .models import DerivationTree


class GraphvizRenderer:
    """Renders derivations as graphviz diagrams."""

    LABEL_WRAP_MAX_CHARS = 50
    LABEL_WRAP_MAX_LINES = 4
    LABEL_WRAP_WINDOW = 12
    LABEL_WRAP_PREFERRED_CHARS = " ,).;"


    @staticmethod
    def generate_dot(
        tree: DerivationTree,
        label_wrapper: Optional[Callable[[str], List[str]]] = None,
    ) -> str:
        """Generate graphviz DOT for a derivation tree."""
        dot_lines = ["digraph DerivationTree {"]
        dot_lines.append("  rankdir=BT;")
        dot_lines.append("  node [shape=box, style=rounded];")

        capability_children_by_fact: Dict[tuple, set] = {}
        for source_key, target_key in tree.edges:
            target_node = tree.nodes[target_key]
            if target_node.node_type == "capability":
                capability_children_by_fact.setdefault(source_key, set()).add(target_key)

        highlighted_nodes = tree._get_attack_highlight_nodes()
        wrap = label_wrapper or GraphvizRenderer.wrap_label_for_display

        for (fact, variant_id), node in tree.nodes.items():
            if node.node_type == "capability":
                label = fact
            elif tree.readable_nodes:
                label = node.to_readable_format(fact)
            else:
                label = fact

            label_lines = wrap(label)
            html_parts = [GraphvizRenderer._format_label_html(line) for line in label_lines[:4]]

            if node.rule == "goal" and tree.query_tag:
                html_parts.append(
                    GraphvizRenderer._format_label_html(f"(❌ {tree.query_tag})")
                )

            if node.node_type == "capability":
                cost_parts = []
                for cap in sorted(node.capabilities or {fact}):
                    if cap in tree.capability_costs:
                        for cost_type, cost_value in sorted(tree.capability_costs[cap].items()):
                            cost_parts.append(f"{cost_value} {cost_type}")
                if cost_parts:
                    html_parts.append(GraphvizRenderer._format_label_html(" + ".join(cost_parts)))
            elif tree.show_clause_ids and node.clause_number is not None:
                html_parts.append(
                    GraphvizRenderer._format_label_html(f"clause {node.clause_number}")
                )

            label_html = "<BR/>".join(html_parts)

            fillcolor = None
            color = None
            shape = "box"
            style = "filled"
            if node.node_type == "capability":
                fillcolor = "#F4CCCC"
                color = "#CC0000"
                shape = "octagon"
            elif node.rule == "goal":
                fillcolor = "#D8B4E2"
                shape = "ellipse"
            elif fact.startswith("table("):
                fillcolor = "#D9D9D9"
                shape = "cylinder"
            elif fact.startswith("mess("):
                fillcolor = "#D9D9D9"
                shape = "note"
            else:
                fillcolor = "#D9D9D9"

            attrs = {
                "label": f"<{label_html}>",
                "shape": f'"{shape}"',
                "style": f'"{style}"',
            }
            if fillcolor:
                attrs["fillcolor"] = f'"{fillcolor}"'
            if color:
                attrs["color"] = f'"{color}"'
                attrs["fontcolor"] = f'"{color}"'

            if tree.highlight_attack and (fact, variant_id) not in highlighted_nodes:
                attrs["fillcolor"] = '"#F2F2F2"'
                attrs["color"] = '"#A6A6A6"'
                attrs["fontcolor"] = '"#A6A6A6"'

            xlabel_attributes: Dict[str, str] = {}
            if node.node_type == "capability":
                for cap in sorted(node.capabilities or {fact}):
                    xlabel_attributes.update(tree.capability_attributes.get(cap, {}))
            if node.required_seconds is not None:
                xlabel_attributes["required_time"] = f"{node.required_seconds}s"
            if xlabel_attributes:
                xlabel_lines = [
                    f"{GraphvizRenderer._escape_dot_string(key)}: "
                    f"{GraphvizRenderer._escape_dot_string(value)}"
                    for key, value in sorted(xlabel_attributes.items())
                ]
                xlabel_text = "\\n".join(xlabel_lines)
                attrs["xlabel"] = f'"{xlabel_text}"'

            attrs_str = ", ".join(f"{key}={value}" for key, value in attrs.items())
            dot_lines.append(f"  {node.node_id} [{attrs_str}];")

        visited = set()
        for source_key, target_key in tree.edges:
            source_node = tree.nodes[source_key]
            target_node = tree.nodes[target_key]
            edge_key = f"{source_node.node_id}-{target_node.node_id}"
            if edge_key in visited:
                continue

            visited.add(edge_key)
            edge_label = ""
            if (
                target_node.node_type == "capability"
                and len(capability_children_by_fact.get(source_key, set())) > 1
            ):
                edge_label = ' [label="OR", style=dashed]'

            edge_highlighted = source_key in highlighted_nodes and target_key in highlighted_nodes
            if tree.highlight_attack and not edge_highlighted:
                if edge_label:
                    edge_label = edge_label[:-1] + ', color="#BFBFBF", fontcolor="#BFBFBF", penwidth=0.8]'
                else:
                    edge_label = ' [color="#BFBFBF", fontcolor="#BFBFBF", penwidth=0.8]'

            dot_lines.append(f"  {target_node.node_id} -> {source_node.node_id}{edge_label};")

        dot_lines.append("}")
        return "\n".join(dot_lines)

    @staticmethod
    def build_tree_from_derivations(
        derivations: List[Derivation],
        query_tag: Optional[str] = None,
        capability_costs: Optional[Dict[str, Dict[str, int]]] = None,
        readable_nodes: bool = False,
        show_clause_ids: bool = False,
        highlight_attack: bool = False,
        capability_attributes: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Optional[DerivationTree]:
        """Build a derivation tree from a list of derivations.

        Kept here for backwards compatibility; delegates to DerivationTreeAnalyzer.
        """
        return DerivationTreeAnalyzer.build_tree_from_derivations(
            derivations,
            query_tag=query_tag,
            capability_costs=capability_costs,
            readable_nodes=readable_nodes,
            show_clause_ids=show_clause_ids,
            highlight_attack=highlight_attack,
            capability_attributes=capability_attributes,
        )

    @staticmethod
    def render_to_file(tree: DerivationTree, output_path: Path) -> None:
        """
        Render a tree to a graphviz dot file.

        Args:
            tree: DerivationTree to render
            output_path: Path to write the dot file
        """
        dot_content = GraphvizRenderer.generate_dot(
            tree,
            label_wrapper=GraphvizRenderer.wrap_label_for_display,
        )
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
        dot_content = GraphvizRenderer.generate_dot(
            tree,
            label_wrapper=GraphvizRenderer.wrap_label_for_display,
        )
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

    @staticmethod
    def render_to_svg(tree: DerivationTree, output_path: Path) -> None:
        """
        Render a tree as SVG using graphviz.

        Args:
            tree: DerivationTree to render
            output_path: Path to write the SVG file (without .svg extension)

        Raises:
            RuntimeError: If graphviz is not installed
        """
        dot_content = GraphvizRenderer.generate_dot(
            tree,
            label_wrapper=GraphvizRenderer.wrap_label_for_display,
        )
        dot_file = output_path.with_suffix(".dot")
        dot_file.write_text(dot_content)

        try:
            svg_path = output_path.with_suffix(".svg")
            subprocess.run(
                ["dot", "-Tsvg", str(dot_file), "-o", str(svg_path)],
                check=True,
                capture_output=True,
            )
            print(f"SVG rendered to: {svg_path}")
        except FileNotFoundError:
            print(f"Graphviz 'dot' command not found. Dot file saved to: {dot_file}")
            print(
                "To render as PDF, install graphviz and run: dot -Tpdf {dot_file} -o output.pdf"
            )
        except subprocess.CalledProcessError as e:
            print(f"Error rendering PDF: {e.stderr.decode()}")

    @staticmethod
    def render_to_json(tree: DerivationTree, output_path: Path) -> None:
        """Render a tree to a plain JSON file."""
        json_content = tree.to_json()
        output_path.write_text(json.dumps(json_content, indent=2))
        print(f"JSON tree written to: {output_path}")

    @staticmethod
    def render_to_window(tree: DerivationTree, title: Optional[str] = None) -> None:
        """Render a tree in a Matplotlib window using a temporary PNG."""
        import matplotlib.image as mpimg
        import matplotlib.pyplot as plt

        dot_content = GraphvizRenderer.generate_dot(
            tree,
            label_wrapper=GraphvizRenderer.wrap_label_for_display,
        )

        with tempfile.TemporaryDirectory(prefix="compareverif_tree_") as temp_dir:
            dot_file = Path(temp_dir) / "tree.dot"
            png_file = Path(temp_dir) / "tree.png"
            dot_file.write_text(dot_content)

            try:
                subprocess.run(
                    ["dot", "-Tpng", str(dot_file), "-o", str(png_file)],
                    check=True,
                    capture_output=True,
                )
            except FileNotFoundError:
                print("Graphviz 'dot' command not found. Cannot open interactive window.")
                return
            except subprocess.CalledProcessError as e:
                print(f"Error rendering PNG: {e.stderr.decode()}")
                return

            image = mpimg.imread(png_file)
            figure, ax = plt.subplots()
            ax.imshow(image)
            ax.axis("off")
            if title:
                figure.suptitle(title)

    @staticmethod
    def show_windows() -> None:
        """Show all queued Matplotlib windows."""
        import matplotlib.pyplot as plt

        plt.show()

    @staticmethod
    def wrap_label_for_display(label: str) -> List[str]:
        """Wrap a node label by visible text width while preserving HTML tags."""
        plain_text = re.sub(r"<[^>]+>", "", label)
        if len(plain_text) <= GraphvizRenderer.LABEL_WRAP_MAX_CHARS:
            return [label]

        break_points = GraphvizRenderer._choose_wrap_points(
            plain_text,
            max_chars=GraphvizRenderer.LABEL_WRAP_MAX_CHARS,
            max_breaks=GraphvizRenderer.LABEL_WRAP_MAX_LINES - 1,
        )
        if not break_points:
            return [label]

        return GraphvizRenderer._split_html_label_at_plain_positions(label, break_points)

    @staticmethod
    def _choose_wrap_points(text: str, max_chars: int, max_breaks: int) -> List[int]:
        """Choose visible-text break points near max_chars boundaries."""
        break_points: List[int] = []
        start = 0

        while len(break_points) < max_breaks and len(text) - start > max_chars:
            target = start + max_chars
            lo = max(start + 1, target - GraphvizRenderer.LABEL_WRAP_WINDOW)
            hi = min(len(text), target + GraphvizRenderer.LABEL_WRAP_WINDOW)

            best = -1
            for idx in range(hi - 1, lo - 1, -1):
                if text[idx] in GraphvizRenderer.LABEL_WRAP_PREFERRED_CHARS:
                    best = idx + 1
                    break

            if best <= start:
                best = min(len(text), target)

            break_points.append(best)
            start = best

        return break_points

    @staticmethod
    def _split_html_label_at_plain_positions(label: str, break_points: List[int]) -> List[str]:
        """Split an HTML label at plain-text character offsets."""
        points = sorted(set(break_points))
        if not points:
            return [label]

        lines: List[str] = []
        current: List[str] = []
        visible_count = 0
        point_idx = 0
        next_point = points[point_idx]
        i = 0

        while i < len(label):
            if label[i] == "<":
                end = label.find(">", i)
                if end == -1:
                    current.append(label[i])
                    i += 1
                    continue
                current.append(label[i : end + 1])
                i = end + 1
                continue

            current.append(label[i])
            visible_count += 1
            i += 1

            if visible_count >= next_point:
                lines.append("".join(current).rstrip(" "))
                current = []
                while i < len(label) and label[i] == " ":
                    i += 1
                point_idx += 1
                if point_idx >= len(points):
                    next_point = -1
                    break
                next_point = points[point_idx]

        if i < len(label):
            current.append(label[i:])
        remainder = "".join(current).strip()
        if remainder:
            lines.append(remainder)

        return lines or [label]

    @staticmethod
    def _format_label_html(text: str) -> str:
        """Escape HTML special characters in text while preserving known tags."""
        return re.sub(r"&(?![a-z]+;)", "&amp;", text)

    @staticmethod
    def _escape_dot_string(text: str) -> str:
        """Escape backslashes and double quotes for a quoted DOT string attribute."""
        return text.replace("\\", "\\\\").replace('"', '\\"')
