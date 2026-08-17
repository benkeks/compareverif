"""Generate UPPAAL timed automata documents."""

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from compareverif.attack_tree import DerivationTree, TreeNode


class UppaalGenerator:
    """Generate a single-loop event automaton for a derivation tree."""

    DOCTYPE = (
        "<!DOCTYPE nta PUBLIC '-//Uppaal Team//DTD Flat System 1.6//EN' "
        "'http://www.it.uu.se/research/group/darts/uppaal/flat-1_6.dtd'>"
    )

    @staticmethod
    def _slugify_name(name: str) -> str:
        """Normalize names to stable, filename-like identifiers."""
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", str(name).strip().lower()).strip("_")
        return slug or "event"

    @staticmethod
    def _pretty_text(node: TreeNode) -> str:
        """Return a human-readable plain-text comment for one node."""
        if node.node_type == "capability":
            return node.fact

        readable = TreeNode.to_readable_format(node.fact)
        plain = re.sub(r"<[^>]+>", "", readable)
        plain = plain.replace("&amp;", "&")
        return plain

    @classmethod
    def _node_variable_names(cls, tree: DerivationTree) -> dict:
        """Return one collision-free variable slug for each concrete tree node."""
        variable_names = {}
        for index, ((fact, variant_id), _node) in enumerate(tree.nodes.items(), start=1):
            parts = [fact]
            if variant_id:
                parts.append(variant_id)
            slug = cls._slugify_name("_".join(parts))
            variable_names[(fact, variant_id)] = f"{slug}_{index}"
        return variable_names

    @classmethod
    def render_empty(cls, output_file: Path) -> None:
        """Write a minimal but valid empty UPPAAL document."""
        nta = ET.Element("nta")
        ET.SubElement(nta, "declaration").text = "// No derivation nodes available.\n"
        template = ET.SubElement(nta, "template")
        ET.SubElement(template, "name").text = "EventLoop"
        ET.SubElement(template, "declaration").text = "clock event_clock;\n"
        location = ET.SubElement(template, "location", {"id": "event_loop", "x": "0", "y": "0"})
        ET.SubElement(location, "name", {"x": "0", "y": "-34"}).text = "EventLoop"
        ET.SubElement(template, "init", {"ref": "event_loop"})
        ET.SubElement(nta, "system").text = "Process = EventLoop();\nsystem Process;\n"
        queries = ET.SubElement(nta, "queries")
        query = ET.SubElement(queries, "query")
        ET.SubElement(query, "formula").text = "A[] true"
        ET.SubElement(query, "comment").text = "Empty placeholder model."
        cls._write_document(output_file, nta)

    @classmethod
    def render_tree(cls, output_file: Path, tree: DerivationTree) -> None:
        """Write one self-loop transition for each node in the derivation tree."""
        if not tree.nodes:
            cls.render_empty(output_file)
            return

        variable_names = cls._node_variable_names(tree)
        prerequisites = {key: [] for key in tree.nodes}
        for source_key, target_key in tree.edges:
            if source_key in prerequisites:
                prerequisites[source_key].append(target_key)

        nta = ET.Element("nta")

        declaration = ET.SubElement(nta, "declaration")
        declaration_lines = ["// Event booleans. All start false."]
        for key, node in tree.nodes.items():
            declaration_lines.append(f"// {cls._pretty_text(node)}")
            declaration_lines.append(f"bool bool_{variable_names[key]} = false;")
        declaration.text = "\n".join(declaration_lines) + "\n"

        template = ET.SubElement(nta, "template")
        ET.SubElement(template, "name").text = "EventLoop"
        ET.SubElement(template, "declaration").text = "clock event_clock;\n"

        location = ET.SubElement(template, "location", {"id": "event_loop", "x": "0", "y": "0"})
        ET.SubElement(location, "name", {"x": "0", "y": "-34"}).text = "EventLoop"
        ET.SubElement(template, "init", {"ref": "event_loop"})

        for index, (key, node) in enumerate(tree.nodes.items()):
            transition = ET.SubElement(template, "transition", {"id": f"t_{index}"})
            ET.SubElement(transition, "source", {"ref": "event_loop"})
            ET.SubElement(transition, "target", {"ref": "event_loop"})

            nail_offset = 180 + (index % 4) * 180
            nail_height = -180 - (index // 4) * 140
            ET.SubElement(transition, "nail", {"x": str(nail_offset), "y": str(nail_height)})
            ET.SubElement(transition, "nail", {"x": str(nail_offset + 60), "y": str(nail_height)})

            guard_parts = [f"!bool_{variable_names[key]}"]
            for req_key in prerequisites[key]:
                guard_parts.append(f"bool_{variable_names[req_key]} == true")
            guard_text = " && ".join(guard_parts)

            base_x = nail_offset + 30
            base_y = nail_height - 30
            guard = ET.SubElement(
                transition,
                "label",
                {"kind": "guard", "x": str(base_x), "y": str(base_y)},
            )
            guard.text = guard_text

            assignment = ET.SubElement(
                transition,
                "label",
                {"kind": "assignment", "x": str(base_x), "y": str(base_y + 26)},
            )
            assignment.text = f"bool_{variable_names[key]} = true"

            comment = ET.SubElement(
                transition,
                "label",
                {"kind": "comment", "x": str(base_x), "y": str(base_y + 52)},
            )
            comment.text = cls._pretty_text(node)

        system = ET.SubElement(nta, "system")
        system.text = "Process = EventLoop();\nsystem Process;\n"

        queries = ET.SubElement(nta, "queries")
        query = ET.SubElement(queries, "query")
        ET.SubElement(query, "formula").text = "A[] not deadlock"
        ET.SubElement(query, "comment").text = "Generated attack-tree event structure."

        cls._write_document(output_file, nta)

    @classmethod
    def _write_document(cls, output_file: Path, nta: ET.Element) -> None:
        """Write the XML document with UPPAAL's required doctype."""
        tree = ET.ElementTree(nta)
        ET.indent(tree, space="  ")
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("wb") as handle:
            handle.write(b'<?xml version="1.0" encoding="utf-8"?>\n')
            handle.write(f"{cls.DOCTYPE}\n".encode("utf-8"))
            tree.write(handle, encoding="utf-8", xml_declaration=False)
