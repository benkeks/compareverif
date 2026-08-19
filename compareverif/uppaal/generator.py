"""Generate UPPAAL timed automata documents."""

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from compareverif.attack_tree import DerivationTree, TreeNode
from compareverif.scenarios.generator import create_scenario_filename


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
        used_names = set()
        for index, ((fact, variant_id), node) in enumerate(tree.nodes.items(), start=1):
            if node.rule == "goal":
                prefix = "goal"
            elif node.node_type == "capability":
                prefix = "cap"
            else:
                prefix = "ev"

            if node.node_type == "capability":
                candidate = f"{prefix}_{create_scenario_filename([fact])}"
            else:
                parts = [fact]
                if variant_id:
                    parts.append(variant_id)
                suffix = f"_{index}"
                max_slug_length = 60 - len(prefix) - 1 - len(suffix)
                slug = cls._slugify_name("_".join(parts))[:max_slug_length]
                candidate = f"{prefix}_{slug}{suffix}"

            if candidate in used_names:
                suffix = f"_{index}"
                candidate = f"{candidate[:60 - len(suffix)]}{suffix}"
            used_names.add(candidate)
            variable_names[(fact, variant_id)] = candidate
        return variable_names

    @classmethod
    def _resource_budgets(cls, tree: DerivationTree) -> dict:
        """Sum capability costs into budgets sufficient for all tree transitions."""
        budgets = {}
        for node in tree.nodes.values():
            if node.node_type != "capability":
                continue
            for capability in node.capabilities or {node.fact}:
                for resource, cost in tree.capability_costs.get(capability, {}).items():
                    if isinstance(cost, int) and cost > 0:
                        budgets[resource] = budgets.get(resource, 0) + cost
        return budgets

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
        resource_budgets = cls._resource_budgets(tree)
        resource_names = {
            resource: f"res_{cls._slugify_name(resource)}"
            for resource in resource_budgets
        }
        prerequisites = {key: [] for key in tree.nodes}
        for source_key, target_key in tree.edges:
            if source_key in prerequisites:
                prerequisites[source_key].append(target_key)

        nta = ET.Element("nta")

        declaration = ET.SubElement(nta, "declaration")
        declaration_lines = ["// Event booleans. All start false."]
        for key, node in tree.nodes.items():
            declaration_lines.append(f"\n// {cls._pretty_text(node)}")
            declaration_lines.append(f"bool {variable_names[key]} = false;")
            declaration_lines.append(f"broadcast chan {variable_names[key]}_c;")
        if resource_budgets:
            declaration_lines.append("\n// Attacker resource budgets.")
            for resource, budget in resource_budgets.items():
                declaration_lines.append(f"int {resource_names[resource]} = {budget};")
        declaration.text = "\n".join(declaration_lines) + "\n"

        template = ET.SubElement(nta, "template")
        ET.SubElement(template, "name").text = "EventLoop"
        ET.SubElement(template, "declaration").text = "clock event_clock;\n"

        location = ET.SubElement(template, "location", {"id": "event_loop", "x": "0", "y": "0"})
        ET.SubElement(location, "name", {"x": "0", "y": "-34"}).text = "EventLoop"
        ET.SubElement(template, "init", {"ref": "event_loop"})

        event_nodes = [
            (key, node) for key, node in tree.nodes.items() if node.node_type != "capability"
        ]
        capability_nodes = [
            (key, node) for key, node in tree.nodes.items() if node.node_type == "capability"
        ]
        node_count = len(event_nodes)
        for index, (key, node) in enumerate(event_nodes):
            transition = ET.SubElement(template, "transition", {"id": f"t_{index}"})
            ET.SubElement(transition, "source", {"ref": "event_loop"})
            ET.SubElement(transition, "target", {"ref": "event_loop"})

            if node_count < 20:
                nail_offset = 180
                nail_height = -180 - index * 140
            else:
                nail_offset = 180 + (index % 4) * 180
                nail_height = -180 - (index // 4) * 140
            guard_parts = [f"!{variable_names[key]}"]
            for req_key in prerequisites[key]:
                guard_parts.append(f"{variable_names[req_key]}")
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
            assignment.text = f"{variable_names[key]} = true"

            synchronization = ET.SubElement(
                transition,
                "label",
                {"kind": "synchronisation", "x": str(base_x), "y": str(base_y + 52)},
            )
            synchronization.text = f"{variable_names[key]}_c!"

            # Though not mentioned in the XML doc, `comments` is the correct kind for a comment label.
            comment = ET.SubElement(
                transition,
                "label",
                {"kind": "comments", "x": str(base_x), "y": str(base_y + 78)},
            )
            comment.text = cls._pretty_text(node)

            ET.SubElement(transition, "nail", {"x": str(nail_offset), "y": str(nail_height)})
            ET.SubElement(transition, "nail", {"x": str(nail_offset + 60), "y": str(nail_height)})

        for index, (key, node) in enumerate(capability_nodes):
            capability_name = variable_names[key]
            capability_template_name = f"Obtain_{capability_name}"
            capability_template = ET.SubElement(nta, "template")
            ET.SubElement(capability_template, "name").text = capability_template_name
            ET.SubElement(capability_template, "declaration").text = "clock acquisition_clock;\n"

            idle_id = f"{capability_name}_idle"
            obtained_id = f"{capability_name}_obtained"
            idle = ET.SubElement(
                capability_template,
                "location",
                {"id": idle_id, "x": "0", "y": "0"},
            )
            ET.SubElement(idle, "name", {"x": "0", "y": "-34"}).text = "Idle"
            obtained = ET.SubElement(
                capability_template,
                "location",
                {"id": obtained_id, "x": "260", "y": "0"},
            )
            ET.SubElement(obtained, "name", {"x": "260", "y": "-34"}).text = "Obtained"
            ET.SubElement(capability_template, "init", {"ref": idle_id})

            capability_costs = {}
            for capability in node.capabilities or {node.fact}:
                for resource, cost in tree.capability_costs.get(capability, {}).items():
                    if resource in resource_names and isinstance(cost, int) and cost > 0:
                        capability_costs[resource] = capability_costs.get(resource, 0) + cost

            transition = ET.SubElement(
                capability_template,
                "transition",
                {"id": f"capability_transition_{index}"},
            )
            ET.SubElement(transition, "source", {"ref": idle_id})
            ET.SubElement(transition, "target", {"ref": obtained_id})
            guard = ET.SubElement(transition, "label", {"kind": "guard", "x": "40", "y": "-30"})
            guard_parts = [f"{resource_names[resource]} >= {cost}" for resource, cost in capability_costs.items()]
            guard.text = " && ".join(guard_parts) if guard_parts else "true"
            assignment = ET.SubElement(
                transition,
                "label",
                {"kind": "assignment", "x": "40", "y": "0"},
            )
            assignments = [f"{capability_name} = true"]
            assignments.extend(
                f"{resource_names[resource]} -= {cost}"
                for resource, cost in capability_costs.items()
            )
            assignment.text = ", ".join(assignments)
            synchronization = ET.SubElement(
                transition,
                "label",
                {"kind": "synchronisation", "x": "40", "y": "30"},
            )
            synchronization.text = f"{capability_name}_c!"
            comment = ET.SubElement(
                transition,
                "label",
                {"kind": "comments", "x": "40", "y": "60"},
            )
            comment.text = cls._pretty_text(node)

        system = ET.SubElement(nta, "system")
        system_lines = ["main_process = EventLoop();"]
        for key, _node in capability_nodes:
            capability_name = variable_names[key]
            system_lines.append(
                f"{capability_name}_process = Obtain_{capability_name}();"
            )
        system_lines.append(
            "system " + ", ".join(
                ["main_process"]
                + [f"{variable_names[key]}_process" for key, _node in capability_nodes]
            )
            + ";"
        )
        system.text = "\n".join(system_lines) + "\n"

        queries = ET.SubElement(nta, "queries")
        query = ET.SubElement(queries, "query")
        goal_key = (tree.goal, tree.GOAL_VARIANT)
        ET.SubElement(query, "formula").text = f"E<> {variable_names[goal_key]}"
        ET.SubElement(query, "comment").text = cls._pretty_text(tree.nodes[goal_key])

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
