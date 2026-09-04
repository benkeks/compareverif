"""Immediate capability UPPAAL backend."""

from xml.etree import ElementTree as ET


class ImmediateCapabilityAutomaton:
    """Render immediate capability acquisition."""

    @staticmethod
    def render(
        template: ET.Element,
        *,
        capability_name: str,
        idle_id: str,
        obtained_id: str,
        capability_costs: dict,
        resource_names: dict,
        pretty_text: str,
    ) -> None:
        """Add the immediate Idle-to-Obtained capability transition."""
        transition = ET.SubElement(
            template,
            "transition",
            {"id": "capability_transition"},
        )
        ET.SubElement(transition, "source", {"ref": idle_id})
        ET.SubElement(transition, "target", {"ref": obtained_id})
        guard_parts = [
            f"{resource_names[resource]} >= {cost}"
            for resource, cost in capability_costs.items()
        ]
        ET.SubElement(transition, "label", {"kind": "guard", "x": "40", "y": "-30"}).text = (
            " && ".join(guard_parts) if guard_parts else "true"
        )
        ET.SubElement(transition, "label", {"kind": "assignment", "x": "40", "y": "0"}).text = ", ".join(
            [f"{capability_name} = true"]
            + [
                f"{resource_names[resource]} -= {cost}"
                for resource, cost in capability_costs.items()
            ]
        )
        ET.SubElement(
            transition,
            "label",
            {"kind": "synchronisation", "x": "40", "y": "30"},
        ).text = f"{capability_name}_c!"
        ET.SubElement(
            transition,
            "label",
            {"kind": "comments", "x": "40", "y": "60"},
        ).text = pretty_text
