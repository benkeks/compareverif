"""Mitigatable capability UPPAAL backend."""

from xml.etree import ElementTree as ET


class MitigatableCapabilityAutomaton:
    """Render delayed capability acquisition with a mitigation-ready skeleton."""

    @staticmethod
    def render(
        template: ET.Element,
        *,
        capability_name: str,
        idle_id: str,
        committed_id: str,
        obtained_id: str,
        start_channel: str,
        capability_costs: dict,
        resource_names: dict,
        pretty_text: str,
        unlocking_time: int,
        mitigation_time: int,
    ) -> None:
        """Add Idle-to-Committed and delayed Committed-to-Obtained transitions."""
        guard_parts = [
            f"{resource_names[resource]} >= {cost}"
            for resource, cost in capability_costs.items()
        ]
        acquire = ET.SubElement(
            template,
            "transition",
            {"id": "capability_transition_acquire"},
        )
        ET.SubElement(acquire, "source", {"ref": idle_id})
        ET.SubElement(acquire, "target", {"ref": committed_id})
        ET.SubElement(acquire, "label", {"kind": "guard", "x": "40", "y": "-70"}).text = (
            " && ".join(guard_parts) if guard_parts else "true"
        )
        ET.SubElement(acquire, "label", {"kind": "assignment", "x": "40", "y": "-44"}).text = ", ".join(
            ["unlocking_clock = 0"]
            + [
                f"{resource_names[resource]} -= {cost}"
                for resource, cost in capability_costs.items()
            ]
        )
        ET.SubElement(
            acquire,
            "label",
            {"kind": "synchronisation", "x": "40", "y": "-18"},
        ).text = f"{start_channel}!"

        complete = ET.SubElement(
            template,
            "transition",
            {"id": "capability_transition_complete"},
        )
        ET.SubElement(complete, "source", {"ref": committed_id})
        ET.SubElement(complete, "target", {"ref": obtained_id})
        ET.SubElement(complete, "label", {"kind": "guard", "x": "360", "y": "-70"}).text = (
            "unlocking_clock >= unlocking_time"
        )
        ET.SubElement(complete, "label", {"kind": "assignment", "x": "360", "y": "-44"}).text = (
            f"{capability_name} = true"
        )
        ET.SubElement(
            complete,
            "label",
            {"kind": "synchronisation", "x": "360", "y": "-18"},
        ).text = f"{capability_name}_c!"
        ET.SubElement(
            complete,
            "label",
            {"kind": "comments", "x": "360", "y": "8"},
        ).text = f"{pretty_text} (unlocking {unlocking_time}, mitigation {mitigation_time})"
