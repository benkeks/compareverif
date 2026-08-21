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
        obtained_location: ET.Element,
        start_channel: str,
        mitigated_channel: str,
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
        ET.SubElement(acquire, "label", {"kind": "guard", "x": "80", "y": "-250"}).text = (
            " && ".join(guard_parts) if guard_parts else "true"
        )
        ET.SubElement(acquire, "label", {"kind": "assignment", "x": "80", "y": "-224"}).text = ", ".join(
            ["unlocking_clock = 0"]
            + [
                f"{resource_names[resource]} -= {cost}"
                for resource, cost in capability_costs.items()
            ]
        )
        ET.SubElement(
            acquire,
            "label",
            {"kind": "synchronisation", "x": "80", "y": "-198"},
        ).text = f"{start_channel}!"
        ET.SubElement(acquire, "nail", {"x": "80", "y": "-220"})
        ET.SubElement(acquire, "nail", {"x": "180", "y": "-220"})

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

        invariant = ET.SubElement(
            obtained_location,
            "label",
            {"kind": "invariant", "x": "520", "y": "34"},
        )
        invariant.text = "mitigation_clock <= mitigation_time"

        committed_timeout = ET.SubElement(
            template,
            "transition",
            {"id": "capability_transition_committed_timeout"},
        )
        ET.SubElement(committed_timeout, "source", {"ref": committed_id})
        ET.SubElement(committed_timeout, "target", {"ref": idle_id})
        ET.SubElement(
            committed_timeout,
            "label",
            {"kind": "guard", "x": "180", "y": "110"},
        ).text = "mitigation_clock >= mitigation_time"
        ET.SubElement(
            committed_timeout,
            "label",
            {"kind": "assignment", "x": "180", "y": "136"},
        ).text = "mitigation_clock = 0"
        ET.SubElement(
            committed_timeout,
            "label",
            {"kind": "synchronisation", "x": "180", "y": "162"},
        ).text = f"{mitigated_channel}!"
        ET.SubElement(committed_timeout, "nail", {"x": "180", "y": "80"})
        ET.SubElement(committed_timeout, "nail", {"x": "80", "y": "80"})

        obtained_timeout = ET.SubElement(
            template,
            "transition",
            {"id": "capability_transition_obtained_timeout"},
        )
        ET.SubElement(obtained_timeout, "source", {"ref": obtained_id})
        ET.SubElement(obtained_timeout, "target", {"ref": idle_id})
        ET.SubElement(
            obtained_timeout,
            "label",
            {"kind": "guard", "x": "360", "y": "180"},
        ).text = "mitigation_clock >= mitigation_time"
        ET.SubElement(
            obtained_timeout,
            "label",
            {"kind": "assignment", "x": "360", "y": "206"},
        ).text = f"{capability_name} = false, mitigation_clock = 0"
        ET.SubElement(
            obtained_timeout,
            "label",
            {"kind": "synchronisation", "x": "360", "y": "232"},
        ).text = f"{mitigated_channel}!"
        ET.SubElement(obtained_timeout, "nail", {"x": "420", "y": "220"})
        ET.SubElement(obtained_timeout, "nail", {"x": "100", "y": "220"})
