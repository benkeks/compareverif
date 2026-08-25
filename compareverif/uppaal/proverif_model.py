"""Build a static UPPAAL model skeleton from a parsed ProVerif intermediate process."""

from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from compareverif.proverif.intermediate_process import IntermediateProcess

from .document import write_document

_CHANNEL_STATEMENT_RE = re.compile(r"^(?:in|out)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,")


def collect_channel_names(process: IntermediateProcess) -> list[str]:
    """Return channel names used by in(...)/out(...) statements, in first-seen order."""
    channels: list[str] = []
    seen: set[str] = set()
    for node in process.labeled_nodes():
        match = _CHANNEL_STATEMENT_RE.match(node.text)
        if not match:
            continue
        channel = match.group(1)
        if channel not in seen:
            seen.add(channel)
            channels.append(channel)
    return channels


def render_channel_skeleton(output_file: Path, process: IntermediateProcess) -> list[str]:
    """Write a blank UPPAAL model declaring one channel and payload variable per ProVerif channel.

    Replicated subprocesses are ignored here (this only inspects channel usages), and
    payloads are represented by a single global variable per channel rather than actual
    process locations/transitions, which are added in later translation steps.
    """
    channels = collect_channel_names(process)

    nta = ET.Element("nta")

    declaration = ET.SubElement(nta, "declaration")
    declaration_lines = ["// Channels extracted from the ProVerif process."]
    for channel in channels:
        declaration_lines.append(f"chan {channel};")
        declaration_lines.append(f"int {channel}_p;")
    declaration.text = "\n".join(declaration_lines) + "\n"

    template = ET.SubElement(nta, "template")
    ET.SubElement(template, "name").text = "AttackProgress"
    location = ET.SubElement(template, "location", {"id": "attack_progress", "x": "0", "y": "0"})
    ET.SubElement(location, "name", {"x": "0", "y": "-34"}).text = "AttackProgress"
    ET.SubElement(template, "init", {"ref": "attack_progress"})

    system = ET.SubElement(nta, "system")
    system.text = "Process = AttackProgress();\nsystem Process;\n"

    queries = ET.SubElement(nta, "queries")
    query = ET.SubElement(queries, "query")
    ET.SubElement(query, "formula").text = "A[] true"
    ET.SubElement(query, "comment").text = "Blank model skeleton with ProVerif channels."

    write_document(output_file, nta)
    return channels
