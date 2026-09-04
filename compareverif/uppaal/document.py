"""Shared XML writer for UPPAAL documents."""

from pathlib import Path
from xml.etree import ElementTree as ET

DOCTYPE = (
    "<!DOCTYPE nta PUBLIC '-//Uppaal Team//DTD Flat System 1.6//EN' "
    "'http://www.it.uu.se/research/group/darts/uppaal/flat-1_6.dtd'>"
)


def write_document(output_file: Path, nta: ET.Element) -> None:
    """Write an ``nta`` element as a UPPAAL XML document with its required doctype."""
    tree = ET.ElementTree(nta)
    ET.indent(tree, space="  ")
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("wb") as handle:
        handle.write(b'<?xml version="1.0" encoding="utf-8"?>\n')
        handle.write(f"{DOCTYPE}\n".encode("utf-8"))
        tree.write(handle, encoding="utf-8", xml_declaration=False)
