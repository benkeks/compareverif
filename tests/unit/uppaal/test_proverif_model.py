"""Tests for building a blank UPPAAL model from a parsed ProVerif process."""

from xml.etree import ElementTree as ET

from compareverif.proverif.intermediate_process import extract_let_drifted_process
from compareverif.uppaal import collect_channel_names, render_channel_skeleton


PROVERIF_OUTPUT = """--  Process 1 (that is, process 0, with let moved downwards):
{1}new key: bitstring;
(
    {2}!
    {3}in(server_link, ct: bitstring);
    {4}out(server_link, ct)
) | (
    {5}in(tick, seconds(3));
    {6}out(loop, ())
)

Translating the process into Horn clauses...
"""


def test_collect_channel_names_deduplicates_and_preserves_first_seen_order():
    process = extract_let_drifted_process(PROVERIF_OUTPUT)

    assert collect_channel_names(process) == ["server_link", "tick", "loop"]


def test_render_channel_skeleton_declares_channel_and_payload_variable(tmp_path):
    process = extract_let_drifted_process(PROVERIF_OUTPUT)
    output_file = tmp_path / "model.xml"

    channels = render_channel_skeleton(output_file, process)

    assert channels == ["server_link", "tick", "loop"]
    document = output_file.read_text()
    root = ET.parse(output_file).getroot()
    assert "<!DOCTYPE nta PUBLIC '-//Uppaal Team//DTD Flat System 1.6//EN'" in document
    assert root.tag == "nta"
    for channel in channels:
        assert f"chan {channel};" in document
        assert f"int {channel}_p;" in document
