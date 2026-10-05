"""Tests for the ProVerif-to-UPPAAL command-line entry point."""

import subprocess
import sys
from pathlib import Path

import pytest

import proverif_to_uppaal


INITIAL_PROCESS = """Process 0 (that is, the initial process):
(
    {1}out(c, value)
) | (
    {2}out(c, value)
)

Translating the process into Horn clauses...
"""


def test_no_attacks_uses_short_timeout_and_initial_process(tmp_path, monkeypatch):
    scenario = tmp_path / "scenario.pv"
    output_file = tmp_path / "model.xml"
    scenario.write_text("channel c.\nprocess out(c, value) | out(c, value).\n")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "proverif_to_uppaal.py",
            "--no-attacks",
            "--uppaal-out",
            str(output_file),
            str(scenario),
        ],
    )

    def timeout(*args, **kwargs):
        assert "traceDisplay" not in args[0]
        assert kwargs["timeout"] == 0.5
        raise subprocess.TimeoutExpired(args[0], 0.5, output=INITIAL_PROCESS)

    monkeypatch.setattr(proverif_to_uppaal.subprocess, "run", timeout)

    assert proverif_to_uppaal.main() == 0
    document = output_file.read_text()
    assert "Component1" in document
    assert "AttackOnQuery" not in document


def test_defaults_uppaal_output_to_input_name_with_xml_suffix(tmp_path, monkeypatch):
    scenario = tmp_path / "scenario.pv"
    output_file = tmp_path / "scenario.xml"
    scenario.write_text("channel c.\nprocess out(c, value) | out(c, value).\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["proverif_to_uppaal.py", "--no-attacks", str(scenario)],
    )
    monkeypatch.setattr(
        proverif_to_uppaal.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0, INITIAL_PROCESS, ""),
    )

    assert proverif_to_uppaal.main() == 0
    assert output_file.is_file()


def test_no_attacks_conflicts_with_show_attack_processes(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["proverif_to_uppaal.py", "--no-attacks", "--show-attack-processes", "scenario.pv"],
    )

    with pytest.raises(SystemExit) as error:
        proverif_to_uppaal.parse_arguments()

    assert error.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err