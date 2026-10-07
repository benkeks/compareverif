"""Tests for the ProVerif-to-UPPAAL command-line entry point."""

import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

import proverif_to_uppaal
from compareverif.uppaal import ReservedTranslationNameWarning


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


def test_all_caps_names_warn_and_still_write_uppaal_output(tmp_path, monkeypatch):
    scenario = tmp_path / "scenario.pv"
    output_file = tmp_path / "scenario.xml"
    scenario.write_text("channel c.\nfree VALUE: bitstring.\nprocess out(c, VALUE) | out(c, VALUE).\n")
    monkeypatch.setattr(
        sys,
        "argv",
        ["proverif_to_uppaal.py", "--no-attacks", str(scenario)],
    )
    monkeypatch.setattr(
        proverif_to_uppaal.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, INITIAL_PROCESS.replace("value", "VALUE"), ""
        ),
    )

    with pytest.warns(ReservedTranslationNameWarning, match="VALUE"):
        assert proverif_to_uppaal.main() == 0
    assert output_file.is_file()
    assert "VALUE" in output_file.read_text()


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


@pytest.mark.integration
@pytest.mark.skipif(shutil.which("proverif") is None, reason="ProVerif is not installed")
@pytest.mark.parametrize(
    ("key_leak", "weak_disclosure", "expected"),
    [(True, True, "false"), (False, True, "false"), (False, False, "true")],
    ids=["compromised-key", "weak-rsa-only", "no-disclosures"],
)
def test_tls12_static_v2_authentication_controls(
    tmp_path, monkeypatch, key_leak, weak_disclosure, expected
):
    model = Path(__file__).resolve().parents[2] / "examples/3rd-party/tls12_attack_static_v2.pv"
    source = model.read_text()
    if not key_leak:
        source = source.replace("| out(leak, compromised_key) )", ")")
    if not weak_disclosure:
        source = source.replace(
            "then pair(pms, sign(server_key, pms)) else zero in",
            "then zero else zero in",
        )
    scenario = tmp_path / "tls12.pv"
    scenario.write_text(source)
    result = subprocess.run(
        ["proverif", "-set", "traceDisplay", "long", "-test", str(scenario)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    query = "event(client_finished(connection)) ==> event(server_finished(connection))"
    assert f"RESULT {query} is {expected}." in result.stdout
    monkeypatch.setattr(sys, "argv", ["proverif_to_uppaal.py", str(scenario)])
    monkeypatch.setattr(proverif_to_uppaal.subprocess, "run", lambda *args, **kwargs: result)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        assert proverif_to_uppaal.main() == 0
    document = scenario.with_suffix(".xml").read_text()
    assert ("AttackOnQuery1" in document) == (expected == "false")
    assert "attack_weak_rsa" not in document
    assert "attack_strong_rsa" not in document
    for template in ET.fromstring(document).findall("template"):
        names = [location.findtext("name") for location in template.findall("location")]
        assert len(names) == len(set(names)), template.findtext("name")