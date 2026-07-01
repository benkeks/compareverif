"""Tests for the scenario preprocessor orchestrator."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
from compareverif.scenarios.preprocessor import ScenarioPreprocessor


class TestScenarioPreprocessor:
    """Tests for ScenarioPreprocessor class."""
    
    def test_initialization(self):
        """Test preprocessor initialization."""
        preprocessor = ScenarioPreprocessor(timeout=600)
        assert preprocessor.timeout == 600
    
    def test_default_timeout(self):
        """Test default timeout."""
        preprocessor = ScenarioPreprocessor()
        assert preprocessor.timeout == 300
        assert preprocessor.check_all_scenarios is True
        assert preprocessor.dump_logs is False
    
    def test_preprocess_with_no_capabilities(self, tmp_scenario_dir):
        """Test preprocessing a file with no magical comments."""
        scenario_file = tmp_scenario_dir / "no_caps.pv"
        scenario_file.write_text("new key: bitstring.\nquery attacker(key).")
        
        preprocessor = ScenarioPreprocessor()
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))
        
        assert generated == []
        assert output_dir == Path(tmp_scenario_dir / "output")
    
    def test_preprocess_with_capabilities(self, tmp_scenario_dir, sample_scenario_content):
        """Default preprocessing generates all capability combinations (exhaustive mode)."""
        scenario_file = tmp_scenario_dir / "test.pv"
        scenario_file.write_text(sample_scenario_content)
        
        preprocessor = ScenarioPreprocessor()
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))
        
        # With check_all_scenarios=True by default, all combinations should be generated
        assert len(generated) == 4  # base + 2 single + 1 combined
        assert output_dir == Path(tmp_scenario_dir / "output")
        for scenario_file_obj in generated:
            assert scenario_file_obj.path.exists()

    def test_preprocess_check_all_scenarios_generates_all_combinations(self, tmp_scenario_dir, sample_scenario_content):
        """The exhaustive mode (default) should preserve eager scenario generation."""
        scenario_file = tmp_scenario_dir / "test.pv"
        scenario_file.write_text(sample_scenario_content)

        # Default behavior is check_all_scenarios=True
        preprocessor = ScenarioPreprocessor(check_all_scenarios=True)
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        assert len(generated) == 4
        assert output_dir == Path(tmp_scenario_dir / "output")
        for scenario_file_obj in generated:
            assert scenario_file_obj.path.exists()

    def test_preprocess_lazy_mode_generates_support_scenarios(self, tmp_scenario_dir, sample_scenario_content):
        """The lazy mode should only generate support scenarios needed downstream."""
        scenario_file = tmp_scenario_dir / "test.pv"
        scenario_file.write_text(sample_scenario_content)

        preprocessor = ScenarioPreprocessor(check_all_scenarios=False)
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        assert sorted(s.path.stem for s in generated) == [
            "base_scenario",
            "intruder_at_database",
            "rainbow_table_attack",
        ]
        assert output_dir == Path(tmp_scenario_dir / "output")
        for scenario_file_obj in generated:
            assert scenario_file_obj.path.exists()
    
    def test_preprocess_default_output_dir(self, tmp_scenario_dir):
        """Test preprocessing with default output directory."""
        import tempfile
        import os
        
        # Use a temp location that doesn't exist yet
        with tempfile.TemporaryDirectory() as td:
            # Go to temp dir so relative paths work
            original_cwd = os.getcwd()
            try:
                os.chdir(td)
                
                # Create test file in temp dir
                scenario_file = Path(td) / "mytest.pv"
                scenario_file.write_text("""
(*** Test attack [10 time]
code.
***)
query true.
""")
                
                preprocessor = ScenarioPreprocessor()
                generated, output_dir = preprocessor.preprocess(str(scenario_file))
                
                # Default should be _scenarios/mytest
                assert "_scenarios" in str(output_dir)
                assert "mytest" in str(output_dir)
            finally:
                os.chdir(original_cwd)
    
    def test_analyze_no_results(self):
        """Test analyze with empty results."""
        preprocessor = ScenarioPreprocessor()
        analysis = preprocessor.analyze([], ["test.pv"])
        assert analysis == {"test.pv": {}}

    def test_run_proverif_monotone_search_checks_each_snippet_combination_once(self, tmp_scenario_dir):
        """Monotone search should cache boolean snippet combinations."""
        scenario_file = tmp_scenario_dir / "variants.pv"
        scenario_file.write_text(
            """
new key: bitstring.

(*** Attack A [100 time] / Attack A [10 time]
attacker(a).
***)

(*** Attack B [20 time]
attacker(b).
***)

(* Security *) query attacker(secret).
"""
        )

        preprocessor = ScenarioPreprocessor(check_all_scenarios=False)
        preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        def fake_run(command, capture_output, text, timeout, cwd):
            path = Path(cwd) / command[-1]
            stem = path.stem
            is_false = stem == "attack_a+attack_b"
            return Mock(returncode=0, stdout=f"RESULT query attacker(secret) is {'false' if is_false else 'true'}.\n")

        with patch("compareverif.scenarios.preprocessor.subprocess.run", side_effect=fake_run) as mock_run:
            results = preprocessor.run_proverif([])

        assert len(results) == 4
        assert mock_run.call_count == 4
        assert sorted(result.scenario.path.stem for result in results) == [
            "attack_a",
            "attack_a+attack_b",
            "attack_b",
            "base_scenario",
        ]

    def test_preprocess_generates_single_capability_support_files_for_attack_tree(self, tmp_scenario_dir):
        """Lazy mode should always generate base and single-capability scenario files."""
        scenario_file = tmp_scenario_dir / "support.pv"
        scenario_file.write_text(
            """
new key: bitstring.

(*** Attack A [100 time] / Attack A [10 time]
attacker(a).
***)

(*** Attack B [20 time]
attacker(b).
***)

(*** Attack C [5 hack]
attacker(c).
***)

query attacker(secret).
"""
        )

        preprocessor = ScenarioPreprocessor(check_all_scenarios=False)
        generated, _ = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        assert sorted(scenario.path.stem for scenario in generated) == [
            "attack_a",
            "attack_b",
            "attack_c",
            "base_scenario",
        ]

    def test_execution_stats_track_generated_files_and_runs(self, tmp_scenario_dir):
        """Stats should distinguish generated files from executed ProVerif runs."""
        scenario_file = tmp_scenario_dir / "stats.pv"
        scenario_file.write_text(
            """
new key: bitstring.

(*** Attack A [100 time]
attacker(a).
***)

(*** Attack B [20 time]
attacker(b).
***)

query attacker(secret).
"""
        )

        preprocessor = ScenarioPreprocessor(check_all_scenarios=False)
        preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        before = preprocessor.get_execution_stats()
        assert before.generated_files == 3
        assert before.proverif_runs == 0

        def fake_run(command, capture_output, text, timeout, cwd):
            path = Path(cwd) / command[-1]
            stem = path.stem
            is_false = stem == "attack_a+attack_b"
            return Mock(returncode=0, stdout=f"RESULT query attacker(secret) is {'false' if is_false else 'true'}.\n")

        with patch("compareverif.scenarios.preprocessor.subprocess.run", side_effect=fake_run):
            preprocessor.run_proverif([])

        after = preprocessor.get_execution_stats()
        assert after.generated_files == 4
        assert after.proverif_runs == 4

    def test_preprocess_copies_declared_libraries_and_passes_lib_flags(self, tmp_scenario_dir):
        """Declared top-level `(* -lib ... *)` directives should be copied and invoked."""
        scenario_file = tmp_scenario_dir / "libs.pv"
        library_file = tmp_scenario_dir / "primitives.pvl"
        library_file.write_text("fun h(bitstring): bitstring.")
        scenario_file.write_text(
            """
(* -lib primitives.pvl *)

new key: bitstring.

(*** Attack A [1 time]
attacker(a).
***)

query attacker(secret).
"""
        )

        preprocessor = ScenarioPreprocessor(check_all_scenarios=True)
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        assert (output_dir / "primitives.pvl").exists()
        assert generated
        for generated_scenario in generated:
            assert generated_scenario.libraries == ["primitives.pvl"]

        def fake_run(command, capture_output, text, timeout, cwd):
            assert command[:3] == ["proverif", "-lib", "primitives.pvl"]
            assert Path(cwd) == output_dir
            return Mock(returncode=0, stdout="RESULT query attacker(secret) is true.\n")

        with patch("compareverif.scenarios.preprocessor.subprocess.run", side_effect=fake_run) as mock_run:
            preprocessor.run_proverif(generated)

        assert mock_run.call_count == len(generated)

    def test_run_proverif_writes_logs_when_enabled(self, tmp_scenario_dir):
        """With dump_logs enabled, each scenario should get a .pv.log file."""
        scenario_file = tmp_scenario_dir / "logs.pv"
        scenario_file.write_text(
            """
new key: bitstring.

(*** Attack A [1 time]
attacker(a).
***)

query attacker(secret).
"""
        )

        preprocessor = ScenarioPreprocessor(check_all_scenarios=True, dump_logs=True)
        generated, _ = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))

        def fake_run(command, capture_output, text, timeout, cwd):
            return Mock(returncode=0, stdout="RESULT query attacker(secret) is true.\n", stderr="")

        with patch("compareverif.scenarios.preprocessor.subprocess.run", side_effect=fake_run):
            preprocessor.run_proverif(generated)

        for generated_scenario in generated:
            log_path = generated_scenario.path.with_suffix(generated_scenario.path.suffix + ".log")
            assert log_path.exists()
            assert "RESULT query attacker(secret) is true." in log_path.read_text()
    
    def test_print_analysis_no_false_results(self, capsys):
        """Test printing analysis when no queries return false."""
        from compareverif.scenarios.models import ScenarioFile, ScenarioResult
        
        preprocessor = ScenarioPreprocessor()
        
        scenario = ScenarioFile(
            path=Path("test.pv"),
            capabilities=[],
            costs={},
            queries=[{"tag": "test_query", "query": "query a."}],
            capability_names=[],
        )
        result = ScenarioResult(
            scenario=scenario,
            status="success",
            query_results=[{"tag": "test_query", "result": True}]
        )
        
        analysis = {"test.pv": {"test_query": []}}
        preprocessor.print_analysis(analysis)
        
        captured = capsys.readouterr()
        assert "No false results found" in captured.out
