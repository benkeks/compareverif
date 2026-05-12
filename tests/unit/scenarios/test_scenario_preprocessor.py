"""Tests for the scenario preprocessor orchestrator."""

import pytest
from pathlib import Path
from proverifbatch.scenarios.preprocessor import ScenarioPreprocessor


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
    
    def test_preprocess_with_no_capabilities(self, tmp_scenario_dir):
        """Test preprocessing a file with no magical comments."""
        scenario_file = tmp_scenario_dir / "no_caps.pv"
        scenario_file.write_text("new key: bitstring.\nquery attacker(key).")
        
        preprocessor = ScenarioPreprocessor()
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))
        
        assert generated == []
        assert output_dir == Path(tmp_scenario_dir / "output")
    
    def test_preprocess_with_capabilities(self, tmp_scenario_dir, sample_scenario_content):
        """Test preprocessing a file with capabilities."""
        scenario_file = tmp_scenario_dir / "test.pv"
        scenario_file.write_text(sample_scenario_content)
        
        preprocessor = ScenarioPreprocessor()
        generated, output_dir = preprocessor.preprocess(str(scenario_file), str(tmp_scenario_dir / "output"))
        
        # Should generate base + all capability combinations
        # 2 capabilities with 1 variant each = (0,0), (0,1), (1,0), (1,1) = 4 combinations
        assert len(generated) > 0
        
        # Check that files were created
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
    
    def test_print_analysis_no_false_results(self, capsys):
        """Test printing analysis when no queries return false."""
        from proverifbatch.scenarios.models import ScenarioFile, ScenarioResult
        
        preprocessor = ScenarioPreprocessor()
        
        scenario = ScenarioFile(
            path=Path("test.pv"),
            capabilities=[],
            costs={},
            queries=[{"tag": "test_query", "query": "query a."}]
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
