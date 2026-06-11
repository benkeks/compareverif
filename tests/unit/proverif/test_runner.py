"""Unit tests for ProVerif runner."""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from proverifbatch.proverif import ProVerifRunner


class TestProVerifRunner:
    """Test ProVerifRunner class."""

    def test_runner_creation(self):
        """Test basic runner creation."""
        runner = ProVerifRunner(timeout=600)
        assert runner.timeout == 600

    def test_runner_default_timeout(self):
        """Test runner default timeout."""
        runner = ProVerifRunner()
        assert runner.timeout == 300  # DEFAULT_TIMEOUT

    def test_run_missing_file(self):
        """Test running on non-existent file."""
        runner = ProVerifRunner()
        with pytest.raises(FileNotFoundError):
            runner.run(Path("/nonexistent/file.pv"))

    @patch("subprocess.run")
    def test_run_success(self, mock_run):
        """Test successful ProVerif run."""
        # Mock subprocess.run
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Test output"
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        runner = ProVerifRunner()
        # Create a temporary file for testing
        with patch("pathlib.Path.exists", return_value=True):
            code, stdout, stderr = runner.run(
                Path("test.pv"),
                verbose_clauses=True,
                clause_verbosity="short",
            )

        assert code == 0
        assert stdout == "Test output"
        assert stderr == ""

    @patch("subprocess.run")
    def test_run_with_error_output(self, mock_run):
        """Test ProVerif run with error output."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = "Some output"
        mock_result.stderr = "Error message"
        mock_run.return_value = mock_result

        runner = ProVerifRunner()
        with patch("pathlib.Path.exists", return_value=True):
            code, stdout, stderr = runner.run(Path("test.pv"))

        assert code == 1
        assert "Error message" in stderr

    @patch("subprocess.run")
    def test_run_timeout(self, mock_run):
        """Test ProVerif run timeout."""
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("proverif", 10)

        runner = ProVerifRunner(timeout=10)
        with patch("pathlib.Path.exists", return_value=True):
            with pytest.raises(TimeoutError):
                runner.run(Path("test.pv"))

    @patch("subprocess.run")
    def test_run_command_structure(self, mock_run):
        """Test that ProVerif command is constructed correctly."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        runner = ProVerifRunner()
        with patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.read_text", return_value="new x: bitstring."
        ):
            runner.run(
                Path("test.pv"),
                verbose_clauses=True,
                clause_verbosity="explained",
            )

        # Check that the command was called with correct arguments
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert "proverif" in cmd
        assert "-set" in cmd
        assert "verboseClauses" in cmd
        assert "explained" in cmd
        assert "-set" in cmd
        assert "explainDerivation" in cmd
        assert cmd[-1] == "test.pv"
        assert mock_run.call_args.kwargs["cwd"] == Path(".")

    @patch("subprocess.run")
    def test_run_includes_declared_library_flags(self, mock_run):
        """Runner should pass top-level `(* -lib ... *)` declarations to proverif."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        runner = ProVerifRunner()
        with patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.read_text",
            return_value="(* -lib primitives.pvl *)\nnew key: bitstring.\n",
        ):
            runner.run(Path("test.pv"), verbose_clauses=False)

        cmd = mock_run.call_args[0][0]
        assert cmd[:3] == ["proverif", "-lib", "primitives.pvl"]
