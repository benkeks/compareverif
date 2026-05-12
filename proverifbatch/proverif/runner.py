"""ProVerif execution interface."""

import subprocess
from pathlib import Path
from typing import Tuple


DEFAULT_TIMEOUT = 300  # 5 minutes


class ProVerifRunner:
    """Runs ProVerif and captures output."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def run(
        self,
        scenario_file: Path,
        verbose_clauses: bool = True,
        clause_verbosity: str = "short",
    ) -> Tuple[int, str, str]:
        """
        Run ProVerif on a scenario file.

        Args:
            scenario_file: Path to the ProVerif file (.pv)
            verbose_clauses: Whether to use -set verboseClauses
            clause_verbosity: Verbosity level: "short" (initial clauses) or "explained" (all clauses)

        Returns:
            Tuple of (return_code, stdout, stderr)

        Raises:
            FileNotFoundError: If scenario file doesn't exist
            TimeoutError: If ProVerif execution exceeds timeout
        """
        if not scenario_file.exists():
            raise FileNotFoundError(f"Scenario file not found: {scenario_file}")

        cmd = ["proverif"]
        if verbose_clauses:
            cmd.extend(["-set", "verboseClauses", clause_verbosity])
        # Use simpler derivation format for uniform parsing
        cmd.extend(["-set", "explainDerivation", "false"])
        cmd.extend(["-set", "simplifyDerivation", "false"])
        cmd.extend(["-set", "abbreviateDerivation", "false"])
        cmd.extend(["-set", "abbreviateClauses", "false"])
        cmd.append(str(scenario_file))

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            raise TimeoutError(
                f"ProVerif execution timed out after {self.timeout} seconds"
            )
