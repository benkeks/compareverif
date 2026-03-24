"""Main orchestrator for attack tree extraction."""

from pathlib import Path
from typing import Optional

from src.proverif import ProVerifRunner, ProVerifOutputParser, ProVerifOutput
from src.proverif.runner import DEFAULT_TIMEOUT


class AttackTreeExtractor:
    """Main orchestrator for extracting attack trees from ProVerif."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.runner = ProVerifRunner(timeout=timeout)
        self.parser = ProVerifOutputParser()

    def extract(
        self, scenario_file: Path, verbose_clauses: bool = True
    ) -> ProVerifOutput:
        """
        Run ProVerif and extract clauses and derivations.

        Args:
            scenario_file: Path to the ProVerif file
            verbose_clauses: Whether to use short clause verbosity

        Returns:
            ProVerifOutput containing extracted information
        """
        print(f"Running ProVerif on: {scenario_file}")
        try:
            return_code, stdout, stderr = self.runner.run(scenario_file, verbose_clauses)
            output = self.parser.parse(stdout)
            if stderr:
                output.errors = stderr.split("\n")
            return output
        except FileNotFoundError as e:
            output = ProVerifOutput()
            output.errors = [str(e)]
            return output
        except TimeoutError as e:
            output = ProVerifOutput()
            output.errors = [str(e)]
            return output

    def print_summary(self, output: ProVerifOutput) -> None:
        """Print a summary of extracted information."""
        print(f"\n{'='*60}")
        print("Attack Tree Extraction Summary")
        print(f"{'='*60}")

        print(f"\nClauses extracted: {len(output.clauses)}")
        if output.clauses:
            max_display = min(10, len(output.clauses))
            for clause in output.clauses[:max_display]:
                clause_text = clause.original_text or str(clause)
                clause_num = (
                    str(clause.clause_number)
                    if clause.clause_number is not None
                    else "?"
                )
                scope_str = (
                    f" [Query {clause.clause_scope + 1}]"
                    if clause.clause_scope is not None
                    else ""
                )
                clause_str = f"Clause {clause_num}{scope_str}: {clause_text}"
                # Truncate if necessary
                if len(clause_str) > 70:
                    clause_str = clause_str[:67] + "..."
                clause_tag = "initial" if clause.is_initial else "derived"
                print(f"  {clause_str} [{clause_tag}]")
            if len(output.clauses) > 10:
                print(f"  ... and {len(output.clauses) - 10} more")

        print(f"\nDerivations extracted: {len(output.derivations)}")
        if output.derivations:
            max_display = min(10, len(output.derivations))
            for derivation in output.derivations[:max_display]:
                indent = "  " * derivation.indent_level
                rule_label = derivation.rule_name or "step"
                if rule_label == "clause" and derivation.clause_number is not None:
                    scope_str = (
                        f" [Query {derivation.query_scope + 1}]"
                        if derivation.query_scope is not None
                        else ""
                    )
                    rule_label = f"clause {derivation.clause_number}{scope_str}"
                deriv_str = f"{indent}{rule_label}: {derivation.conclusion}"
                # Truncate if necessary
                if len(deriv_str) > 70:
                    deriv_str = deriv_str[:67] + "..."
                print(f"  {deriv_str}")
            if len(output.derivations) > 10:
                print(f"  ... and {len(output.derivations) - 10} more")

        if output.errors:
            print(f"\nErrors encountered: {len(output.errors)}")
            for error in output.errors[:5]:
                if error.strip():
                    print(f"  - {error}")
