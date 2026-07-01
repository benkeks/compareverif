"""Focused tests for the high-level attack-tree extractor API."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from compareverif.attack_tree import AttackTreeExtractor, CapabilityAnalyzer
from compareverif.proverif import Derivation, ProVerifOutput


class TestAttackTreeExtractor:
    """Test the high-level tree-building convenience API."""

    def test_extract_tree_filters_derivations_before_building_tree(self):
        """The convenience API should expose the filtered derivation slice it renders."""
        extractor = AttackTreeExtractor()
        output = ProVerifOutput(
            derivations=[
                Derivation(conclusion="goal1", rule_name="goal", indent_level=0, query="keep"),
                Derivation(conclusion="fact1", rule_name="clause", indent_level=1, query="keep"),
                Derivation(conclusion="goal2", rule_name="goal", indent_level=0, query="drop"),
            ],
            clauses=[],
        )

        with patch.object(extractor, "extract", return_value=output):
            result = extractor.extract_tree(
                Path("scenario.pv"),
                derivation_filter=lambda derivation: derivation.query == "keep",
            )

        assert len(result.derivations) == 2
        assert result.tree is not None
        assert result.tree.goal == "goal1"

    def test_extract_tree_builds_capability_analyzer_from_scenarios(self):
        """Generated scenarios should be enough to request capability-aware trees."""
        extractor = AttackTreeExtractor()
        output = ProVerifOutput(
            derivations=[
                Derivation(conclusion="attacker(secret[])", rule_name="goal", indent_level=0)
            ],
            clauses=[],
        )
        mock_analyzer = MagicMock(spec=CapabilityAnalyzer)
        mock_analyzer.capability_costs = {"Rainbow": {"time": 5}}
        mock_analyzer.annotate_tree_with_capabilities.side_effect = lambda tree, _: tree

        with patch.object(extractor, "extract", return_value=output), patch(
            "compareverif.attack_tree.extractor.CapabilityAnalyzer.from_scenarios",
            return_value=mock_analyzer,
        ) as mock_from_scenarios:
            result = extractor.extract_tree(
                Path("scenario.pv"),
                capability_scenarios=[object()],
                readable_nodes=True,
            )

        mock_from_scenarios.assert_called_once()
        mock_analyzer.annotate_tree_with_capabilities.assert_called_once()
        assert result.capability_analyzer is mock_analyzer
        assert result.tree is not None

    def test_extract_tree_filters_by_query_tag_using_scenario_queries(self):
        """API callers should be able to select the desired query using only its tag."""
        extractor = AttackTreeExtractor()
        output = ProVerifOutput(
            derivations=[
                Derivation(conclusion="auth_goal", rule_name="goal", indent_level=0, query="event(server_user_authenticated(user1[]))"),
                Derivation(conclusion="password_goal", rule_name="goal", indent_level=0, query="attacker(the_password[])"),
                Derivation(conclusion="password_fact", rule_name="clause", indent_level=1, query="attacker(the_password[])"),
            ],
            clauses=[],
        )

        with patch.object(extractor, "extract", return_value=output):
            result = extractor.extract_tree(
                Path("scenario.pv"),
                query_tag="no pw leakage",
                scenario_queries=[
                    {"tag": "authenticated", "query": "query event(server_user_authenticated(user1))."},
                    {"tag": "no pw leakage", "query": "query attacker(the_password)."},
                ],
            )

        assert len(result.derivations) == 2
        assert result.tree is not None
        assert result.tree.goal == "password_goal"