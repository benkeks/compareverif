"""Build derivation trees from parsed ProVerif derivations."""

import re
from typing import Dict, List, Optional

from compareverif.proverif import Derivation

from .models import DerivationTree


class DerivationTreeAnalyzer:
    """Builds a DerivationTree out of a flat list of parsed ProVerif derivations."""

    REQUIRED_SECONDS_PATTERN = re.compile(r"^attacker\(seconds\((\d+)\)\)$")

    @staticmethod
    def build_tree_from_derivations(
        derivations: List[Derivation],
        query_tag: Optional[str] = None,
        capability_costs: Optional[Dict[str, Dict[str, int]]] = None,
        readable_nodes: bool = False,
        show_clause_ids: bool = False,
        highlight_attack: bool = False,
        capability_attributes: Optional[Dict[str, Dict[str, str]]] = None,
    ) -> Optional[DerivationTree]:
        """
        Build a derivation tree from a list of derivations.

        With explainDerivation = false, derivations have hierarchical structure via indentation.
        ProVerif may output multiple derivation trees (one per failed query), so we extract
        only the first complete tree.

        Args:
            derivations: List of Derivation objects with indent_level information
            query_tag: Optional tag/name describing the violated query
            capability_costs: Dict mapping capability names to cost dicts
            readable_nodes: Whether to use readable format for nodes
            show_clause_ids: Whether to show clause numbers
            highlight_attack: Whether to fade non-attack-relevant branches
            capability_attributes: Dict mapping capability names to string attribute dicts

        Returns:
            DerivationTree object or None if no derivations
        """
        if not derivations:
            return None

        # Find the first derivation tree (starts with goal at indent 0)
        # and ends when we see another goal at indent 0
        first_tree_derivs = []
        started = False

        for deriv in derivations:
            if deriv.rule_name == "goal" and deriv.indent_level == 0:
                if started:
                    # Found start of second tree, stop
                    break
                else:
                    # Found start of first tree
                    started = True
                    first_tree_derivs.append(deriv)
            elif started:
                first_tree_derivs.append(deriv)

        if not first_tree_derivs:
            return None

        # Find the goal
        goal = first_tree_derivs[0].conclusion

        tree = DerivationTree(
            goal,
            query_tag,
            capability_costs,
            readable_nodes,
            show_clause_ids,
            highlight_attack,
            capability_attributes,
        )

        # Separate derivations into different categories
        all_derivs = first_tree_derivs

        deriv_node_keys = [None] * len(all_derivs)

        # Add all nodes (including duplicates and transformations)
        for idx, deriv in enumerate(all_derivs):
            # Skip "apply" transformations - they don't represent real derivation steps
            if deriv.rule_name and deriv.rule_name.startswith("apply "):
                continue

            variant_id = None
            # Preserve explicit clause steps that conclude the goal fact as separate nodes.
            # Otherwise they collapse into the goal node and hide capability/cost attribution.
            if (
                deriv.rule_name == "clause"
                and deriv.clause_number is not None
                and deriv.conclusion == goal
            ):
                scope = (
                    str(deriv.query_scope)
                    if deriv.query_scope is not None
                    else "global"
                )
                variant_id = f"goal_clause_{scope}_{deriv.clause_number}_{idx}"

            tree.add_node(
                deriv.conclusion,
                deriv.rule_name,
                clause_number=deriv.clause_number,
                variant_id=variant_id,
                clause_scope=deriv.query_scope,
            )
            deriv_node_keys[idx] = (deriv.conclusion, variant_id)

        # Build parent-child relationships based on indentation
        # For each derivation, find its parent (the closest previous derivation with lower indent)
        for i, deriv in enumerate(all_derivs):
            # Skip "apply" transformations
            if deriv.rule_name and deriv.rule_name.startswith("apply "):
                continue

            current_indent = deriv.indent_level

            # Find parent: look backwards for first item with lower indent level, skipping apply steps
            parent_idx = None
            for j in range(i - 1, -1, -1):
                if all_derivs[j].rule_name and all_derivs[j].rule_name.startswith(
                    "apply "
                ):
                    continue
                if all_derivs[j].indent_level < current_indent:
                    parent_idx = j
                    break

            # If parent found and it's not a self-loop, create edge
            if parent_idx is not None:
                parent_key = deriv_node_keys[parent_idx]
                current_key = deriv_node_keys[i]

                if parent_key is None or current_key is None:
                    continue

                # Don't create exact same-node self-loops; allow same-fact edges when variants differ
                if parent_key != current_key:
                    tree.add_edge(
                        parent_key[0],
                        current_key[0],
                        source_variant=parent_key[1],
                        target_variant=current_key[1],
                    )

        # A derivation step concluding attacker(seconds(N)) - directly or via constructor
        # application (e.g. "apply seconds attacker(seconds(1))") - means its nearest real
        # ancestor step can only fire once N seconds have elapsed. "apply" steps never become
        # tree nodes/edges themselves, so this is resolved with its own ancestor search.
        for i, deriv in enumerate(all_derivs):
            seconds_match = DerivationTreeAnalyzer.REQUIRED_SECONDS_PATTERN.match(
                deriv.conclusion.strip()
            )
            if not seconds_match:
                continue

            seconds_value = int(seconds_match.group(1))
            current_indent = deriv.indent_level
            for j in range(i - 1, -1, -1):
                if all_derivs[j].rule_name and all_derivs[j].rule_name.startswith("apply "):
                    continue
                if all_derivs[j].indent_level < current_indent:
                    ancestor_key = deriv_node_keys[j]
                    if ancestor_key is not None:
                        tree.mark_required_seconds(
                            ancestor_key[0], ancestor_key[1], seconds_value
                        )
                    break

        return tree
