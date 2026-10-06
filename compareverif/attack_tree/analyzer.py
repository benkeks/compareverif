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

        all_derivs = first_tree_derivs
        retained = [
            not (deriv.rule_name or "").startswith("apply ")
            for deriv in all_derivs
        ]

        parent_indices = []
        ancestor_stack = []
        for index, deriv in enumerate(all_derivs):
            while (
                ancestor_stack
                and all_derivs[ancestor_stack[-1]].indent_level >= deriv.indent_level
            ):
                ancestor_stack.pop()
            parent_indices.append(ancestor_stack[-1] if ancestor_stack else None)
            ancestor_stack.append(index)

        retained_parent_indices = []
        for parent_idx in parent_indices:
            while parent_idx is not None and not retained[parent_idx]:
                parent_idx = parent_indices[parent_idx]
            retained_parent_indices.append(parent_idx)

        requirements = [set() for _ in all_derivs]
        seconds_by_index = {}
        for index, deriv in enumerate(all_derivs):
            parent_idx = retained_parent_indices[index]
            if retained[index] and parent_idx is not None:
                requirements[parent_idx].add(deriv.conclusion)
            seconds_match = DerivationTreeAnalyzer.REQUIRED_SECONDS_PATTERN.match(
                deriv.conclusion.strip()
            )
            if seconds_match and parent_idx is not None:
                seconds_by_index[parent_idx] = max(
                    seconds_by_index.get(parent_idx, 0), int(seconds_match.group(1))
                )

        proofs_by_fact = {}
        for index, deriv in enumerate(all_derivs):
            if not retained[index]:
                continue
            proofs = proofs_by_fact.setdefault(deriv.conclusion, {})
            if deriv.rule_name in {"goal", "duplicate"}:
                continue
            if deriv.rule_name in {"hypothesis", "initial"}:
                requirements[index].clear()
            signature = (
                deriv.rule_name,
                deriv.clause_number,
                deriv.query_scope,
                frozenset(requirements[index]),
                seconds_by_index.get(index),
            )
            proofs.setdefault(signature, index)

        fact_keys = {}
        proof_keys = {}
        for fact, proofs in proofs_by_fact.items():
            indices = list(proofs.values())
            if fact == goal:
                fact_keys[fact] = (fact, tree.GOAL_VARIANT)
                if len(indices) > 1:
                    tree.nodes[fact_keys[fact]].node_type = "or"
            elif len(indices) > 1:
                tree.add_node(fact, rule="or", node_type="or")
                fact_keys[fact] = (fact, None)
            elif not indices:
                tree.add_node(fact, rule="duplicate")
                fact_keys[fact] = (fact, None)

            for index in indices:
                deriv = all_derivs[index]
                scope = str(deriv.query_scope) if deriv.query_scope is not None else "global"
                variant_id = None
                if fact == goal and deriv.rule_name == "clause":
                    variant_id = f"goal_clause_{scope}_{deriv.clause_number}_{index}"
                elif fact == goal or len(indices) > 1:
                    variant_id = f"derivation_{scope}_{index}"
                node = tree.add_node(
                    fact,
                    deriv.rule_name,
                    clause_number=deriv.clause_number,
                    variant_id=variant_id,
                    clause_scope=deriv.query_scope,
                )
                proof_keys[index] = (fact, node.variant_id)
                if fact not in fact_keys:
                    fact_keys[fact] = proof_keys[index]
                if index in seconds_by_index:
                    tree.mark_required_seconds(fact, node.variant_id, seconds_by_index[index])

        edges = [
            (fact_keys[goal], fact_keys[required_fact])
            for required_fact in sorted(requirements[0])
            if required_fact != goal
        ]
        if 0 in seconds_by_index:
            tree.mark_required_seconds(goal, tree.GOAL_VARIANT, seconds_by_index[0])
        for fact, proofs in proofs_by_fact.items():
            fact_key = fact_keys[fact]
            for index in proofs.values():
                proof_key = proof_keys[index]
                if fact_key != proof_key:
                    edges.append((fact_key, proof_key))
                for required_fact in sorted(requirements[index]):
                    required_key = fact_keys[required_fact]
                    if proof_key != required_key:
                        edges.append((proof_key, required_key))
        tree.edges = list(dict.fromkeys(edges))

        return tree
