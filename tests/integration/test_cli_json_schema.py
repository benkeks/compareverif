"""Integration tests for CLI JSON output schema validation."""

import json
import tempfile
from pathlib import Path
from unittest import mock

from compareverif.attack_tree.models import DerivationTree
from compareverif.attack_tree.renderer import GraphvizRenderer


def test_cli_json_output_schema():
    """Test that CLI JSON output has the required schema structure and fields."""
    # Create a minimal test tree
    tree = DerivationTree(
        goal="attacker(test_fact)",
        query_tag="test_query",
        readable_nodes=True,
        show_clause_ids=False,
        highlight_attack=False,
    )
    
    # Add a simple derivation: goal -> fact -> capability
    goal_key = ("attacker(test_fact)", None)
    fact_key = ("attacker(source)", None)
    cap_key = ("Capability", "capability_leaf::base::1::1::Capability")
    
    tree.add_node(*goal_key, node_type="fact")
    tree.add_node(*fact_key, node_type="fact")
    tree.add_node(*cap_key, node_type="capability", capabilities={"Test Capability"})
    
    tree.add_edge(goal_key, fact_key)
    tree.add_edge(fact_key, cap_key)
    
    # Register the capability cost
    tree.capability_costs["Test Capability"] = {"complexity": 5}
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)
        json_file = output_dir / "test_derivation.json"
        
        # Render JSON
        GraphvizRenderer.render_to_json(tree, json_file)
        
        # Load and validate JSON structure
        with open(json_file) as f:
            tree_data = json.load(f)
        
        # Validate top-level structure
        assert "meta" in tree_data, "Missing 'meta' field in JSON"
        assert "nodes" in tree_data, "Missing 'nodes' field in JSON"
        
        # Validate meta structure
        meta = tree_data["meta"]
        assert "schema_version" in meta, "Missing 'schema_version' in meta"
        assert meta["schema_version"] == "1.0", f"Expected schema_version 1.0, got {meta['schema_version']}"
        assert "goal" in meta, "Missing 'goal' in meta"
        assert "query_tag" in meta, "Missing 'query_tag' in meta"
        assert "readable_nodes" in meta, "Missing 'readable_nodes' in meta"
        assert "show_clause_ids" in meta, "Missing 'show_clause_ids' in meta"
        assert "highlight_attack" in meta, "Missing 'highlight_attack' in meta"
        
        # Validate nodes structure
        nodes = tree_data["nodes"]
        assert isinstance(nodes, list), "nodes must be a list"
        assert len(nodes) > 0, "nodes list is empty"
        
        # Validate each node has required fields
        for node in nodes:
            assert "id" in node, f"Missing 'id' field in node {node}"
            assert "node_type" in node, f"Missing 'node_type' field in node {node['id']}"
            assert "fact" in node, f"Missing 'fact' field in node {node['id']}"
            assert "depends_on_all" in node, f"Missing 'depends_on_all' field in node {node['id']}"
            assert "depends_on_any" in node, f"Missing 'depends_on_any' field in node {node['id']}"
            
            # Validate depends_on fields are lists
            assert isinstance(node["depends_on_all"], list), f"depends_on_all must be a list in node {node['id']}"
            assert isinstance(node["depends_on_any"], list), f"depends_on_any must be a list in node {node['id']}"
            
            # Validate capability nodes have costs
            if node["node_type"] == "capability":
                assert "costs" in node, f"Missing 'costs' field in capability node {node['id']}"
                assert isinstance(node["costs"], dict), f"costs must be a dict in node {node['id']}"


def test_cli_json_output_with_highlight():
    """Test JSON output schema when highlight mode is enabled."""
    # Create a test tree with highlight mode
    tree = DerivationTree(
        goal="attacker(target)",
        query_tag="test_query",
        readable_nodes=True,
        show_clause_ids=False,
        highlight_attack=True,
    )
    
    # Add nodes
    goal_key = ("attacker(target)", None)
    fact_key = ("attacker(source)", None)
    cap_key = ("Capability", "capability_leaf::base::1::1::Capability")
    
    tree.add_node(*goal_key, node_type="fact")
    tree.add_node(*fact_key, node_type="fact")
    tree.add_node(*cap_key, node_type="capability", capabilities={"Test Capability"})
    
    tree.add_edge(goal_key, fact_key)
    tree.add_edge(fact_key, cap_key)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        output_dir = Path(tmpdir)
        json_file = output_dir / "test_derivation.json"
        
        # Render JSON
        GraphvizRenderer.render_to_json(tree, json_file)
        
        # Load and validate
        with open(json_file) as f:
            tree_data = json.load(f)
        
        # Validate schema_version is present with highlight mode
        assert tree_data["meta"]["schema_version"] == "1.0"
        assert tree_data["meta"]["highlight_attack"] is True
        
        # Validate all required node fields are present
        for node in tree_data["nodes"]:
            assert "depends_on_all" in node
            assert "depends_on_any" in node

