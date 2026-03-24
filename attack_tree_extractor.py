#!/usr/bin/env python3
"""
Attack Tree Extractor - Refactored CLI

Runs ProVerif on scenario files and extracts clauses and derivations
from the console output to build attack trees. Can render derivations
as graphviz diagrams.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from src.attack_tree import (
    AttackTreeExtractor,
    CapabilityAnalyzer,
    GraphvizRenderer,
)


def _normalize_query_text(query: str) -> str:
    """Normalize query text for robust exact matching across formats."""
    if not query:
        return ""

    normalized = re.sub(r"\(\*.*?\*\)", "", query)
    normalized = normalized.strip().lower()
    normalized = normalized.replace("query ", "")
    normalized = normalized.replace("\n", "")
    normalized = normalized.replace(" ", "")
    normalized = normalized.replace("[", "").replace("]", "")
    normalized = normalized.replace(";", "").replace(".", "")
    return normalized


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Extract clauses and derivations from ProVerif output. Optionally render derivations as graphviz trees.",
    )
    parser.add_argument("files", nargs="*", help="ProVerif scenario files (.pv)")
    parser.add_argument(
        "--graphviz-dot",
        metavar="DIR",
        help="Output directory for graphviz dot files",
    )
    parser.add_argument(
        "--graphviz-pdf",
        metavar="DIR",
        help="Output directory for graphviz PDF files (requires graphviz installed)",
    )
    parser.add_argument(
        "--no-summary",
        action="store_true",
        help="Skip printing the summary to console",
    )
    parser.add_argument(
        "--manifest",
        metavar="FILE",
        help="Manifest.json file for capability analysis (annotates attack trees with capabilities)",
    )
    parser.add_argument(
        "--original-terms",
        action="store_true",
        help="Use original ProVerif syntax for node labels (default is human-readable format)",
    )
    parser.add_argument(
        "--query",
        metavar="INDEX",
        type=int,
        help="Select which query to visualize (1=first, 2=second, etc.) matching ProVerif numbering",
    )
    parser.add_argument(
        "--show-clause-ids",
        action="store_true",
        help="Include ProVerif clause IDs in node labels",
    )

    args = parser.parse_args()

    if not args.files and not args.manifest:
        print("Usage: python3 attack_tree_extractor_refactored.py <scenario_file.pv> [scenario_file2.pv ...]")
        print("\nOptions:")
        print("  --graphviz-dot DIR      Output graphviz dot files to DIR")
        print("  --graphviz-pdf DIR      Output graphviz PDF files to DIR (requires graphviz)")
        print("  --no-summary            Skip printing the summary")
        print("  --manifest FILE         Use manifest.json for capability analysis")
        print("  --original-terms        Use original ProVerif syntax for node labels")
        print("  --query INDEX           Select query by index when multiple queries exist (1=first)")
        print("  --show-clause-ids       Include ProVerif clause IDs in node labels")
        print("\nExamples:")
        print("  # Basic extraction")
        print("  python3 attack_tree_extractor_refactored.py scenario.pv --graphviz-pdf output/")
        print("\n  # With capability analysis")
        print("  python3 attack_tree_extractor_refactored.py --manifest _scenarios/hashed_passwords/manifest.json \\")
        print("      _scenarios/hashed_passwords/*.pv --graphviz-pdf annotated/")
        print("\n  # Select specific query (if multiple exist)")
        print("  python3 attack_tree_extractor_refactored.py scenario.pv --query 1 --graphviz-pdf output/")
        sys.exit(1)

    if not args.manifest and args.files:
        manifest_candidate = Path(args.files[0]).parent / "manifest.json"
        if manifest_candidate.exists():
            args.manifest = str(manifest_candidate)

    # Create output directories if needed
    dot_dir = None
    pdf_dir = None
    if args.graphviz_dot:
        dot_dir = Path(args.graphviz_dot)
        dot_dir.mkdir(parents=True, exist_ok=True)
    if args.graphviz_pdf:
        pdf_dir = Path(args.graphviz_pdf)
        pdf_dir.mkdir(parents=True, exist_ok=True)

    extractor = AttackTreeExtractor()
    renderer = GraphvizRenderer()

    # Capability analysis setup
    capability_analyzer = None
    manifest_data = None
    capability_costs = {}  # Initialize capability costs (empty if no manifest)
    if args.manifest:
        manifest_path = Path(args.manifest)
        if not manifest_path.exists():
            print(f"Error: Manifest file not found: {manifest_path}")
            sys.exit(1)

        print(f"\n{'='*60}")
        print("Capability Analysis")
        print(f"{'='*60}")
        print(f"Analyzing capabilities from: {manifest_path}")

        # Load manifest data for query tag lookup and capability costs
        with open(manifest_path) as f:
            manifest_data = json.load(f)

        # Extract capability costs from all scenarios in manifest
        capability_costs = {}
        for scenario in manifest_data.get("scenarios", []):
            for cap_info in scenario.get("capabilities", []):
                cap_name = cap_info.get("name")
                costs = cap_info.get("costs", {})
                if cap_name and costs:
                    # Store the costs (overwriting duplicates is fine, they should be the same)
                    capability_costs[cap_name] = costs

        capability_analyzer = CapabilityAnalyzer(capability_costs)
        capability_analyzer.analyze_from_manifest(manifest_path)
        print()

    for scenario_path in args.files:
        scenario_file = Path(scenario_path)
        output = extractor.extract(scenario_file, verbose_clauses=True)

        if capability_analyzer:
            capability_analyzer.update_capability_clause_numbers_from_output(output)

        # Handle multiple queries: filter derivations if --query specified
        if output.derivations:
            # Collect unique queries from derivations by canonical form
            unique_queries = []
            canonical_to_display = {}
            for deriv in output.derivations:
                if deriv.query:
                    canonical = _normalize_query_text(deriv.query)
                    if canonical and canonical not in canonical_to_display:
                        canonical_to_display[canonical] = deriv.query
                        unique_queries.append(canonical)

            # Validate --query argument if provided
            if args.query is not None:
                # User explicitly requested a query index (1-based, like ProVerif)
                if args.query < 1 or args.query > len(unique_queries):
                    print(f"Error: --query {args.query} out of range.")
                    if unique_queries:
                        print(f"Available queries (1-{len(unique_queries)}):")
                        for i, q in enumerate(unique_queries):
                            print(f"  {i + 1}: {canonical_to_display[q]}")
                    else:
                        print("No queries found in derivations!")
                    continue
                # Select the requested query
                selected_canonical = unique_queries[args.query - 1]
                output.derivations = [
                    d
                    for d in output.derivations
                    if _normalize_query_text(d.query or "") == selected_canonical
                ]
                output.query = canonical_to_display[selected_canonical]
                if not args.no_summary:
                    print(f"Selected query {args.query}: {output.query}")

            # If multiple queries and user didn't specify one
            elif len(unique_queries) > 1:
                # Multiple queries found, inform user
                if not args.no_summary:
                    print(f"\nWarning: Multiple queries found ({len(unique_queries)} total).")
                    print("Available queries:")
                    for i, q in enumerate(unique_queries):
                        print(f"  {i + 1}: {canonical_to_display[q]}")
                    print(f"Using first query. To select another, use: --query <index>")
                # Use first query by default
                selected_canonical = unique_queries[0]
                output.derivations = [
                    d
                    for d in output.derivations
                    if _normalize_query_text(d.query or "") == selected_canonical
                ]
                output.query = canonical_to_display[selected_canonical]

            elif len(unique_queries) == 1:
                # Single query, update output.query if not already set
                if not output.query:
                    output.query = canonical_to_display[unique_queries[0]]

        if not args.no_summary:
            extractor.print_summary(output)

        # Generate graphviz files if requested
        if output.derivations:
            # Try to find a query tag from manifest
            query_tag = None
            if manifest_data and output.query:
                # Try multiple scenario name variations (for cost-annotated files)
                scenario_name = scenario_file.name
                # Strip cost annotations like ___100_time_ to find base scenario
                base_scenario_name = scenario_name
                base_scenario_name = re.sub(r"___\d+_\w+_", "", base_scenario_name)

                # Try to find matching scenario in manifest
                matching_scenarios = []
                for scenario in manifest_data.get("scenarios", []):
                    if scenario.get("file") in [scenario_name, base_scenario_name]:
                        matching_scenarios.append(scenario)

                # If no exact match, try to find any scenario with similar name
                if not matching_scenarios:
                    for scenario in manifest_data.get("scenarios", []):
                        scenario_file_base = scenario.get("file", "").replace(".pv", "")
                        our_file_base = base_scenario_name.replace(".pv", "")
                        # Remove cost annotations for comparison
                        scenario_file_base = re.sub(r"___\d+_\w+_", "", scenario_file_base)
                        if scenario_file_base in our_file_base or our_file_base in scenario_file_base:
                            matching_scenarios.append(scenario)

                # Search for matching query in all candidate scenarios
                for scenario in matching_scenarios:
                    for query_info in scenario.get("queries", []):
                        query_text = query_info.get("query", "")

                        normalized_manifest = _normalize_query_text(query_text)
                        normalized_output = _normalize_query_text(output.query)

                        # Require canonical exact match to bind the correct query tag
                        if normalized_output and normalized_output == normalized_manifest:
                            tag = query_info.get("tag", "")
                            # Prefer meaningful tags over generic "query" tag
                            if tag and tag != "query":
                                query_tag = tag
                                break
                            elif tag == "query" and not query_tag:
                                # Use generic tag as fallback
                                comment_match = re.search(r"\(\*\s*([^*]+?)\s*\*\)", query_text)
                                if comment_match:
                                    query_tag = comment_match.group(1).strip()
                    if query_tag and query_tag != "query":
                        break

            # If no tag from manifest, extract a short version of the query
            if not query_tag and output.query:
                # Use a simplified version: just show what's being queried
                match = re.search(r"(not\s+)?(\w+)\(", output.query)
                if match:
                    negation = "not " if match.group(1) else ""
                    predicate = match.group(2)
                    query_tag = f"{negation}{predicate}(...)"
                else:
                    # Truncate long queries
                    query_tag = (
                        output.query[:50] + "..."
                        if len(output.query) > 50
                        else output.query
                    )

            # Use readable nodes by default, unless --original-terms is specified
            use_readable = not args.original_terms
            tree = renderer.build_tree_from_derivations(
                output.derivations,
                query_tag,
                capability_costs,
                use_readable,
                args.show_clause_ids,
            )
            if tree:
                # Annotate with capabilities if analyzer is available
                if capability_analyzer:
                    tree = capability_analyzer.annotate_tree_with_capabilities(
                        tree, scenario_file
                    )

                base_name = scenario_file.stem

                if dot_dir:
                    dot_file = dot_dir / f"{base_name}_derivation.dot"
                    renderer.render_to_file(tree, dot_file)

                if pdf_dir:
                    pdf_file = pdf_dir / f"{base_name}_derivation"
                    renderer.render_to_pdf(tree, pdf_file)


if __name__ == "__main__":
    main()
