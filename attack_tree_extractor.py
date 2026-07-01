#!/usr/bin/env python3
"""
Attack Tree Extractor

Runs ProVerif on scenario files and extracts clauses and derivations
from the console output to build attack trees. Can render derivations
as graphviz diagrams.
"""

import argparse
import json
import re
import sys
from pathlib import Path

from compareverif.common import QuerySelectionOption, normalize_query_text, resolve_query_selector
from compareverif.attack_tree import (
    AttackTreeExtractor,
    CapabilityAnalyzer,
    GraphvizRenderer,
)


def _describe_query(query: str) -> str:
    """Build a short user-facing query name when no manifest tag exists."""
    match = re.search(r"(not\s+)?(\w+)\(", query)
    if match:
        negation = "not " if match.group(1) else ""
        predicate = match.group(2)
        return f"{negation}{predicate}(...)"

    return query[:50] + "..." if len(query) > 50 else query


def _find_matching_manifest_scenarios(manifest_data, scenario_file: Path):
    """Find manifest scenarios corresponding to one scenario file."""
    if not manifest_data:
        return []

    scenario_name = scenario_file.name
    base_scenario_name = re.sub(r"___\d+_\w+_", "", scenario_name)
    matching_scenarios = []

    for scenario in manifest_data.get("scenarios", []):
        if scenario.get("file") in [scenario_name, base_scenario_name]:
            matching_scenarios.append(scenario)

    if matching_scenarios:
        return matching_scenarios

    for scenario in manifest_data.get("scenarios", []):
        scenario_file_base = scenario.get("file", "").replace(".pv", "")
        our_file_base = base_scenario_name.replace(".pv", "")
        scenario_file_base = re.sub(r"___\d+_\w+_", "", scenario_file_base)
        if scenario_file_base in our_file_base or our_file_base in scenario_file_base:
            matching_scenarios.append(scenario)

    return matching_scenarios


def _query_options_for_output(output, manifest_data, scenario_file: Path):
    """Build ordered query selection options for one ProVerif output."""
    canonical_to_display = {}
    ordered_canonicals = []
    canonical_to_name = {}

    for derivation in output.derivations:
        if not derivation.query:
            continue
        canonical = normalize_query_text(derivation.query)
        if canonical and canonical not in canonical_to_display:
            canonical_to_display[canonical] = derivation.query
            ordered_canonicals.append(canonical)

    for scenario in _find_matching_manifest_scenarios(manifest_data, scenario_file):
        for query_info in scenario.get("queries", []):
            canonical = normalize_query_text(query_info.get("query", ""))
            if not canonical:
                continue
            tag = str(query_info.get("tag", "")).strip()
            if tag and tag != "query":
                canonical_to_name[canonical] = tag
            elif canonical not in canonical_to_name:
                comment_match = re.search(r"\(\*\s*([^*]+?)\s*\*\)", query_info.get("query", ""))
                if comment_match:
                    canonical_to_name[canonical] = comment_match.group(1).strip()

    options = []
    for canonical in ordered_canonicals:
        display_query = canonical_to_display[canonical]
        option_name = canonical_to_name.get(canonical, _describe_query(display_query))
        options.append(
            QuerySelectionOption(
                name=option_name,
                value=canonical,
                aliases=(display_query,),
            )
        )

    return options, canonical_to_display


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
        "--graphviz-svg",
        metavar="DIR",
        help="Output directory for graphviz SVG files (requires graphviz installed)",
    )
    parser.add_argument(
        "--json-out",
        metavar="DIR",
        help="Output directory for plain JSON attack tree dumps",
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
        metavar="QUERY",
        help="Select which query to visualize by 1-based index or query name",
    )
    parser.add_argument(
        "--show-clause-ids",
        action="store_true",
        help="Include ProVerif clause numbers in node labels",
    )
    parser.add_argument(
        "--highlight-attack",
        action="store_true",
        help="Highlight attack-relevant paths and fade less relevant branches",
    )

    args = parser.parse_args()

    if not args.files and not args.manifest:
        print("Usage: python3 attack_tree_extractor.py <scenario_file.pv> [scenario_file2.pv ...]")
        print("\nOptions:")
        print("  --graphviz-dot DIR      Output graphviz dot files to DIR")
        print("  --graphviz-pdf DIR      Output graphviz PDF files to DIR (requires graphviz)")
        print("  --graphviz-svg DIR      Output graphviz SVG files to DIR (requires graphviz)")
        print("  --json-out DIR          Output plain JSON tree dumps to DIR")
        print("  --no-summary            Skip printing the summary")
        print("  --manifest FILE         Use manifest.json for capability analysis")
        print("  --original-terms        Use original ProVerif syntax for node labels")
        print("  --query QUERY           Select query by index or name when multiple queries exist")
        print("  --show-clause-ids       Include ProVerif clause IDs in node labels")
        print("  --highlight-attack      Highlight paths above attack capabilities")
        print("\nExamples:")
        print("  # Basic extraction")
        print("  python3 attack_tree_extractor.py scenario.pv --graphviz-pdf output/")
        print("\n  # With capability analysis")
        print("  python3 attack_tree_extractor.py --manifest _scenarios/hashed_passwords/manifest.json \\")
        print("      _scenarios/hashed_passwords/*.pv --graphviz-pdf annotated/")
        print("\n  # Select specific query (if multiple exist)")
        print("  python3 attack_tree_extractor.py scenario.pv --query 'no pw leakage' --graphviz-pdf output/")
        sys.exit(1)

    if not args.manifest and args.files:
        manifest_candidate = Path(args.files[0]).parent / "manifest.json"
        if manifest_candidate.exists():
            args.manifest = str(manifest_candidate)

    # Create output directories if needed
    dot_dir = None
    pdf_dir = None
    svg_dir = None
    json_dir = None
    if args.graphviz_dot:
        dot_dir = Path(args.graphviz_dot)
        dot_dir.mkdir(parents=True, exist_ok=True)
    if args.graphviz_pdf:
        pdf_dir = Path(args.graphviz_pdf)
        pdf_dir.mkdir(parents=True, exist_ok=True)
    if args.graphviz_svg:
        svg_dir = Path(args.graphviz_svg)
        svg_dir.mkdir(parents=True, exist_ok=True)
    if args.json_out:
        json_dir = Path(args.json_out)
        json_dir.mkdir(parents=True, exist_ok=True)

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

        capability_analyzer = CapabilityAnalyzer.from_manifest(manifest_path)
        capability_costs = capability_analyzer.capability_costs
        print()

    for scenario_path in args.files:
        scenario_file = Path(scenario_path)
        output = extractor.extract(scenario_file, verbose_clauses=True)
        selected_query_option = None

        if capability_analyzer:
            capability_analyzer.update_capability_clause_numbers_from_output(output)

        # Handle multiple queries: filter derivations if --query specified
        if output.derivations:
            query_options, canonical_to_display = _query_options_for_output(
                output,
                manifest_data,
                scenario_file,
            )

            if args.query is not None:
                try:
                    selected_query_option = resolve_query_selector(query_options, args.query)[0]
                except ValueError as exc:
                    print(f"Error: {exc}")
                    if query_options:
                        print("Available queries:")
                        for index, option in enumerate(query_options, start=1):
                            print(f"  {index}: {option.name}")
                    else:
                        print("No queries found in derivations!")
                    continue

                selected_canonical = selected_query_option.value
                output.derivations = [
                    d
                    for d in output.derivations
                    if normalize_query_text(d.query or "") == selected_canonical
                ]
                output.query = canonical_to_display[selected_canonical]
                if not args.no_summary:
                    print(f"Selected query {args.query}: {selected_query_option.name}")

            elif len(query_options) > 1:
                if not args.no_summary:
                    print(f"\nWarning: Multiple queries found ({len(query_options)} total).")
                    print("Available queries:")
                    for index, option in enumerate(query_options, start=1):
                        print(f"  {index}: {option.name}")
                    print("Using first query. To select another, use: --query <index-or-name>")
                selected_query_option = query_options[0]
                selected_canonical = selected_query_option.value
                output.derivations = [
                    d
                    for d in output.derivations
                    if normalize_query_text(d.query or "") == selected_canonical
                ]
                output.query = canonical_to_display[selected_canonical]

            elif len(query_options) == 1:
                selected_query_option = query_options[0]
                if not output.query:
                    output.query = canonical_to_display[selected_query_option.value]

        if not args.no_summary:
            extractor.print_summary(output)

        # Generate graphviz files if requested
        if output.derivations:
            query_tag = selected_query_option.name if selected_query_option else None
            if not query_tag and output.query:
                query_tag = _describe_query(output.query)

            # Use readable nodes by default, unless --original-terms is specified
            use_readable = not args.original_terms
            tree = renderer.build_tree_from_derivations(
                output.derivations,
                query_tag,
                capability_costs,
                use_readable,
                args.show_clause_ids,
                args.highlight_attack,
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

                if svg_dir:
                    svg_file = svg_dir / f"{base_name}_derivation"
                    renderer.render_to_svg(tree, svg_file)

                if json_dir:
                    json_file = json_dir / f"{base_name}_derivation.json"
                    renderer.render_to_json(tree, json_file)


if __name__ == "__main__":
    main()
