#!/usr/bin/env python3
"""Render Pareto-front comparisons from scenario manifests."""

import argparse
import sys

from proverifbatch.scenarios import ParetoFrontRenderer


def main() -> None:
    """Main entry point for Pareto-front comparisons."""
    parser = argparse.ArgumentParser(
        description=(
            "Render Pareto-front comparisons from scenario manifest.json files "
            "or directories containing them."
        )
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        help="Manifest.json files or directories containing manifest.json",
    )
    parser.add_argument(
        "--costs",
        help="Comma-separated pair of cost dimensions to plot, e.g. --costs=time,hack",
    )
    parser.add_argument(
        "--query",
        help="Query tag or 1-based query number to render",
    )
    args = parser.parse_args()

    try:
        renderer = ParetoFrontRenderer.from_manifest_inputs(args.inputs)
        renderer.plot_queries(
            query=args.query,
            costs=args.costs,
            show=True,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()