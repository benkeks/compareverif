#!/usr/bin/env python3
"""Render Pareto-front comparisons from scenario manifests."""

import argparse
import re
import sys
from pathlib import Path

from compareverif.scenarios import ParetoFrontRenderer


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
    parser.add_argument(
        "--out-png",
        metavar="PATH",
        help="Save rendered figure(s) to PNG. For multiple queries, suffixes are added automatically.",
    )
    args = parser.parse_args()

    try:
        renderer = ParetoFrontRenderer.from_manifest_inputs(args.inputs)
        figures = renderer.plot_queries(
            query=args.query,
            costs=args.costs,
            show=args.out_png is None,
        )

        if args.out_png:
            out_path = Path(args.out_png)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            queries = list(figures.keys())

            if len(queries) == 1:
                target = out_path
                figures[queries[0]][0].savefig(target, dpi=150, bbox_inches="tight")
                print(f"Saved Pareto plot: {target}")
            else:
                stem = out_path.stem
                suffix = out_path.suffix or ".png"
                for query_tag, (figure, _) in figures.items():
                    slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(query_tag)).strip("_") or "query"
                    target = out_path.with_name(f"{stem}_{slug}{suffix}")
                    figure.savefig(target, dpi=150, bbox_inches="tight")
                    print(f"Saved Pareto plot: {target}")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()