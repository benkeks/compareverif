"""Pareto front comparison helpers for scenario analyses and manifests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import matplotlib.pyplot as plt

from .analyzer import analyze_minimal_false_combinations
from compareverif.common import QuerySelectionOption, resolve_query_selector
from .generator import create_scenario_filename
from .models import ScenarioFile, ScenarioResult
from .parser import extract_attacker_capabilities


@dataclass(frozen=True)
class ParetoPoint:
    """One point on a projected Pareto front."""

    scenarios: Tuple[str, ...]
    label: str
    costs: Dict[str, float]


class ParetoFrontRenderer:
    """Render Pareto-front comparisons from scenario analysis results."""

    DEFAULT_MODEL_STYLES: Dict[str, Dict[str, str]] = {
        "hashed_passwords": {"color": "forestgreen", "label": "hashed_passwords"},
        "singularized_passwords": {"color": "darkviolet", "label": "singularized_passwords"},
    }
    PREFERRED_COST_DIMENSIONS: Tuple[str, ...] = ("time", "hack")

    def __init__(
        self,
        analysis: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
        *,
        input_labels: Optional[Mapping[str, str]] = None,
        query_order: Optional[Sequence[str]] = None,
        cost_dimensions: Optional[Sequence[str]] = None,
        scenario_aliases: Optional[Mapping[str, str]] = None,
        model_styles: Optional[Mapping[str, Mapping[str, str]]] = None,
    ) -> None:
        self.analysis = {
            str(input_name): {
                str(query_tag): [dict(combo) for combo in combinations]
                for query_tag, combinations in queries.items()
            }
            for input_name, queries in analysis.items()
        }
        self.input_labels = {
            input_name: input_labels.get(input_name, Path(input_name).stem)
            if input_labels
            else Path(input_name).stem
            for input_name in self.analysis
        }
        self.query_order = list(query_order or self._discover_query_order())
        self.cost_dimensions = self._ordered_cost_dimensions(
            cost_dimensions or self._discover_cost_dimensions()
        )
        self.scenario_aliases = {
            self._normalize_scenario_name(name): label
            for name, label in (scenario_aliases or {}).items()
        }
        self.model_styles = {
            **self.DEFAULT_MODEL_STYLES,
            **(model_styles or {}),
        }

    @classmethod
    def from_analysis(
        cls,
        analysis: Mapping[str, Mapping[str, Sequence[Mapping[str, Any]]]],
        **kwargs: Any,
    ) -> "ParetoFrontRenderer":
        """Build a renderer directly from `ScenarioPreprocessor.analyze()` output."""
        return cls(analysis, **kwargs)

    @classmethod
    def from_manifest_inputs(
        cls,
        inputs: Sequence[str | Path],
        **kwargs: Any,
    ) -> "ParetoFrontRenderer":
        """Build a renderer from manifest files or directories containing manifests."""
        manifest_paths = cls.resolve_manifest_paths(inputs)

        results: List[ScenarioResult] = []
        input_files: List[str] = []
        input_labels: Dict[str, str] = {}
        query_order: List[str] = []
        cost_dimensions: List[str] = []
        capabilities_by_input = {}

        for manifest_path in manifest_paths:
            with manifest_path.open("r", encoding="utf-8") as handle:
                manifest = json.load(handle)

            input_file = str(manifest.get("input_file") or manifest_path.parent.name)
            input_files.append(input_file)
            input_labels[input_file] = Path(input_file).stem
            input_path = Path(input_file)
            if input_path.exists():
                with input_path.open("r", encoding="utf-8") as handle:
                    content = handle.read()
                capabilities, _ = extract_attacker_capabilities(content)
                if capabilities:
                    for capability in capabilities:
                        capability.primary_name = create_scenario_filename([capability.primary_name])
                    capabilities_by_input[input_file] = capabilities

            for scenario_entry in manifest.get("scenarios", []):
                queries = list(scenario_entry.get("queries", []))
                for query in queries:
                    tag = str(query.get("tag", "")).strip()
                    if tag and tag not in query_order:
                        query_order.append(tag)

                total_costs = dict(scenario_entry.get("total_costs", {}))
                for dimension in total_costs:
                    if dimension not in cost_dimensions:
                        cost_dimensions.append(dimension)

                verification = scenario_entry.get("verification") or {}
                query_results = verification.get("query_results")
                if not query_results:
                    query_results = [
                        {"tag": query.get("tag", ""), "result": None}
                        for query in queries
                    ]

                scenario = ScenarioFile(
                    path=Path(scenario_entry.get("path") or scenario_entry.get("file") or manifest_path),
                    capabilities=[],
                    costs=total_costs,
                    queries=queries,
                    capability_names=cls._scenario_names_from_manifest_entry(scenario_entry),
                )
                results.append(
                    ScenarioResult(
                        scenario=scenario,
                        status=verification.get("status"),
                        query_results=list(query_results),
                        error_message=verification.get("error_message"),
                    )
                )

        analysis = analyze_minimal_false_combinations(
            results,
            input_files,
            capabilities_by_input=capabilities_by_input or None,
        )
        return cls(
            analysis,
            input_labels=input_labels,
            query_order=query_order,
            cost_dimensions=cls._ordered_cost_dimensions(cost_dimensions),
            **kwargs,
        )

    @staticmethod
    def resolve_manifest_paths(inputs: Sequence[str | Path]) -> List[Path]:
        """Resolve CLI-style manifest inputs to concrete manifest paths."""
        manifest_paths: List[Path] = []

        for raw_input in inputs:
            path = Path(raw_input)
            manifest_path = path / "manifest.json" if path.is_dir() else path
            if manifest_path.name != "manifest.json":
                raise ValueError(f"Expected a manifest.json file or directory, got: {path}")
            if not manifest_path.exists():
                raise ValueError(f"Manifest not found: {manifest_path}")
            manifest_paths.append(manifest_path)

        if not manifest_paths:
            raise ValueError("At least one manifest input is required.")

        return manifest_paths

    def available_queries(self) -> List[str]:
        """Return query tags in stable discovery order."""
        return list(self.query_order)

    def available_cost_dimensions(self) -> List[str]:
        """Return cost dimensions in stable discovery order."""
        return list(self.cost_dimensions)

    def resolve_queries(self, query: Optional[str | int] = None) -> List[str]:
        """Resolve a query selector to concrete query tags."""
        options = [
            QuerySelectionOption(name=query_tag, value=query_tag)
            for query_tag in self.query_order
        ]
        return [option.value for option in resolve_query_selector(options, query)]

    def resolve_cost_dimensions(
        self,
        costs: Optional[Sequence[str] | str] = None,
    ) -> Tuple[str, str]:
        """Resolve a 2D cost selection for plotting."""
        if costs is None:
            if len(self.cost_dimensions) < 2:
                raise ValueError(
                    "At least two cost dimensions are required for a 2D Pareto plot."
                )
            return self.cost_dimensions[0], self.cost_dimensions[1]

        if isinstance(costs, str):
            selected_costs = [part.strip() for part in costs.split(",") if part.strip()]
        else:
            selected_costs = [str(part).strip() for part in costs if str(part).strip()]

        if len(selected_costs) != 2:
            raise ValueError("Exactly two cost dimensions are required, e.g. --costs=time,hack")

        missing = [dimension for dimension in selected_costs if dimension not in self.cost_dimensions]
        if missing:
            raise ValueError(
                f"Unknown cost dimensions {missing}; available dimensions: {self.cost_dimensions}"
            )

        return selected_costs[0], selected_costs[1]

    def get_front_points(
        self,
        query: str | int,
        *,
        costs: Optional[Sequence[str] | str] = None,
    ) -> Dict[str, List[ParetoPoint]]:
        """Return projected 2D Pareto fronts per model for one query."""
        resolved_query = self.resolve_queries(query)
        if len(resolved_query) != 1:
            raise ValueError("get_front_points expects a single query selector.")

        x_dim, y_dim = self.resolve_cost_dimensions(costs)
        query_tag = resolved_query[0]
        fronts: Dict[str, List[ParetoPoint]] = {}

        for input_name, queries in self.analysis.items():
            model_label = self.input_labels[input_name]
            combinations = queries.get(query_tag, [])
            projected_points = [
                ParetoPoint(
                    scenarios=tuple(sorted(combo.get("scenarios", []))),
                    label=self._format_combo_label(combo.get("scenarios", [])),
                    costs={
                        x_dim: float(combo.get("costs", {}).get(x_dim, 0)),
                        y_dim: float(combo.get("costs", {}).get(y_dim, 0)),
                    },
                )
                for combo in combinations
            ]
            reduced = self._reduce_points(projected_points, x_dim, y_dim)
            if reduced:
                fronts[model_label] = reduced

        return fronts

    def plot_query(
        self,
        query: str | int,
        *,
        costs: Optional[Sequence[str] | str] = None,
        ax=None,
        axis_limits: Optional[Tuple[Tuple[float, float], Tuple[float, float]]] = None,
        title: Optional[str] = None,
        annotate: bool = True,
        annotation_offsets: Optional[Mapping[str, Tuple[int, int]]] = None,
        fill_alpha: float = 0.14,
    ):
        """Render a single-query Pareto-front comparison."""
        resolved_query = self.resolve_queries(query)
        if len(resolved_query) != 1:
            raise ValueError("plot_query expects a single query selector.")

        query_tag = resolved_query[0]
        x_dim, y_dim = self.resolve_cost_dimensions(costs)
        fronts = self.get_front_points(query_tag, costs=(x_dim, y_dim))
        if not fronts:
            raise ValueError(f"No Pareto-front points available for query {query_tag!r}.")

        figure = None
        if ax is None:
            figure, ax = plt.subplots(figsize=(10, 6))
        else:
            figure = ax.figure

        x_limits, y_limits = axis_limits or self._default_axis_limits(fronts, x_dim, y_dim)
        legend_handles = []

        for model_index, model_label in enumerate(self._ordered_front_labels(fronts)):
            points = fronts[model_label]
            style = self._style_for_model(model_label, model_index)
            color = style["color"]
            offset = (annotation_offsets or {}).get(
                model_label,
                (8, 8 if model_index % 2 == 0 else -16),
            )

            boundary_x, boundary_y = self._build_stair_boundary(
                points,
                x_dim=x_dim,
                y_dim=y_dim,
                x_max=x_limits[1],
                y_max=y_limits[1],
            )
            polygon_x = [points[0].costs[x_dim], *boundary_x[1:], x_limits[1], points[0].costs[x_dim]]
            polygon_y = [points[0].costs[y_dim], *boundary_y[1:], y_limits[1], y_limits[1]]

            ax.fill(polygon_x, polygon_y, color=color, alpha=fill_alpha)
            ax.plot(boundary_x, boundary_y, color=color, linewidth=3, solid_capstyle="round")
            ax.scatter(
                [point.costs[x_dim] for point in points],
                [point.costs[y_dim] for point in points],
                color=color,
                s=90,
                zorder=3,
            )

            if annotate:
                for point in points:
                    ax.scatter(
                        point.costs[x_dim],
                        point.costs[y_dim],
                        color=color,
                        edgecolor="black",
                        linewidth=0.8,
                        s=130,
                        zorder=4,
                    )
                    ax.annotate(
                        point.label,
                        (point.costs[x_dim], point.costs[y_dim]),
                        xytext=offset,
                        textcoords="offset points",
                        fontsize=10,
                        bbox={
                            "boxstyle": "round,pad=0.2",
                            "facecolor": "white",
                            "alpha": 0.8,
                            "edgecolor": "none",
                        },
                    )

            legend_handles.append(
                plt.Line2D(
                    [0],
                    [0],
                    color=color,
                    linewidth=3,
                    marker="o",
                    markersize=8,
                    label=style["label"],
                )
            )

        ax.set_title(title or f"Pareto Fronts for `{query_tag}`")
        ax.set_xlabel(x_dim)
        ax.set_ylabel(y_dim)
        ax.set_xlim(*x_limits)
        ax.set_ylim(*y_limits)
        ax.grid(True, alpha=0.3)
        ax.legend(handles=legend_handles, loc="upper left")

        return figure, ax

    def plot_queries(
        self,
        *,
        query: Optional[str | int] = None,
        costs: Optional[Sequence[str] | str] = None,
        show: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Render one figure per selected query."""
        figures = {}
        for query_tag in self.resolve_queries(query):
            figures[query_tag] = self.plot_query(query_tag, costs=costs, **kwargs)

        if show:
            plt.show()

        return figures

    def _discover_query_order(self) -> List[str]:
        query_order: List[str] = []
        for queries in self.analysis.values():
            for query_tag in queries:
                if query_tag not in query_order:
                    query_order.append(query_tag)
        return query_order

    def _discover_cost_dimensions(self) -> List[str]:
        dimensions: List[str] = []
        for queries in self.analysis.values():
            for combinations in queries.values():
                for combo in combinations:
                    for dimension in combo.get("costs", {}):
                        if dimension not in dimensions:
                            dimensions.append(dimension)
        return self._ordered_cost_dimensions(dimensions)

    @classmethod
    def _ordered_cost_dimensions(cls, dimensions: Sequence[str]) -> List[str]:
        ordered: List[str] = []
        for dimension in cls.PREFERRED_COST_DIMENSIONS:
            if dimension in dimensions and dimension not in ordered:
                ordered.append(dimension)
        for dimension in dimensions:
            if dimension not in ordered:
                ordered.append(dimension)
        return ordered

    def _ordered_front_labels(self, fronts: Mapping[str, List[ParetoPoint]]) -> List[str]:
        ordered = []
        for input_name in self.analysis:
            label = self.input_labels[input_name]
            if label in fronts:
                ordered.append(label)
        return ordered

    def _style_for_model(self, model_label: str, model_index: int) -> Dict[str, str]:
        if model_label in self.model_styles:
            return dict(self.model_styles[model_label])

        cycle = plt.rcParams["axes.prop_cycle"].by_key().get("color", ["C0"])
        return {
            "color": cycle[model_index % len(cycle)],
            "label": model_label,
        }

    @staticmethod
    def _reduce_points(
        points: Sequence[ParetoPoint],
        x_dim: str,
        y_dim: str,
    ) -> List[ParetoPoint]:
        reduced: List[ParetoPoint] = []

        for point in points:
            dominated = False
            for other in points:
                if other is point:
                    continue
                if ParetoFrontRenderer._point_dominates(other, point, x_dim, y_dim):
                    dominated = True
                    break

            if not dominated and point not in reduced:
                reduced.append(point)

        return sorted(reduced, key=lambda point: (point.costs[x_dim], -point.costs[y_dim], point.label))

    @staticmethod
    def _point_dominates(left: ParetoPoint, right: ParetoPoint, x_dim: str, y_dim: str) -> bool:
        left_x = left.costs[x_dim]
        left_y = left.costs[y_dim]
        right_x = right.costs[x_dim]
        right_y = right.costs[y_dim]

        return (
            left_x <= right_x
            and left_y <= right_y
            and (left_x < right_x or left_y < right_y)
        )

    @staticmethod
    def _build_stair_boundary(
        points: Sequence[ParetoPoint],
        *,
        x_dim: str,
        y_dim: str,
        x_max: float,
        y_max: float,
    ) -> Tuple[List[float], List[float]]:
        boundary_x = [points[0].costs[x_dim], points[0].costs[x_dim]]
        boundary_y = [y_max, points[0].costs[y_dim]]

        for index, point in enumerate(points):
            next_x = points[index + 1].costs[x_dim] if index + 1 < len(points) else x_max
            boundary_x.append(next_x)
            boundary_y.append(point.costs[y_dim])
            if index + 1 < len(points):
                boundary_x.append(next_x)
                boundary_y.append(points[index + 1].costs[y_dim])

        return boundary_x, boundary_y

    @staticmethod
    def _default_axis_limits(
        fronts: Mapping[str, Sequence[ParetoPoint]],
        x_dim: str,
        y_dim: str,
    ) -> Tuple[Tuple[float, float], Tuple[float, float]]:
        x_max = max(point.costs[x_dim] for points in fronts.values() for point in points)
        y_max = max(point.costs[y_dim] for points in fronts.values() for point in points)
        x_upper = ParetoFrontRenderer._nice_upper_bound(x_max)
        y_upper = ParetoFrontRenderer._nice_upper_bound(y_max)
        return (0.0, x_upper), (0.0, y_upper)

    @staticmethod
    def _nice_upper_bound(value: float) -> float:
        if value <= 0:
            return 1.0
        margin = max(value * 0.05, 1.0)
        upper = value + margin
        if upper <= 10:
            return float(int(upper + 0.9999))
        magnitude = 10 ** max(len(str(int(upper))) - 1, 0)
        return float(((int(upper) + magnitude - 1) // magnitude) * magnitude)

    def _format_combo_label(self, scenario_names: Iterable[str]) -> str:
        ordered = []
        for scenario_name in sorted(scenario_names):
            normalized = self._normalize_scenario_name(str(scenario_name))
            ordered.append(self.scenario_aliases.get(normalized, normalized.replace("_", "-")))
        return "+".join(ordered) if ordered else "base"

    @staticmethod
    def _normalize_scenario_name(name: str) -> str:
        return name.strip().lower().replace(" ", "_").replace("-", "_")

    @staticmethod
    def _scenario_names_from_manifest_entry(scenario_entry: Mapping[str, Any]) -> List[str]:
        capability_names = scenario_entry.get("capability_names")
        if capability_names:
            return [str(name) for name in capability_names]

        file_name = str(scenario_entry.get("file", ""))
        stem = Path(file_name).stem
        stem = re.sub(r"___\d+_\w+_", "", stem)
        if stem == "base_scenario":
            return []
        return [part for part in stem.split("+") if part]
