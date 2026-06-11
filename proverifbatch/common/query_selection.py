"""Shared helpers for selecting queries by name or 1-based index."""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Optional, Sequence


def normalize_query_text(query: str) -> str:
    """Normalize query text for robust matching across formats."""
    if not query:
        return ""

    normalized = re.sub(r"\(\*.*?\*\)", "", query)
    normalized = normalized.strip().lower()
    normalized = normalized.replace("query ", "")
    normalized = normalized.replace("weaksecret ", "")
    normalized = normalized.replace("\n", "")
    normalized = normalized.replace(" ", "")
    normalized = normalized.replace("[", "").replace("]", "")
    normalized = normalized.replace(";", "").replace(".", "")
    return normalized


@dataclass(frozen=True)
class QuerySelectionOption:
    """One user-visible query option with an internal selected value."""

    name: str
    value: str
    aliases: tuple[str, ...] = field(default_factory=tuple)


def resolve_query_selector(
    options: Sequence[QuerySelectionOption],
    selector: Optional[str | int] = None,
) -> list[QuerySelectionOption]:
    """Resolve a query selector to one or more query options."""
    ordered_options = list(options)
    if selector is None:
        return ordered_options

    if isinstance(selector, int) or (isinstance(selector, str) and selector.isdigit()):
        index = int(selector) - 1
        if index < 0 or index >= len(ordered_options):
            raise ValueError(
                f"Query index {selector} is out of range; available queries: "
                f"{[option.name for option in ordered_options]}"
            )
        return [ordered_options[index]]

    raw_selector = str(selector).strip()
    normalized_selector = normalize_query_text(raw_selector)

    for option in ordered_options:
        if raw_selector == option.name:
            return [option]
        if normalized_selector and normalize_query_text(option.name) == normalized_selector:
            return [option]
        for alias in option.aliases:
            if raw_selector == alias:
                return [option]
            if normalized_selector and normalize_query_text(alias) == normalized_selector:
                return [option]

    raise ValueError(
        f"Unknown query {selector!r}; available queries: {[option.name for option in ordered_options]}"
    )