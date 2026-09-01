"""Parse optional UPPAAL configuration pragmas from ProVerif comments."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

import yaml

_UPPAAL_PRAGMA_RE = re.compile(r"\(\*\s*UPPAAL\s*\n(?P<content>.*?)\*\)", re.DOTALL)
_SUPPORTED_FIELDS = {"additional_queries", "data_width", "non_blocking_channels", "time_channels"}


class UnknownUppaalPragmaWarning(UserWarning):
    """Warn when an UPPAAL pragma contains a field the translator does not support."""


class InvalidUppaalPragmaError(ValueError):
    """Raised when a supported UPPAAL pragma has an unsupported value."""


@dataclass(frozen=True)
class UppaalPragmas:
    """Translator configuration extracted from ``(* UPPAAL ... *)`` comments."""

    non_blocking_channels: list[str]
    time_channels: list[str]
    additional_queries: list[str]
    data_width: int | None


def parse_uppaal_pragmas(source: str) -> UppaalPragmas:
    """Parse UPPAAL YAML comment blocks, retaining defaults for omitted supported fields."""
    values: dict[str, list[str] | int | None] = {
        "non_blocking_channels": ["leak"],
        "time_channels": ["tick"],
        "additional_queries": [],
        "data_width": None,
    }
    for match in _UPPAAL_PRAGMA_RE.finditer(source):
        parsed = yaml.safe_load(match.group("content")) or {}
        if not isinstance(parsed, dict):
            raise ValueError("UPPAAL pragma must contain a YAML key-value mapping")
        unknown = sorted(set(parsed) - _SUPPORTED_FIELDS)
        if unknown:
            warnings.warn(
                f"Unsupported UPPAAL pragma fields: {', '.join(unknown)}.",
                UnknownUppaalPragmaWarning,
                stacklevel=2,
            )
        if "data_width" in parsed:
            if parsed["data_width"] != 64:
                raise InvalidUppaalPragmaError(
                    "UPPAAL pragma data_width must be 64, the only supported wide-data width."
                )
            values["data_width"] = 64
        for field in {"additional_queries", "non_blocking_channels", "time_channels"} & parsed.keys():
            values_list = parsed[field]
            if not isinstance(values_list, list) or not all(isinstance(value, str) for value in values_list):
                raise ValueError(f"UPPAAL pragma field {field!r} must be a list of strings")
            values[field] = values_list
    return UppaalPragmas(**values)