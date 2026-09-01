"""Parse optional UPPAAL configuration pragmas from ProVerif comments."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass

import yaml

_UPPAAL_PRAGMA_RE = re.compile(r"\(\*\s*UPPAAL\s*\n(?P<content>.*?)\*\)", re.DOTALL)
_SUPPORTED_FIELDS = {"non_blocking_channels", "time_channels"}


class UnknownUppaalPragmaWarning(UserWarning):
    """Warn when an UPPAAL pragma contains a field the translator does not support."""


@dataclass(frozen=True)
class UppaalPragmas:
    """Translator configuration extracted from ``(* UPPAAL ... *)`` comments."""

    non_blocking_channels: list[str]
    time_channels: list[str]


def parse_uppaal_pragmas(source: str) -> UppaalPragmas:
    """Parse UPPAAL YAML comment blocks, retaining defaults for omitted supported fields."""
    values: dict[str, list[str]] = {
        "non_blocking_channels": ["leak"],
        "time_channels": ["tick"],
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
        for field in _SUPPORTED_FIELDS & parsed.keys():
            channels = parsed[field]
            if not isinstance(channels, list) or not all(isinstance(channel, str) for channel in channels):
                raise ValueError(f"UPPAAL pragma field {field!r} must be a list of channel names")
            values[field] = channels
    return UppaalPragmas(**values)