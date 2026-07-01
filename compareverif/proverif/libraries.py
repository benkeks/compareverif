"""Helpers for parsing and applying ProVerif -lib directives."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List


_LIB_DIRECTIVE_RE = re.compile(r"-lib\s+([^\s*]+\.pvl)")


def extract_declared_libraries(content: str) -> List[str]:
    """Return unique -lib declarations found in the top-of-file comment area."""
    header = _extract_top_comment_header(content)
    discovered: List[str] = []
    for match in _LIB_DIRECTIVE_RE.finditer(header):
        library = match.group(1).strip()
        if library and library not in discovered:
            discovered.append(library)
    return discovered


def extract_declared_libraries_from_file(file_path: Path) -> List[str]:
    """Read and extract declared libraries from a ProVerif file."""
    try:
        content = file_path.read_text(encoding="utf-8")
    except OSError:
        return []
    return extract_declared_libraries(content)


def append_library_arguments(command: List[str], libraries: Iterable[str]) -> None:
    """Append `-lib <name>` pairs to an existing ProVerif command."""
    seen = set()
    for library in libraries:
        value = str(library).strip()
        if not value or value in seen:
            continue
        seen.add(value)
        command.extend(["-lib", value])


def _extract_top_comment_header(content: str) -> str:
    """Extract leading blank lines/comments before first code token."""
    lines = content.splitlines()
    header_lines: List[str] = []
    in_comment = False

    for line in lines:
        stripped = line.strip()

        if in_comment:
            header_lines.append(line)
            if "*)" in line:
                in_comment = False
            continue

        if not stripped:
            continue

        if stripped.startswith("(*"):
            header_lines.append(line)
            if "*)" not in stripped:
                in_comment = True
            continue

        break

    return "\n".join(header_lines)
