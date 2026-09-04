"""Small text-parsing helpers shared across ProVerif intermediate-process analyses."""

from __future__ import annotations


def find_matching_paren(text: str, open_index: int) -> int:
    """Return the index of the ")" matching the "(" at open_index."""
    depth = 0
    for index in range(open_index, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return len(text) - 1


def extract_balanced_parens(text: str, open_index: int) -> str:
    """Return the contents between the "(" at open_index and its matching ")"."""
    close_index = find_matching_paren(text, open_index)
    return text[open_index + 1 : close_index]


def split_top_level_commas(text: str) -> list[str]:
    """Split text on commas that are not nested inside parentheses."""
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in text:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return [part.strip() for part in parts if part.strip()]
