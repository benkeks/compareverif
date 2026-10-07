"""Small text-parsing helpers shared across ProVerif intermediate-process analyses."""

from __future__ import annotations

import re


IDENTIFIER_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"
IDENTIFIER_RE = re.compile(IDENTIFIER_PATTERN)


def strip_proverif_comments(source: str) -> str:
    """Replace nested comments with whitespace, preserving lines and quoted strings."""
    characters = list(source)
    index = 0
    depth = 0
    quoted = False
    while index < len(source):
        if depth:
            if source.startswith("(*", index):
                depth += 1
                characters[index:index + 2] = "  "
                index += 2
            elif source.startswith("*)", index):
                depth -= 1
                characters[index:index + 2] = "  "
                index += 2
            else:
                if source[index] != "\n":
                    characters[index] = " "
                index += 1
        elif quoted:
            if source[index] == "\\":
                index += 2
            else:
                if source[index] == '"':
                    quoted = False
                index += 1
        elif source[index] == '"':
            quoted = True
            index += 1
        elif source.startswith("(*", index):
            depth = 1
            characters[index:index + 2] = "  "
            index += 2
        else:
            index += 1
    return "".join(characters)


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


def find_top_level_equality(text: str) -> tuple[str, str] | None:
    """Split at the first equality outside parentheses, or return None."""
    depth = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "=" and depth == 0:
            return text[:index].strip(), text[index + 1 :].strip()
    return None


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
