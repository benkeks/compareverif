"""Shared formatting utilities."""


def print_headline(title: str, char: str = '=', width: int = 60) -> None:
    """Print a formatted headline."""
    border = char * width
    print(f"\n{border}")
    print(title)
    print(border)


def print_subheading(title: str, char: str = '-', width: int = 60) -> None:
    """Print a formatted subheading."""
    print(title)
    print(char * width)
