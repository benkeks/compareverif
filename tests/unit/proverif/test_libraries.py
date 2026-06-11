"""Tests for ProVerif -lib directive parsing helpers."""

from proverifbatch.proverif.libraries import extract_declared_libraries


def test_extract_declared_libraries_from_top_comments_only():
    content = """
(* -lib primitives.pvl *)
(* -lib crypto/extra.pvl *)

new key: bitstring.
(* -lib ignored.pvl *)
"""

    assert extract_declared_libraries(content) == ["primitives.pvl", "crypto/extra.pvl"]


def test_extract_declared_libraries_deduplicates():
    content = """
(* -lib primitives.pvl *)
(* -lib primitives.pvl *)
new key: bitstring.
"""

    assert extract_declared_libraries(content) == ["primitives.pvl"]
