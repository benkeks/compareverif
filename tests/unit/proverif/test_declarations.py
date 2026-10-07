import pytest

from compareverif.proverif.declarations import parse_source_declarations
from compareverif.proverif.syntax_utils import (
    IDENTIFIER_RE,
    find_top_level_equality,
    strip_proverif_comments,
)
from compareverif.uppaal import extract_global_free_names, extract_proverif_functions


@pytest.mark.parametrize("name", ["value", "_value", "Value_12", "_"])
def test_shared_identifier_grammar_accepts_source_identifiers(name):
    assert IDENTIFIER_RE.fullmatch(name)
    declarations = parse_source_declarations(f"const {name}: bitstring.")
    assert declarations.value_names == [name]


@pytest.mark.parametrize("name", ["", "12value", "caf\u00e9", "a-b", "~M_1", "value\n"])
def test_shared_identifier_grammar_rejects_non_source_identifiers(name):
    assert IDENTIFIER_RE.fullmatch(name) is None


@pytest.mark.parametrize(
    "text, expected",
    [
        (" key = value ", ("key", "value")),
        ("decode(box(value, key), key) = value", ("decode(box(value, key), key)", "value")),
        ("box(a = b) = value", ("box(a = b)", "value")),
        ("box(a = b)", None),
        ("value", None),
    ],
)
def test_shared_equality_scanner_preserves_nested_terms(text, expected):
    assert find_top_level_equality(text) == expected


def test_catalogue_collects_grouped_values_constants_and_callable_attributes():
    declarations = parse_source_declarations("""
type key.
free first, second: key [private]. const mode, other_mode: bitstring.
channel io, leak [private].
fun box(key, bitstring): bitstring [data, typeConverter].
fun marker(): bitstring.
table entries(key, bitstring).
event done(bitstring).
event completed.
process new local: key; out(io, box(local, mode))
""")
    assert declarations.value_names == ["first", "second", "mode", "other_mode"]
    assert declarations.symbols["second"].type_name == "key"
    assert declarations.symbols["second"].attributes == ("private",)
    assert declarations.symbols["io"].type_name == "channel"
    assert declarations.symbols["leak"].attributes == ("private",)
    assert declarations.symbols["entries"].argument_types == ("key", "bitstring")
    assert declarations.symbols["done"].kind == "event"
    assert declarations.symbols["completed"].kind == "event"
    assert declarations.symbols["completed"].argument_types == ()
    assert declarations.functions["box"].attributes == ("data", "typeConverter")
    assert declarations.functions["marker"].argument_types == ()
    assert "local" not in declarations.symbols


def test_nested_comments_and_strings_do_not_introduce_declarations():
    source = '''(* outer (* nested *) free ghost: bitstring. *)
(* fun ignored(bitstring): bitstring. *)
free real: bitstring.
set traceDisplay = "(* not a comment *)".
const actual: bitstring.
'''
    declarations = parse_source_declarations(source)
    assert list(declarations.symbols) == ["real", "actual"]
    assert declarations.source.count("\n") == source.count("\n")
    assert '"(* not a comment *)"' in strip_proverif_comments(source)


def test_declared_selector_signature_is_kept_when_reductions_follow_it():
    declarations = parse_source_declarations("""
fun decode(bitstring, key): bitstring
reduc forall plaintext: bitstring, secret: key;
    decode(encode(plaintext, secret), secret) = plaintext.
""")
    assert declarations.functions["decode"].argument_types == ("bitstring", "key")
    assert declarations.functions["decode"].type_name == "bitstring"


def test_uppaal_metadata_uses_the_same_catalogue_for_names_and_attributes():
    source = """
(* outer (* nested *) fun phantom(bitstring): bitstring. const ignored: bitstring. *)
free first, second: bitstring.
const mode: bitstring.
fun wrapped(bitstring): bitstring [data, typeConverter].
fun private_box(bitstring): bitstring [private].
"""
    declarations = parse_source_declarations(source)
    assert extract_global_free_names(source) == declarations.value_names
    assert extract_global_free_names(declarations) == ["first", "second", "mode"]
    functions = extract_proverif_functions(declarations)
    assert functions.constructors == ["wrapped", "private_box"]
    assert functions.data_functions == ["wrapped"]
    assert functions.arities == {"wrapped": 1, "private_box": 1}