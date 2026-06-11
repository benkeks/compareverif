"""Tests for shared query-selection helpers."""

from proverifbatch.common import QuerySelectionOption, normalize_query_text, resolve_query_selector


def test_resolve_query_selector_supports_name_and_index():
    options = [
        QuerySelectionOption(name="no pw leakage", value="canonical-a"),
        QuerySelectionOption(name="no hashed pw leakage", value="canonical-b"),
    ]

    assert resolve_query_selector(options, "no pw leakage")[0].value == "canonical-a"
    assert resolve_query_selector(options, "1")[0].value == "canonical-a"
    assert resolve_query_selector(options, 2)[0].value == "canonical-b"


def test_normalize_query_text_matches_query_and_weaksecret_forms():
    assert normalize_query_text("(* no pw leakage *)\nquery attacker(secret).") == "attacker(secret)"
    assert normalize_query_text("weaksecret attacker(secret).") == "attacker(secret)"