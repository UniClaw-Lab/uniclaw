"""Unit tests for the JCS canonicalizer. Mirrors the Rust unit tests
in ``crates/boardproof-receipt/src/canonical.rs`` and the TS unit tests
in ``packages/verifier-ts/tests/canonical.test.ts``."""

from __future__ import annotations

import math

import pytest

from boardproof_client._canonical import canonicalize_jcs


class TestPrimitives:
    def test_null_true_false(self) -> None:
        assert canonicalize_jcs(None) == "null"
        assert canonicalize_jcs(True) == "true"
        assert canonicalize_jcs(False) == "false"

    def test_integers(self) -> None:
        assert canonicalize_jcs(0) == "0"
        assert canonicalize_jcs(-1) == "-1"
        assert canonicalize_jcs(42) == "42"

    def test_floats_raise(self) -> None:
        with pytest.raises(ValueError, match="integer"):
            canonicalize_jcs(1.5)
        with pytest.raises(ValueError, match="integer"):
            canonicalize_jcs(math.nan)
        with pytest.raises(ValueError, match="integer"):
            canonicalize_jcs(math.inf)


class TestStrings:
    def test_plain_ascii(self) -> None:
        assert canonicalize_jcs("hello") == '"hello"'

    def test_named_escapes(self) -> None:
        assert canonicalize_jcs('he said "hi"') == '"he said \\"hi\\""'
        assert canonicalize_jcs("a\\b") == '"a\\\\b"'
        assert canonicalize_jcs("a\nb") == '"a\\nb"'
        assert canonicalize_jcs("a\rb") == '"a\\rb"'
        assert canonicalize_jcs("a\tb") == '"a\\tb"'
        assert canonicalize_jcs("a\bb") == '"a\\bb"'
        assert canonicalize_jcs("a\fb") == '"a\\fb"'

    def test_low_controls_escape(self) -> None:
        assert canonicalize_jcs("\x01") == '"\\u0001"'
        assert canonicalize_jcs("\x1f") == '"\\u001f"'

    def test_forward_slash_not_escaped(self) -> None:
        assert (
            canonicalize_jcs("https://example.com/path")
            == '"https://example.com/path"'
        )


class TestContainers:
    def test_arrays_preserve_order(self) -> None:
        assert canonicalize_jcs([1, 2, 3]) == "[1,2,3]"
        assert canonicalize_jcs([]) == "[]"
        assert canonicalize_jcs(["a", "b"]) == '["a","b"]'

    def test_object_keys_sort_lexicographically(self) -> None:
        assert canonicalize_jcs({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_object_output_is_order_independent(self) -> None:
        a = canonicalize_jcs({"foo": 1, "bar": 2})
        b = canonicalize_jcs({"bar": 2, "foo": 1})
        assert a == b

    def test_nested_structure(self) -> None:
        nested = {"z": [1, {"b": 2, "a": 3}], "y": None}
        assert canonicalize_jcs(nested) == '{"y":null,"z":[1,{"a":3,"b":2}]}'

    def test_non_string_keys_rejected(self) -> None:
        with pytest.raises(TypeError, match="key must be str"):
            canonicalize_jcs({1: "a"})
