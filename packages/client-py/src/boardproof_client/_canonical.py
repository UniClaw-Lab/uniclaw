"""RFC 8785 JCS canonicalizer for BoardProof receipt bodies.

Python port of ``crates/boardproof-receipt/src/canonical.rs`` and
``packages/verifier-ts/src/canonical.ts``. The three implementations
share a single conformance fixture
(``crates/boardproof-receipt/tests/vectors/canonical-v2.json``); any
divergence fails the conformance test in whichever language drifted.

Scope: handles the shape BoardProof receipts use — string keys,
integer numbers only, ASCII-mostly strings. Floats raise rather than
emit potentially wrong bytes (matches Rust and TS behavior).
"""

from __future__ import annotations

from typing import Any


def canonicalize_body(body: dict[str, Any]) -> bytes:
    """Encode a receipt body to canonical bytes.

    Dispatches on ``body.schema_version``:

    - ``<= 1``: legacy ``json.dumps`` (struct-declaration order is
      preserved when the body was already parsed from JSON text).
    - ``>= 2``: RFC 8785 JCS (lexicographic key sort, integer
      numbers only, standard string escapes).
    """
    if not isinstance(body, dict):
        raise TypeError("body must be a dict")
    schema_version = body.get("schema_version", 0)
    if isinstance(schema_version, int) and schema_version >= 2:
        return canonicalize_jcs(body).encode("utf-8")
    # Legacy path: json.dumps with insertion-order keys + no spaces.
    # Importing here keeps the JCS path free of stdlib JSON overhead.
    import json

    return json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonicalize_jcs(value: Any) -> str:
    """Canonicalize an arbitrary JSON value to a string per RFC 8785."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, bool):
        # Unreachable — bool is True/False above. Defensive belt.
        raise RuntimeError("bool fell through")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise ValueError(f"JCS: expected integer, got float {value!r}")
    if isinstance(value, str):
        return _canonicalize_jcs_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonicalize_jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        # Sort keys by UTF-16 code-unit order. Python's str default
        # ordering is by codepoint; for the BMP-only strings BoardProof
        # uses today, that matches UTF-16 ordering byte-for-byte.
        # If a future field admits non-BMP keys, this function will
        # need a real UTF-16 comparison; the conformance fixture
        # would catch that drift the same way Rust + TS do.
        keys = sorted(value.keys())
        parts: list[str] = []
        for k in keys:
            if not isinstance(k, str):
                raise TypeError(f"JCS: object key must be str, got {type(k).__name__}")
            parts.append(_canonicalize_jcs_string(k) + ":" + canonicalize_jcs(value[k]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"JCS: unsupported value type {type(value).__name__}")


def _canonicalize_jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)
