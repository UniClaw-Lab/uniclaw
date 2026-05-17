"""Hex helpers. Kept tiny and dependency-free so the auditable surface
stays small."""

from __future__ import annotations


def hex_to_bytes(hex_str: str) -> bytes:
    """Decode a hex string into raw bytes.

    Raises:
        TypeError: if ``hex_str`` is not a ``str``.
        ValueError: if the length is odd or any character isn't hex.
    """
    if not isinstance(hex_str, str):
        raise TypeError("hex must be a str")
    if len(hex_str) % 2 != 0:
        raise ValueError("hex must have even length")
    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValueError(f"invalid hex: {e}") from e


def bytes_to_hex(data: bytes) -> str:
    """Encode raw bytes as a lowercase hex string."""
    return data.hex()
