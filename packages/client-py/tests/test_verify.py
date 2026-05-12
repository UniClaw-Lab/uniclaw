"""Sign+verify roundtrip tests. The package can't construct receipts
(it's a verifier, not a kernel), but we can synthesize signed
receipts inside the test using PyNaCl to prove the verify path is
consistent with the canonicalize path — i.e. anything that signs a
JCS-canonicalized body with a known key verifies under that key,
and anything that doesn't is rejected.

Cross-implementation Ed25519 conformance is guaranteed by RFC 8032;
PyNaCl's Ed25519 produces/consumes identical bytes to the Rust
``ed25519-dalek``.
"""

from __future__ import annotations

import json
from typing import Any

from nacl.signing import SigningKey

from uniclaw_client._hex import bytes_to_hex, hex_to_bytes
from uniclaw_client.verify import canonicalize, compute_content_id_hex, verify_receipt, verify_receipt_json


# Same deterministic seed the demo binary uses (`[42u8; 32]`).
DEMO_SEED = bytes([42] * 32)


def _sample_body(seq: int = 0) -> dict[str, Any]:
    return {
        "schema_version": 2,
        "issued_at": "2026-05-12T12:00:00Z",
        "action": {
            "kind": "http.fetch",
            "target": "https://example.com/",
            "input_hash": "00" * 32,
        },
        "decision": "allowed",
        "constitution_rules": [],
        "provenance": [],
        "redactor_stack_hash": None,
        "merkle_leaf": {
            "sequence": seq,
            "leaf_hash": "01" * 32,
            "prev_hash": "00" * 32,
        },
    }


def _sign_receipt(body: dict[str, Any], seed: bytes) -> dict[str, Any]:
    signing_key = SigningKey(seed)
    public_key_bytes = bytes(signing_key.verify_key)
    canonical = canonicalize(body)
    signature_bytes = signing_key.sign(canonical).signature
    return {
        "version": 1,
        "body": body,
        "issuer": bytes_to_hex(public_key_bytes),
        "signature": bytes_to_hex(signature_bytes),
    }


class TestHappyPath:
    def test_freshly_signed_receipt_verifies(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        result = verify_receipt(receipt)
        assert result.ok is True
        assert result.error is None
        assert result.schema_version == 2
        assert result.decision == "allowed"
        assert result.content_id_hex == compute_content_id_hex(receipt["body"])
        assert result.issuer_hex == receipt["issuer"]

    def test_multiple_sequence_numbers(self) -> None:
        for seq in range(3):
            receipt = _sign_receipt(_sample_body(seq), DEMO_SEED)
            assert verify_receipt(receipt).ok is True


class TestTamperDetection:
    def test_body_mutation_rejected(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        # Deep copy + mutate one field.
        tampered = json.loads(json.dumps(receipt))
        tampered["body"]["decision"] = "denied"
        result = verify_receipt(tampered)
        assert result.ok is False
        assert result.error is not None
        assert "did not verify" in result.error

    def test_sequence_swap_rejected(self) -> None:
        receipt = _sign_receipt(_sample_body(7), DEMO_SEED)
        tampered = json.loads(json.dumps(receipt))
        tampered["body"]["merkle_leaf"]["sequence"] = 8
        assert verify_receipt(tampered).ok is False

    def test_signature_bit_flip_rejected(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        sig = bytearray(hex_to_bytes(receipt["signature"]))
        sig[0] ^= 0x01
        receipt["signature"] = bytes_to_hex(bytes(sig))
        assert verify_receipt(receipt).ok is False

    def test_wrong_key_rejected(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        # Re-issuer with a totally different key.
        other = SigningKey(bytes([7] * 32))
        receipt["issuer"] = bytes_to_hex(bytes(other.verify_key))
        assert verify_receipt(receipt).ok is False


class TestInputValidation:
    def test_non_object_input(self) -> None:
        # `verify_receipt` takes a dict; type-checked clients won't
        # hit this, but defense-in-depth tests confirm we return
        # ok=False rather than crashing on something silly.
        result = verify_receipt(None)  # type: ignore[arg-type]
        assert result.ok is False
        assert result.error is not None
        assert "not a JSON object" in result.error

    def test_missing_body(self) -> None:
        result = verify_receipt({"version": 1, "issuer": "00" * 32, "signature": "00" * 64})
        assert result.ok is False
        assert result.error is not None
        assert "missing a body" in result.error

    def test_malformed_issuer_hex(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        receipt["issuer"] = "zz"
        assert verify_receipt(receipt).ok is False

    def test_wrong_length_issuer(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        receipt["issuer"] = "00" * 16
        result = verify_receipt(receipt)
        assert result.ok is False
        assert result.error is not None
        assert "32 bytes" in result.error

    def test_wrong_length_signature(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        receipt["signature"] = "00" * 32
        result = verify_receipt(receipt)
        assert result.ok is False
        assert result.error is not None
        assert "64 bytes" in result.error


class TestVerifyReceiptJson:
    def test_parses_and_verifies_json(self) -> None:
        receipt = _sign_receipt(_sample_body(), DEMO_SEED)
        result = verify_receipt_json(json.dumps(receipt))
        assert result.ok is True

    def test_invalid_json_returns_error(self) -> None:
        result = verify_receipt_json("not json")
        assert result.ok is False
        assert result.error is not None
        assert "invalid JSON" in result.error
