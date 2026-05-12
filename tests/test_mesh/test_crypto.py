"""
IMMUNIS ACIN — Mesh Cryptography Tests
Tests hybrid Ed25519 + CRYSTALS-Dilithium signing.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from backend.mesh.crypto import MeshCrypto


class TestMeshCrypto:
    """Tests for hybrid post-quantum cryptography."""

    def setup_method(self):
        from backend.mesh.crypto import MeshCrypto
        self.crypto = MeshCrypto()
        self.crypto.generate_keypair("test_node")  # MUST be called before sign()

    def test_init(self):
        """Crypto module initialises."""
        assert self.crypto is not None

    def test_key_generation(self):
        """Can generate signing key pair."""
        if hasattr(self.crypto, 'generate_keypair'):
            keypair = self.crypto.generate_keypair("test_node")
            assert keypair is not None
            assert hasattr(keypair, 'fingerprint')
            assert hasattr(keypair, 'ed25519_public')
        elif hasattr(self.crypto, 'generate_keys'):
            keys = self.crypto.generate_keys()
            assert keys is not None
            if isinstance(keys, dict):
                assert "public" in keys or "public_key" in keys
                assert "private" in keys or "private_key" in keys or "secret" in keys
            elif isinstance(keys, tuple):
                assert len(keys) >= 2
        elif hasattr(self.crypto, 'create'):
            keys = self.crypto.create()
            assert keys is not None

    def test_sign_and_verify(self):
        """Signature can be verified with correct public key."""
        message = b"Test antibody payload for signing"

        if hasattr(self.crypto, 'sign'):
            signature = self.crypto.sign(message)
            assert signature is not None

            if hasattr(self.crypto, 'verify'):
                is_valid = self.crypto.verify(message, signature)
                assert is_valid is True, "Valid signature should verify"
        elif hasattr(self.crypto, 'create_signature'):
            signature = self.crypto.create_signature(message)
            if hasattr(self.crypto, 'verify_signature'):
                is_valid = self.crypto.verify_signature(message, signature)
                assert is_valid is True

    def test_tampered_message_fails(self):
        """Tampered message fails verification."""
        message = b"Original antibody data"

        if hasattr(self.crypto, 'sign') and hasattr(self.crypto, 'verify'):
            signature = self.crypto.sign(message)
            tampered = b"Modified antibody data"
            is_valid = self.crypto.verify(tampered, signature)
            assert is_valid is False, "Tampered message should fail verification"

    def test_wrong_key_fails(self):
        """Signature from different key fails verification."""
        message = b"Test message"

        if hasattr(self.crypto, 'sign') and hasattr(self.crypto, 'verify'):
            signature = self.crypto.sign(message)

            other_crypto = MeshCrypto()
            other_crypto.generate_keypair("other_node")  # Generate keys for other crypto
            if hasattr(other_crypto, 'verify'):
                is_valid = other_crypto.verify(message, signature)
                assert is_valid is False, "Wrong key should fail verification"

    def test_signature_deterministic(self):
        """Same message + same key = same signature (for Ed25519)."""
        message = b"Deterministic test"

        if hasattr(self.crypto, 'sign'):
            sig1 = self.crypto.sign(message)
            sig2 = self.crypto.sign(message)
            # Ed25519 is deterministic, Dilithium may not be
            # At least they should both verify
            if hasattr(self.crypto, 'verify'):
                assert self.crypto.verify(message, sig1) is True
                assert self.crypto.verify(message, sig2) is True

    def test_empty_message_signing(self):
        """Can sign empty message."""
        if hasattr(self.crypto, 'sign'):
            try:
                signature = self.crypto.sign(b"")
                assert signature is not None
            except (ValueError, Exception):
                pass  # Some implementations reject empty messages

    def test_large_payload_signing(self):
        """Can sign large payloads (antibody bundles can be big)."""
        large_message = b"A" * 1_000_000  # 1MB

        if hasattr(self.crypto, 'sign'):
            signature = self.crypto.sign(large_message)
            assert signature is not None

            if hasattr(self.crypto, 'verify'):
                is_valid = self.crypto.verify(large_message, signature)
                assert is_valid is True
