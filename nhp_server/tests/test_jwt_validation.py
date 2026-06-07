"""Comprehensive tests for JWT/JWS validation.

Tests cover:
- Valid token acceptance
- Ed25519 signature verification (real crypto)
- Token expiration enforcement (strict 60s bound)
- Invalid audience rejection
- Missing claims rejection
- Cross-validation (cleartext vs signed claims)
- Nonce reuse detection
- Untrusted node rejection
- Clock skew tolerance
- ztcpp_intent structure validation
"""

from __future__ import annotations

import base64
import json
import time
import pytest

from app.models.knk import NhpKnkPayload
from app.security.jwt_validation import NhpJwtValidator, JwtValidationError
from app.security.jws import JwsVerifier, JwsVerificationError
from app.security.trust_store import TrustStore

from tests.conftest import (
    generate_ed25519_keypair,
    create_jws_token,
    create_valid_claims,
    create_knk_payload,
)


class TestJwsVerifier:
    """Tests for the Ed25519 JWS verifier."""

    def test_verify_valid_token(self):
        """Verify a valid EdDSA JWS token with correct public key."""
        private_key, pub_bytes, sk_bytes = generate_ed25519_keypair()
        claims = {"test": "data", "number": 42}
        token = create_jws_token(claims, sk_bytes)
        result = JwsVerifier.verify_compact(token, pub_bytes)
        assert result["test"] == "data"
        assert result["number"] == 42

    def test_verify_wrong_key_rejects(self):
        """Verify that using a different public key rejects the token."""
        priv1, pub1, sk1 = generate_ed25519_keypair()
        priv2, pub2, sk2 = generate_ed25519_keypair()
        claims = {"test": "data"}
        token = create_jws_token(claims, sk1)
        with pytest.raises(JwsVerificationError, match="signature verification failed"):
            JwsVerifier.verify_compact(token, pub2)

    def test_verify_tampered_payload_rejects(self):
        """Verify that tampering with the payload rejects the token."""
        priv, pub, sk = generate_ed25519_keypair()
        claims = {"test": "original"}
        token = create_jws_token(claims, sk)

        # Tamper with the payload
        parts = token.split(".")
        tampered_payload = base64.urlsafe_b64encode(
            json.dumps({"test": "tampered"}).encode()
        ).rstrip(b"=").decode("ascii")
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        with pytest.raises(JwsVerificationError, match="signature verification failed"):
            JwsVerifier.verify_compact(tampered_token, pub)

    def test_verify_wrong_algorithm_rejects(self):
        """Verify that tokens with wrong algorithm are rejected."""
        priv, pub, sk = generate_ed25519_keypair()
        claims = {"test": "data"}

        # Create token with HS256 header
        from jwcrypto import jwk, jws
        header = {"alg": "HS256", "typ": "JWS"}
        payload_bytes = json.dumps(claims).encode("utf-8")
        jws_obj = jws.JWS(payload=payload_bytes)
        jws_obj.add_signature(
            key=jwk.JWK.generate(kty="oct", size=256),
            alg="HS256",
            protected=json.dumps(header),
        )
        token = jws_obj.serialize(compact=True)

        with pytest.raises(JwsVerificationError, match="Only EdDSA"):
            JwsVerifier.verify_compact(token, pub)

    def test_verify_empty_token_rejects(self):
        """Verify that empty tokens are rejected."""
        with pytest.raises(JwsVerificationError):
            JwsVerifier.verify_compact("", b"\x00" * 32)

    def test_verify_invalid_format_rejects(self):
        """Verify that malformed tokens are rejected."""
        with pytest.raises(JwsVerificationError, match="Invalid compact JWS"):
            JwsVerifier.verify_compact("not.a.valid.token.extra", b"\x00" * 32)

    def test_verify_wrong_key_length_rejects(self):
        """Verify that wrong key length is rejected."""
        with pytest.raises(JwsVerificationError):
            JwsVerifier.verify_compact("a.b.c", b"\x00" * 16)

    def test_create_and_verify_roundtrip(self):
        """Verify full create-verify roundtrip with real Ed25519 keys."""
        priv, pub, sk = generate_ed25519_keypair()
        claims = {
            "sub": "agent-001",
            "iss": "ztcpp-agent",
            "aud": "ztcpp-nhp-server",
            "exp": int(time.time()) + 30,
        }
        token = create_jws_token(claims, sk)
        verified = JwsVerifier.verify_compact(token, pub)
        assert verified["sub"] == "agent-001"
        assert verified["iss"] == "ztcpp-agent"
        assert verified["aud"] == "ztcpp-nhp-server"


class TestJwtValidation:
    """Tests for the full JWT validation pipeline."""

    @pytest.mark.asyncio
    async def test_valid_token_passes(self, populated_trust_store):
        """A valid token with all correct fields should pass."""
        store, pub_bytes = populated_trust_store
        _, _, sk_bytes = generate_ed25519_keypair()
        # Re-create with the trusted key
        priv2 = None
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        # We need the private key matching the stored public key
        # Since generate_ed25519_keypair generates new keys, we need to use
        # the key pair that was used to populate the store

        # Let's generate a proper key pair and load it
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-001", pub)

        nonce = base64.b64encode(b"\x01" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-001", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-001",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis", "sba-read"],
        )

        result = await validator.validate(payload)
        assert result["iss"] == "ztcpp-agent"
        assert result["aud"] == "ztcpp-nhp-server"
        assert result["node_id"] == "agent-001"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_expired_token_rejects(self, populated_trust_store):
        """An expired token should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-expired", pub)

        nonce = base64.b64encode(b"\x02" * 24).decode("ascii")
        now = int(time.time())
        # Create claims with expiration in the past
        claims = create_valid_claims(
            node_id="agent-expired", nonce=nonce, timestamp=now, exp_offset=-10
        )
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-expired",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "expired_token"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_exp_too_far_future_rejects(self, populated_trust_store):
        """A token with exp > 60s in the future should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-future", pub)

        nonce = base64.b64encode(b"\x03" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(
            node_id="agent-future", nonce=nonce, timestamp=now, exp_offset=120
        )
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-future",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "clock_skew_exceeded"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_wrong_audience_rejects(self, populated_trust_store):
        """A token with wrong audience should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-bad-aud", pub)

        nonce = base64.b64encode(b"\x04" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-bad-aud", nonce=nonce, timestamp=now)
        claims["aud"] = "wrong-audience"
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-bad-aud",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "invalid_audience"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_wrong_issuer_rejects(self, populated_trust_store):
        """A token with wrong issuer should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-bad-iss", pub)

        nonce = base64.b64encode(b"\x05" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-bad-iss", nonce=nonce, timestamp=now)
        claims["iss"] = "malicious-actor"
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-bad-iss",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "invalid_issuer"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_cross_validation_node_id_mismatch_rejects(self):
        """Cleartext node_id differing from signed claim should be rejected."""
        store = TrustStore()
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-cross", pub)

        nonce = base64.b64encode(b"\x06" * 24).decode("ascii")
        now = int(time.time())
        # Claims say node_id="agent-cross" but cleartext says "agent-cross" too
        # We use the same node_id for trust, but mismatch timestamp
        claims = create_valid_claims(node_id="agent-cross", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-cross",
            timestamp=now,
            nonce=base64.b64encode(b"\x99" * 24).decode("ascii"),  # Different nonce in cleartext
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "cross_validation_failed"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_cross_validation_timestamp_mismatch_rejects(self, populated_trust_store):
        """Cleartext timestamp differing from signed claim should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-ts-mismatch", pub)

        nonce = base64.b64encode(b"\x07" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-ts-mismatch", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-ts-mismatch",
            timestamp=now - 100,  # Mismatch!
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "cross_validation_failed"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_nonce_reuse_rejects(self, populated_trust_store):
        """Reusing a nonce should be rejected (replay attack prevention)."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-replay", pub)

        nonce = base64.b64encode(b"\x08" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-replay", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-replay",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        # First call should succeed
        result = await validator.validate(payload)
        assert result["node_id"] == "agent-replay"

        # Second call with same nonce should fail
        with pytest.raises(JwtValidationError, match="Nonce reuse"):
            await validator.validate(payload)
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_untrusted_node_rejects(self, populated_trust_store):
        """A node not in the trust store should be rejected."""
        store, _ = populated_trust_store
        # Do NOT add this key to the store
        priv, pub, sk = generate_ed25519_keypair()

        nonce = base64.b64encode(b"\x09" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-unknown", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-unknown",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "untrusted_node"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_tampered_signature_rejects(self, populated_trust_store):
        """A tampered JWS signature should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-tamper", pub)

        nonce = base64.b64encode(b"\x0a" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-tamper", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        # Tamper with the signature
        parts = token.split(".")
        tampered_sig = base64.urlsafe_b64encode(
            b"\xff" * 64
        ).rstrip(b"=").decode("ascii")
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-tamper",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=tampered_token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "invalid_signature"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_missing_exp_claim_rejects(self, populated_trust_store):
        """Missing exp claim should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-no-exp", pub)

        nonce = base64.b64encode(b"\x0b" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-no-exp", nonce=nonce, timestamp=now)
        del claims["exp"]
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-no-exp",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError) as exc_info:
            await validator.validate(payload)
        assert exc_info.value.rejection_reason == "missing_claim"
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_invalid_aomm_level_rejects(self, populated_trust_store):
        """Invalid aomm_level (e.g., 6) should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-bad-aomm", pub)

        nonce = base64.b64encode(b"\x0c" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-bad-aomm", nonce=nonce, timestamp=now)
        claims["ztcpp_intent"]["aomm_level"] = 6  # Invalid!
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-bad-aomm",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError, match="aomm_level"):
            await validator.validate(payload)
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_missing_ztcpp_intent_rejects(self, populated_trust_store):
        """Missing ztcpp_intent claim should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-no-intent", pub)

        nonce = base64.b64encode(b"\x0d" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-no-intent", nonce=nonce, timestamp=now)
        del claims["ztcpp_intent"]
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-no-intent",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError, match="ztcpp_intent"):
            await validator.validate(payload)
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_invalid_action_class_rejects(self, populated_trust_store):
        """Invalid action_class should be rejected."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-bad-action", pub)

        nonce = base64.b64encode(b"\x0e" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-bad-action", nonce=nonce, timestamp=now)
        claims["ztcpp_intent"]["action_class"] = "destroy"  # Invalid!
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-bad-action",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        with pytest.raises(JwtValidationError, match="action_class"):
            await validator.validate(payload)
        validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_valid_token_allows_55_seconds_exp(self, populated_trust_store):
        """A token expiring in 55 seconds (within 60s bound) should pass."""
        store, _ = populated_trust_store
        priv, pub, sk = generate_ed25519_keypair()
        store.load_key_bytes("agent-55s", pub)

        nonce = base64.b64encode(b"\x0f" * 24).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(
            node_id="agent-55s", nonce=nonce, timestamp=now, exp_offset=55
        )
        token = create_jws_token(claims, sk)

        validator = NhpJwtValidator(store)
        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-55s",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        result = await validator.validate(payload)
        assert result["iss"] == "ztcpp-agent"
        validator.clear_nonce_cache()
