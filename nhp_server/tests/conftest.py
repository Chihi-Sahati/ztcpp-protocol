"""Shared test helpers and fixtures for ZTCPP NHP-Server tests."""

from __future__ import annotations

import base64
import json
import secrets
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.models.knk import NhpKnkPayload
from app.models.policy import CEIMetrics, MAMAConfig
from app.policy.mama_gate import MAMASafetyGate
from app.security.jwt_validation import NhpJwtValidator
from app.security.trust_store import TrustStore


def generate_ed25519_keypair():
    """Generate an Ed25519 key pair.

    Returns:
        Tuple of (private_key, public_key_bytes, private_key_bytes).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_key, public_key_bytes, private_key_bytes


def create_jws_token(
    claims: dict,
    private_key_bytes: bytes,
) -> str:
    """Create a compact EdDSA JWS token with real Ed25519 signature.

    Args:
        claims: Dictionary of claims to sign.
        private_key_bytes: Raw Ed25519 private key bytes (64 bytes = 32 seed + 32 pub).

    Returns:
        Compact JWS token string.
    """
    from jwcrypto import jwk, jws

    # Ed25519 private key: first 32 bytes = seed, last 32 bytes = public key
    pub_bytes = private_key_bytes[32:] if len(private_key_bytes) == 64 else None
    seed_bytes = private_key_bytes[:32]

    if pub_bytes is None:
        # It's just the seed (32 bytes), need to derive public key
        priv_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        pub_bytes = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        seed_bytes = private_key_bytes

    jwk_key = jwk.JWK(
        kty="OKP",
        crv="Ed25519",
        d=base64.urlsafe_b64encode(seed_bytes).rstrip(b"=").decode("ascii"),
        x=base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode("ascii"),
    )

    header = {"alg": "EdDSA", "typ": "JWS"}
    payload_bytes = json.dumps(claims).encode("utf-8")

    jws_obj = jws.JWS(payload=payload_bytes)
    jws_obj.add_signature(
        key=jwk_key,
        alg="EdDSA",
        protected=json.dumps(header),
    )

    return jws_obj.serialize(compact=True)


def create_valid_claims(
    node_id: str = "agent-001",
    nonce: str = None,
    timestamp: int = None,
    exp_offset: int = 30,
) -> dict:
    """Create valid JWS claims for testing."""
    now = int(time.time())
    if nonce is None:
        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
    if timestamp is None:
        timestamp = now

    return {
        "iss": "ztcpp-agent",
        "aud": "ztcpp-nhp-server",
        "exp": now + exp_offset,
        "iat": now,
        "node_id": node_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "edns_score": 0.15,
        "capabilities": ["soc-analysis", "sba-read"],
        "ztcpp_intent": {
            "action_class": "read",
            "aomm_level": 4,
        },
        "ztcpp_context": {
            "session_id": "sess-test-001",
            "requesting_service": "soc-analyzer",
            "target_service": "nrf",
            "sla_tier": "gold",
        },
    }


def create_knk_payload(
    node_id: str = "agent-001",
    public_key_bytes: bytes = None,
    jws_token: str = None,
    nonce: str = None,
    timestamp: int = None,
    edns_score: float = 0.15,
    capabilities: list = None,
) -> NhpKnkPayload:
    """Create a valid NhpKnkPayload for testing."""
    now = int(time.time())
    if nonce is None:
        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
    if timestamp is None:
        timestamp = now
    if capabilities is None:
        capabilities = ["soc-analysis", "sba-read"]
    if public_key_bytes is None:
        _, public_key_bytes, _ = generate_ed25519_keypair()
    if jws_token is None:
        _, pk_bytes, sk_bytes = generate_ed25519_keypair()
        claims = create_valid_claims(node_id=node_id, nonce=nonce, timestamp=timestamp)
        jws_token = create_jws_token(claims, sk_bytes)
        public_key_bytes = pk_bytes

    return NhpKnkPayload(
        version="1.0",
        node_id=node_id,
        timestamp=timestamp,
        nonce=nonce,
        public_key=base64.b64encode(public_key_bytes).decode("ascii"),
        jws=jws_token,
        edns_score=edns_score,
        capabilities=capabilities,
    )


@pytest.fixture
def trust_store():
    """Fixture providing an empty TrustStore."""
    return TrustStore()


@pytest.fixture
def populated_trust_store():
    """Fixture providing a TrustStore with a pre-loaded test key."""
    _, pub_bytes, _ = generate_ed25519_keypair()
    store = TrustStore()
    store.load_key_bytes("agent-001", pub_bytes)
    return store, pub_bytes


@pytest.fixture
def keypair():
    """Fixture providing an Ed25519 key pair."""
    return generate_ed25519_keypair()


@pytest.fixture
def valid_claims():
    """Fixture providing valid JWS claims."""
    return create_valid_claims()


@pytest.fixture
def jwt_validator(populated_trust_store):
    """Fixture providing an NhpJwtValidator with a pre-populated trust store."""
    store, _ = populated_trust_store
    validator = NhpJwtValidator(store)
    yield validator
    validator.clear_nonce_cache()


@pytest.fixture
def mama_gate():
    """Fixture providing a MAMASafetyGate with default config."""
    return MAMASafetyGate(MAMAConfig())


@pytest.fixture
def cei_metrics_safe():
    """Fixture providing safe CEI metrics that should pass all gates."""
    return CEIMetrics(
        capability_effectiveness_index=0.85,
        projected_demand_not_served=0.05,
        throughput_impact=0.10,
        sla_penalty_exposure=0.05,
    )


@pytest.fixture
def cei_metrics_unsafe():
    """Fixture providing unsafe CEI metrics that should fail."""
    return CEIMetrics(
        capability_effectiveness_index=0.3,
        projected_demand_not_served=0.8,
        throughput_impact=0.9,
        sla_penalty_exposure=0.9,
    )
