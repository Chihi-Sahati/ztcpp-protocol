"""
Shared test fixtures and helpers for NHP-Server tests.

Provides:
  - Ed25519 key pair generation
  - JWS token creation with real EdDSA signatures
  - KNK payload construction
  - Trust store setup
  - Various invalid payloads for negative testing
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from jwcrypto import jwk, jws

# Add project root to path so imports work in tests
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def generate_ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair for testing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def private_key_to_jwk(private_key: Ed25519PrivateKey) -> jwk.JWK:
    """Convert an Ed25519 private key to a jwcrypto JWK for signing."""
    private_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # JWK for Ed25519 with both d (private) and x (public)
    d_b64 = base64.urlsafe_b64encode(private_bytes).decode("ascii").rstrip("=")
    x_b64 = base64.urlsafe_b64encode(public_bytes).decode("ascii").rstrip("=")

    return jwk.JWK(kty="OKP", crv="Ed25519", d=d_b64, x=x_b64)


def public_key_to_base64(public_key: Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key as base64 string."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def public_key_to_raw(public_key: Ed25519PublicKey) -> bytes:
    """Get raw 32 bytes of an Ed25519 public key."""
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def generate_nonce() -> str:
    """Generate a hex-encoded cryptographic nonce of 32 bytes."""
    return secrets.token_hex(32)


def create_jws_claims(
    node_id: str,
    nonce: str,
    timestamp: int,
    edns_score: float,
    capabilities: list[str],
    issuer: str = "test-node-1",
    audience: str = "ztcpp-nhp-server",
    action_class: str = "read",
    aomm_level: int = 2,
    session_id: str | None = None,
) -> dict[str, Any]:
    """Create a JWS claims dictionary with all required fields."""
    now = int(time.time())
    claims: dict[str, Any] = {
        "iss": issuer,
        "aud": audience,
        "exp": now + 30,  # 30 seconds from now (within 60s bound)
        "iat": now,
        "node_id": node_id,
        "nonce": nonce,
        "timestamp": timestamp,
        "edns_score": edns_score,
        "capabilities": capabilities,
        "ztcpp_intent": {
            "action_class": action_class,
            "aomm_level": aomm_level,
        },
    }

    if session_id:
        claims["ztcpp_context"] = {
            "session_id": session_id,
            "requesting_service": "test-service",
            "target_service": "target-service",
            "sla_tier": "gold",
        }

    return claims


def sign_jws(claims: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """
    Sign a claims dictionary as a compact JWS with EdDSA.

    Uses real Ed25519 signing via jwcrypto.

    Args:
        claims: Claims dictionary to sign.
        private_key: Ed25519 private key for signing.

    Returns:
        Compact JWS token string.
    """
    signing_key = private_key_to_jwk(private_key)
    payload_json = json.dumps(claims, separators=(",", ":"))

    token = jws.JWS(payload_json)
    token.add_signature(signing_key, alg="EdDSA", protected={"alg": "EdDSA"})
    return token.serialize(compact=True)


def create_knk_payload(
    node_id: str = "test-node-1",
    private_key: Ed25519PrivateKey | None = None,
    edns_score: float = 0.92,
    capabilities: list[str] | None = None,
    action_class: str = "read",
    aomm_level: int = 2,
    audience: str = "ztcpp-nhp-server",
    override_claims: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], Ed25519PrivateKey, Ed25519PublicKey]:
    """
    Create a complete, valid KNK payload with real Ed25519 signature.

    Returns:
        Tuple of (knk_payload_dict, private_key, public_key)
    """
    if private_key is None:
        private_key, public_key = generate_ed25519_keypair()
    else:
        public_key = private_key.public_key()

    if capabilities is None:
        capabilities = ["read", "query"]

    nonce = generate_nonce()
    timestamp = int(time.time())
    pub_key_b64 = public_key_to_base64(public_key)

    claims = create_jws_claims(
        node_id=node_id,
        nonce=nonce,
        timestamp=timestamp,
        edns_score=edns_score,
        capabilities=capabilities,
        action_class=action_class,
        aomm_level=aomm_level,
        audience=audience,
    )

    if override_claims:
        claims.update(override_claims)

    jws_token = sign_jws(claims, private_key)

    payload: dict[str, Any] = {
        "version": "1.0",
        "node_id": node_id,
        "timestamp": timestamp,
        "nonce": nonce,
        "public_key": pub_key_b64,
        "jws": jws_token,
        "edns_score": edns_score,
        "capabilities": capabilities,
    }

    return payload, private_key, public_key


def create_trust_store_with_key(
    node_id: str = "test-node-1",
    public_key: Ed25519PublicKey | None = None,
) -> tuple[Any, Ed25519PublicKey]:
    """Create a TrustStore with a pre-loaded trusted key."""
    from app.security.trust_store import TrustStore

    store = TrustStore()
    if public_key is None:
        _, public_key = generate_ed25519_keypair()

    raw_bytes = public_key_to_raw(public_key)
    store.load_key_bytes(node_id, raw_bytes)
    return store, public_key


@pytest.fixture
def keypair():
    """Fixture providing a fresh Ed25519 keypair."""
    return generate_ed25519_keypair()


@pytest.fixture
def node_id():
    """Fixture providing a test node ID."""
    return "test-node-1"


@pytest.fixture
def trust_store_with_key(keypair, node_id):
    """Fixture providing a TrustStore with one trusted key."""
    _, pub_key = keypair
    return create_trust_store_with_key(node_id, pub_key)


@pytest.fixture
def valid_knk(keypair, node_id):
    """Fixture providing a valid KNK payload with real signature."""
    priv_key, pub_key = keypair
    payload, _, _ = create_knk_payload(node_id=node_id, private_key=priv_key)
    return payload


@pytest.fixture
def valid_knk_with_keys(keypair, node_id):
    """Fixture providing a valid KNK payload and its keys."""
    priv_key, pub_key = keypair
    payload, _, _ = create_knk_payload(node_id=node_id, private_key=priv_key)
    return payload, priv_key, pub_key
