"""FastAPI dependency injection providers."""

from __future__ import annotations

import logging

from app.policy.decision_engine import PolicyDecisionEngine
from app.policy.mama_gate import MAMASafetyGate
from app.security.jwt_validation import NhpJwtValidator
from app.security.trust_store import TrustStore
from app.models.policy import MAMAConfig

logger = logging.getLogger(__name__)


def create_trust_store() -> TrustStore:
    """Create and configure the trust store.

    In production, this would load keys from a secure key management
    system (HSM, Vault, etc.). For PoC, returns an empty store.
    """
    store = TrustStore()
    return store


def create_jwt_validator(trust_store: TrustStore) -> NhpJwtValidator:
    """Create and configure the JWT validator."""
    validator = NhpJwtValidator(trust_store)
    return validator


def create_mama_gate() -> MAMASafetyGate:
    """Create and configure the MAMA Safety Gate."""
    config = MAMAConfig()
    gate = MAMASafetyGate(config)
    return gate


def create_policy_engine(
    jwt_validator: NhpJwtValidator,
    mama_gate: MAMASafetyGate,
) -> PolicyDecisionEngine:
    """Create and configure the policy decision engine."""
    engine = PolicyDecisionEngine(jwt_validator, mama_gate)
    return engine
