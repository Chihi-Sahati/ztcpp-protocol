"""Integration tests for the full Policy Decision Engine.

Tests the complete pipeline: KNK parsing -> JWT validation -> MAMA gates -> Decision.
Uses real Ed25519 keys and actual JWS signatures.
"""

from __future__ import annotations

import base64
import time
import secrets
import pytest

from app.models.knk import NhpKnkPayload
from app.models.policy import CEIMetrics, PolicyDecision
from app.policy.decision_engine import PolicyDecisionEngine
from app.policy.mama_gate import MAMASafetyGate
from app.security.jwt_validation import NhpJwtValidator, JwtValidationError
from app.security.trust_store import TrustStore

from tests.conftest import (
    generate_ed25519_keypair,
    create_jws_token,
    create_valid_claims,
)


class TestDecisionEngine:
    """Integration tests for the Policy Decision Engine."""

    @pytest.mark.asyncio
    async def test_full_approve_pipeline(self):
        """Full pipeline with valid token and safe metrics should APPROVE."""
        # Setup
        priv, pub, sk = generate_ed25519_keypair()
        store = TrustStore()
        store.load_key_bytes("agent-001", pub)
        jwt_validator = NhpJwtValidator(store)
        mama_gate = MAMASafetyGate()
        engine = PolicyDecisionEngine(jwt_validator, mama_gate)

        # Create valid payload
        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-001", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

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

        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.05,
        )

        result = await engine.evaluate(payload, cei)
        assert result.decision == PolicyDecision.APPROVE
        assert result.session_params is not None
        assert result.validated_claims is not None
        jwt_validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_reject_on_invalid_signature(self):
        """Invalid signature should result in REJECT."""
        priv1, pub1, sk1 = generate_ed25519_keypair()
        priv2, pub2, sk2 = generate_ed25519_keypair()
        store = TrustStore()
        store.load_key_bytes("agent-sig", pub1)
        jwt_validator = NhpJwtValidator(store)
        mama_gate = MAMASafetyGate()
        engine = PolicyDecisionEngine(jwt_validator, mama_gate)

        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-sig", nonce=nonce, timestamp=now)
        # Sign with wrong key!
        token = create_jws_token(claims, sk2)

        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-sig",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub1).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.05,
        )

        result = await engine.evaluate(payload, cei)
        assert result.decision == PolicyDecision.REJECT
        jwt_validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_reject_on_mama_gate_failure(self):
        """MAMA gate failure should result in REJECT even with valid JWT."""
        priv, pub, sk = generate_ed25519_keypair()
        store = TrustStore()
        store.load_key_bytes("agent-mama", pub)
        jwt_validator = NhpJwtValidator(store)
        mama_gate = MAMASafetyGate()
        engine = PolicyDecisionEngine(jwt_validator, mama_gate)

        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-mama", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-mama",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        # Dangerous CEI metrics that will fail MAMA gates
        cei = CEIMetrics(
            capability_effectiveness_index=0.10,
            projected_demand_not_served=0.95,
            throughput_impact=0.95,
            sla_penalty_exposure=0.95,
        )

        result = await engine.evaluate(payload, cei)
        assert result.decision == PolicyDecision.REJECT
        assert result.reason is not None
        jwt_validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_reject_on_expired_token(self):
        """Expired token should result in REJECT."""
        priv, pub, sk = generate_ed25519_keypair()
        store = TrustStore()
        store.load_key_bytes("agent-exp", pub)
        jwt_validator = NhpJwtValidator(store)
        mama_gate = MAMASafetyGate()
        engine = PolicyDecisionEngine(jwt_validator, mama_gate)

        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(
            node_id="agent-exp", nonce=nonce, timestamp=now, exp_offset=-10
        )
        token = create_jws_token(claims, sk)

        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-exp",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.05,
        )

        result = await engine.evaluate(payload, cei)
        assert result.decision == PolicyDecision.REJECT
        jwt_validator.clear_nonce_cache()

    @pytest.mark.asyncio
    async def test_approved_session_has_params(self):
        """Approved sessions must have valid session parameters."""
        priv, pub, sk = generate_ed25519_keypair()
        store = TrustStore()
        store.load_key_bytes("agent-params", pub)
        jwt_validator = NhpJwtValidator(store)
        mama_gate = MAMASafetyGate()
        engine = PolicyDecisionEngine(jwt_validator, mama_gate)

        nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
        now = int(time.time())
        claims = create_valid_claims(node_id="agent-params", nonce=nonce, timestamp=now)
        token = create_jws_token(claims, sk)

        payload = NhpKnkPayload(
            version="1.0",
            node_id="agent-params",
            timestamp=now,
            nonce=nonce,
            public_key=base64.b64encode(pub).decode("ascii"),
            jws=token,
            edns_score=0.15,
            capabilities=["soc-analysis"],
        )

        cei = CEIMetrics(
            capability_effectiveness_index=0.85,
            projected_demand_not_served=0.05,
            throughput_impact=0.10,
            sla_penalty_exposure=0.05,
        )

        result = await engine.evaluate(payload, cei)
        assert result.decision == PolicyDecision.APPROVE
        sp = result.session_params
        assert "session_id" in sp
        assert "node_id" in sp
        assert "granted_capabilities" in sp
        assert "expires_at" in sp
        assert "mama_gate_results" in sp
        assert sp["mama_gate_results"]["funding"] is True
        assert sp["mama_gate_results"]["safety"] is True
        assert sp["mama_gate_results"]["value_realization"] is True
        jwt_validator.clear_nonce_cache()
