"""Policy Decision Engine - the central orchestrator for NHP policy evaluation.

This module coordinates the full policy evaluation pipeline:
1. JWS/JWT validation (Ed25519 signature verification)
2. EDNS metrics evaluation
3. MAMA Safety Gate evaluation
4. Decision generation

The engine enforces a fail-closed model: any validation failure at any
stage results in an immediate REJECT decision with a specific reason.
"""

from __future__ import annotations

import logging
import uuid
from typing import Optional

from app.models.knk import NhpKnkPayload
from app.models.policy import (
    CEIMetrics,
    MAMAConfig,
    PolicyDecision,
    PolicyResult,
    RejectionReason,
)
from app.policy.mama_gate import GateResult, MAMASafetyGate
from app.security.jwt_validation import JwtValidationError, NhpJwtValidator

logger = logging.getLogger(__name__)


class PolicyDecisionEngine:
    """Orchestrates the full NHP policy evaluation pipeline.

    This is the primary entry point for policy decisions. It coordinates:
    - NhpJwtValidator: Ed25519 JWS verification and claim validation
    - MAMASafetyGate: Deterministic safety gate evaluation

    All failures at any stage result in an immediate REJECT decision
    with a specific RejectionReason for audit logging.

    Usage:
        engine = PolicyDecisionEngine(jwt_validator, mama_gate)
        result = await engine.evaluate(knk_payload, cei_metrics)
        if result.decision == PolicyDecision.APPROVE:
            # Establish session
        else:
            # Reject and teardown
    """

    def __init__(
        self,
        jwt_validator: NhpJwtValidator,
        mama_gate: MAMASafetyGate,
    ) -> None:
        """Initialize the policy decision engine.

        Args:
            jwt_validator: Configured JWT validator with trust store.
            mama_gate: Configured MAMA safety gate evaluator.
        """
        self._jwt_validator = jwt_validator
        self._mama_gate = mama_gate
        logger.info("PolicyDecisionEngine initialized")

    async def evaluate(
        self,
        payload: NhpKnkPayload,
        cei_metrics: CEIMetrics,
    ) -> PolicyResult:
        """Full policy evaluation pipeline.

        Step 1: Validate JWS signature and claims (Ed25519).
        Step 2: Evaluate MAMA safety gates (Funding, Safety, Value).
        Step 3: Generate decision with session parameters (if approved).

        Args:
            payload: Validated NhpKnkPayload.
            cei_metrics: Capability Effectiveness Index metrics.

        Returns:
            PolicyResult with decision, reason, and optional session params.
        """
        request_id = str(uuid.uuid4())[:8]
        logger.info(
            "Policy evaluation started. request_id=%s, node_id=%s",
            request_id,
            payload.ztcpp_intent.target_service,
        )

        # Step 1: JWT validation (fail-closed)
        try:
            validated_claims = await self._jwt_validator.validate(payload)
        except JwtValidationError as exc:
            rejection = self._map_jwt_error(exc.rejection_reason)
            logger.warning(
                "Policy REJECTED by JWT validation. request_id=%s, "
                "node_id=%s, reason=%s, detail=%s",
                request_id,
                payload.ztcpp_intent.target_service,
                rejection.value,
                exc.message,
            )
            return PolicyResult(
                decision=PolicyDecision.REJECT,
                reason=rejection,
                rejection_detail=exc.message,
            )

        # Step 2: MAMA Safety Gate evaluation (fail-closed)
        gate_result, gate_reason, gate_evaluations = await self._mama_gate.evaluate(
            edns_score=payload.ztcpp_context.current_edns,
            cei_metrics=cei_metrics,
            capabilities=[payload.ztcpp_intent.action_class],
        )

        if gate_result == GateResult.REJECT:
            mapped_reason = self._map_gate_rejection(gate_reason)
            logger.warning(
                "Policy REJECTED by MAMA gate. request_id=%s, node_id=%s, "
                "gate_reason=%s",
                request_id,
                payload.ztcpp_intent.target_service,
                mapped_reason.value if mapped_reason else "unknown",
            )
            return PolicyResult(
                decision=PolicyDecision.REJECT,
                reason=mapped_reason,
                rejection_detail=f"MAMA gate rejection: {gate_reason}",
            )

        # Step 3: APPROVE - generate session parameters
        session_params = self._generate_session_params(
            payload, validated_claims, gate_evaluations
        )

        logger.info(
            "Policy APPROVED. request_id=%s, node_id=%s, capabilities=%s",
            request_id,
            payload.ztcpp_intent.target_service,
            [payload.ztcpp_intent.action_class],
        )
        return PolicyResult(
            decision=PolicyDecision.APPROVE,
            reason=None,
            rejection_detail=None,
            session_params=session_params,
            validated_claims=validated_claims,
        )

    def _generate_session_params(
        self,
        payload: NhpKnkPayload,
        claims: dict,
        gate_evaluations: list,
    ) -> dict:
        """Generate session parameters for an approved request.

        Creates ephemeral session parameters including:
        - session_id: Unique session identifier
        - granted_capabilities: Subset of capabilities based on policy
        - mama_results: Individual gate evaluation results
        - expires_at: Session expiration timestamp

        Args:
            payload: Original KNK payload.
            claims: Validated JWS claims.
            gate_evaluations: MAMA gate evaluation results.

        Returns:
            Session parameter dictionary.
        """
        import time

        return {
            "session_id": str(uuid.uuid4()),
            "node_id": payload.ztcpp_intent.target_service,
            "granted_capabilities": [payload.ztcpp_intent.action_class],
            "expires_at": int(time.time()) + 3600,
            "mama_gate_results": {
                ev.gate_name: ev.passed for ev in gate_evaluations
            },
            "mama_scores": {
                ev.gate_name: round(ev.score, 4) for ev in gate_evaluations
            },
        }

    @staticmethod
    def _map_jwt_error(reason: str) -> RejectionReason:
        """Map JWT validation error reasons to RejectionReason enum."""
        mapping = {
            "invalid_signature": RejectionReason.INVALID_SIGNATURE,
            "expired_token": RejectionReason.EXPIRED_TOKEN,
            "invalid_audience": RejectionReason.INVALID_AUDIENCE,
            "missing_claim": RejectionReason.MISSING_CLAIM,
            "cross_validation_failed": RejectionReason.CROSS_VALIDATION_FAILED,
            "untrusted_node": RejectionReason.UNTRUSTED_NODE,
            "invalid_nonce": RejectionReason.INVALID_NONCE,
            "invalid_public_key": RejectionReason.UNTRUSTED_NODE,
            "invalid_issuer": RejectionReason.CROSS_VALIDATION_FAILED,
            "clock_skew_exceeded": RejectionReason.CLOCK_SKEW_EXCEEDED,
        }
        return mapping.get(reason, RejectionReason.INVALID_SIGNATURE)

    @staticmethod
    def _map_gate_rejection(reason) -> Optional[RejectionReason]:
        """Map MAMA gate rejection to RejectionReason enum."""
        if reason is None:
            return None
        mapping = {
            "funding_threshold_exceeded": RejectionReason.FUNDING_EXCEEDED,
            "safety_gate_triggered": RejectionReason.SAFETY_VIOLATION,
            "negative_value_realization": RejectionReason.VALUE_NEGATIVE,
            "sla_penalty_exposure_exceeded": RejectionReason.SLA_PENALTY_EXCEEDED,
            "max_throughput_deviation": RejectionReason.THROUGHPUT_DEVIATION,
        }
        reason_str = reason.value if hasattr(reason, "value") else str(reason)
        return mapping.get(reason_str, RejectionReason.SAFETY_VIOLATION)
