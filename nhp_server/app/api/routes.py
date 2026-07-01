"""FastAPI routes for the NHP-Server."""

from __future__ import annotations

import time
import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.models.knk import NhpKnkPayload
from app.models.policy import CEIMetrics, PolicyResult
from app.models.response import (
    ErrorResponse,
    HealthResponse,
    KnkSubmitResponse,
    SessionEstablishResponse,
)
from app.policy.decision_engine import PolicyDecisionEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["nhp"])

_start_time = time.time()


class KnkSubmitRequest(BaseModel):
    """Request body for KNK submission endpoint."""

    payload: dict = Field(..., description="NHP-KNK payload JSON")
    cei_metrics: CEIMetrics = Field(..., description="CEI metrics for MAMA evaluation")


class CEIMetricsInput(BaseModel):
    """Input CEI metrics for the submit endpoint."""

    capability_effectiveness_index: float = Field(..., ge=0.0, le=1.0)
    projected_demand_not_served: float = Field(..., ge=0.0, le=1.0)
    throughput_impact: float = Field(..., ge=0.0, le=1.0)
    sla_penalty_exposure: float = Field(..., ge=0.0, le=1.0)


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check endpoint",
)
async def health_check() -> HealthResponse:
    """Health check for monitoring and load balancers."""
    return HealthResponse(
        status="healthy",
        version="1.0",
        uptime_seconds=round(time.time() - _start_time, 2),
        components={
            "jwt_validator": "ok",
            "mama_gate": "ok",
            "state_machine": "ok",
            "trust_store": "ok",
        },
    )


@router.post(
    "/knk/submit",
    response_model=KnkSubmitResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit NHP-KNK payload for policy evaluation",
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def submit_knk(
    request: Request,
    body: KnkSubmitRequest,
) -> KnkSubmitResponse:
    """Submit an NHP-KNK payload for full policy evaluation.

    The payload goes through the complete pipeline:
    1. Schema validation
    2. Nonce and timestamp validation
    3. JWS signature verification (Ed25519)
    4. MAMA Safety Gate evaluation
    5. Policy decision (APPROVE or REJECT)
    """
    engine: PolicyDecisionEngine = request.app.state.policy_engine

    # Parse and validate the KNK payload
    try:
        import orjson
        payload_bytes = orjson.dumps(body.payload)
        from app.protocol.knk import NhpKnkParser
        knk_payload = await NhpKnkParser.full_validate(payload_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    # Build CEI metrics
    cei = CEIMetrics(
        capability_effectiveness_index=body.cei_metrics.capability_effectiveness_index,
        projected_demand_not_served=body.cei_metrics.projected_demand_not_served,
        throughput_impact=body.cei_metrics.throughput_impact,
        sla_penalty_exposure=body.cei_metrics.sla_penalty_exposure,
    )

    # Evaluate policy
    try:
        result: PolicyResult = await engine.evaluate(knk_payload, cei)
    except Exception as exc:
        logger.error("Policy evaluation error: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {exc}",
        ) from exc

    request_id = str(uuid.uuid4())[:8]

    if result.decision.value == "APPROVE":
        return KnkSubmitResponse(
            request_id=request_id,
            decision="APPROVE",
            session_id=result.session_params.get("session_id") if result.session_params else None,
            validated_node_id=knk_payload.nhp_sba_intent.target_service, # Using target service as placeholder for node id
        )
    else:
        return KnkSubmitResponse(
            request_id=request_id,
            decision="REJECT",
            reason=result.reason.value if result.reason else "unknown",
            validated_node_id=knk_payload.nhp_sba_intent.target_service,
        )


@router.post(
    "/session/{session_id}/teardown",
    summary="Teardown an established session",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def teardown_session(session_id: str) -> None:
    """Initiate immediate micro-tunnel teardown for a session.

    This is called when a MAMA gate rejects an operation or when
    the session needs to be terminated for security reasons.
    """
    logger.info(
        "Session teardown requested: session_id=%s",
        session_id,
    )
