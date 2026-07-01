"""NHP-KNK payload models and related data structures for the NHP-SBA protocol."""

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Optional


class ImpactScope(BaseModel):
    max_subscribers: int = Field(..., ge=0)
    max_edns_delta: float = Field(..., ge=0.0, le=1.0)
    domain: str = Field(..., min_length=1)


class ExecutionWindow(BaseModel):
    start_time: int = Field(..., description="Unix timestamp start")
    end_time: int = Field(..., description="Unix timestamp end")


class NhpSbaIntent(BaseModel):
    """Represents the NHP-SBA intent embedded in the JWS signed payload."""

    action_class: str = Field(
        ...,
        pattern=r"^(monitor|remediate|provision|optimize)$",
        description="Action class: monitor, remediate, provision, or optimize",
    )
    target_service: str = Field(..., min_length=1, max_length=256)
    impact_scope: ImpactScope
    temporal_bounds: dict = Field(
        ...,
        description="Dictionary containing session_duration_ms and execution_window",
    )


class NhpSbaContext(BaseModel):
    """Operational context for the NHP-SBA request."""

    current_edns: float = Field(..., ge=0.0, le=1.0)
    current_cei: int = Field(..., ge=0, le=100)
    active_alarms: int = Field(..., ge=0)
    ongoing_remediations: int = Field(..., ge=0)
    agent_confidence_score: float = Field(..., ge=0.0, le=1.0)


class NhpKnkPayload(BaseModel):
    """Canonical NHP-KNK payload contract."""
    version: str = Field(..., pattern=r"^1\.0$")
    node_id: str = Field(..., min_length=1, max_length=256)
    timestamp: int = Field(..., gt=0)
    nonce: str = Field(..., min_length=16, max_length=64)
    public_key: str = Field(..., min_length=1)
    jws: str = Field(..., min_length=1)

    nhp_sba_intent: NhpSbaIntent
    nhp_sba_context: NhpSbaContext
    nhp_sba_sat_fragment: str = Field(..., min_length=1)
