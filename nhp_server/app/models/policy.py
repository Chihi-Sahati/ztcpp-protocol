"""Policy decision and evaluation result models."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class PolicyDecision(str, Enum):
    """Final policy decision outcome."""

    APPROVE = "APPROVE"
    REJECT = "REJECT"


class RejectionReason(str, Enum):
    """Specific reason for policy rejection, used for audit and debugging."""

    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED_TOKEN = "expired_token"
    INVALID_AUDIENCE = "invalid_audience"
    MISSING_CLAIM = "missing_claim"
    CROSS_VALIDATION_FAILED = "cross_validation_failed"
    UNTRUSTED_NODE = "untrusted_node"
    FUNDING_EXCEEDED = "funding_threshold_exceeded"
    SAFETY_VIOLATION = "safety_gate_triggered"
    VALUE_NEGATIVE = "negative_value_realization"
    SLA_PENALTY_EXCEEDED = "sla_penalty_exposure_exceeded"
    THROUGHPUT_DEVIATION = "max_throughput_deviation"
    INVALID_NONCE = "invalid_nonce"
    INVALID_TIMESTAMP = "invalid_timestamp"
    SCHEMA_VALIDATION_FAILED = "schema_validation_failed"
    CLOCK_SKEW_EXCEEDED = "clock_skew_exceeded"


class MAMAConfig(BaseModel):
    """Configuration parameters for the MAMA Safety Gate evaluation."""

    max_sla_penalty_exposure: float = Field(
        default=0.15, ge=0.0, le=1.0, description="Max allowed SLA penalty exposure ratio"
    )
    max_throughput_deviation: float = Field(
        default=0.20, ge=0.0, le=1.0, description="Max allowed throughput deviation ratio"
    )
    min_funding_ratio: float = Field(
        default=0.30, ge=0.0, le=1.0, description="Minimum funding ratio threshold"
    )
    min_safety_score: float = Field(
        default=0.85, ge=0.0, le=1.0, description="Minimum composite safety score"
    )
    min_value_realization: float = Field(
        default=0.10, ge=0.0, le=1.0, description="Minimum value realization threshold"
    )


class CEIMetrics(BaseModel):
    """Capability Effectiveness Index metrics used by MAMA Safety Gate.
    These metrics represent the projected impact of allowing the
    requested operation on the network infrastructure.
    """

    capability_effectiveness_index: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall capability effectiveness index (0.0-1.0)",
    )
    projected_demand_not_served: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Projected demand that would not be served (0.0-1.0)",
    )
    throughput_impact: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Impact on throughput capacity (0.0-1.0)",
    )
    sla_penalty_exposure: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="SLA penalty exposure ratio (0.0-1.0)",
    )


class PolicyResult(BaseModel):
    """Complete policy evaluation result including decision, reason,
    and optional session parameters for approved requests.
    """

    decision: PolicyDecision
    reason: Optional[RejectionReason] = None
    rejection_detail: Optional[str] = None
    session_params: Optional[dict] = Field(
        default=None, description="Session parameters if decision is APPROVE"
    )
    validated_claims: Optional[dict] = Field(
        default=None, description="Validated JWS claims if verification passed"
    )
