"""API response models for the NHP-Server REST interface."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Standard error response returned on validation failures."""

    error: str = Field(..., description="Error type identifier")
    message: str = Field(..., description="Human-readable error description")
    detail: Optional[str] = Field(None, description="Additional error detail")
    status_code: int = Field(..., description="HTTP status code")


class SessionEstablishResponse(BaseModel):
    """Response returned when a session is successfully established."""

    session_id: str = Field(..., description="Unique session identifier")
    node_id: str = Field(..., description="Authenticated node identifier")
    expires_at: int = Field(..., description="Session expiration Unix timestamp")
    allowed_capabilities: list[str] = Field(..., description="Granted capabilities list")
    mama_gate_results: dict[str, bool] = Field(
        ..., description="Individual MAMA gate evaluation results"
    )


class HealthResponse(BaseModel):
    """Health check response for monitoring and load balancers."""

    status: str = Field(default="healthy")
    version: str = Field(default="1.0")
    uptime_seconds: float = Field(...)
    components: dict[str, str] = Field(default_factory=dict)


class KnkSubmitResponse(BaseModel):
    """Response to a KNK submission request."""

    request_id: str = Field(..., description="Unique request tracking ID")
    decision: str = Field(..., description="APPROVE or REJECT")
    reason: Optional[str] = Field(None, description="Rejection reason if rejected")
    session_id: Optional[str] = Field(None, description="Session ID if approved")
    validated_node_id: Optional[str] = Field(None, description="Validated node ID")
