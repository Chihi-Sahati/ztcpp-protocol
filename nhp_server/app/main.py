"""NHP-Server main application entry point.

Creates and configures the FastAPI application with all middleware,
routes, and dependency injection.
"""

from __future__ import annotations

import logging
import uuid

from contextlib import asynccontextmanager
from fastapi import FastAPI

from app.api.dependencies import (
    create_mama_gate,
    create_policy_engine,
    create_trust_store,
    create_jwt_validator,
)
from app.api.middleware import RateLimitMiddleware, RequestLoggingMiddleware, ZtcppSbaMediationMiddleware
from app.api.routes import router
from app.api.agentdns import router as agentdns_router
from app.policy.mama_gate import MAMASafetyGate
from app.security.jwt_validation import NhpJwtValidator
from app.policy.decision_engine import PolicyDecisionEngine
from app.security.trust_store import TrustStore
from app.telemetry.logging import setup_logging
from app.telemetry.tracing import setup_tracing

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup and shutdown."""
    # Startup
    setup_logging()
    setup_tracing()

    trust_store = create_trust_store()
    jwt_validator = create_jwt_validator(trust_store)
    mama_gate = create_mama_gate()
    policy_engine = create_policy_engine(jwt_validator, mama_gate)

    app.state.trust_store = trust_store
    app.state.jwt_validator = jwt_validator
    app.state.mama_gate = mama_gate
    app.state.policy_engine = policy_engine

    logger.info("NHP-Server started. Version 1.0")

    yield

    # Shutdown
    logger.info("NHP-Server shutting down")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="ZTCPP NHP-Server",
        description="Policy Decision Point (PDP) for the Zero Trust Control and Policy Protocol",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Middleware
    app.add_middleware(ZtcppSbaMediationMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

    # Routes
    app.include_router(router)
    app.include_router(agentdns_router, prefix="/api/v1/agentdns", tags=["agentdns"])

    return app


app = create_app()
