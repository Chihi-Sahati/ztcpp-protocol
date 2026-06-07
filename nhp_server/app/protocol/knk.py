"""NHP-KNK payload parser and validator.

Implements the NhpKnkParser ABC with real validation logic for
schema, nonce format, and timestamp freshness checks.
"""

from __future__ import annotations

import logging

from app.models.knk import NhpKnkPayload

logger = logging.getLogger(__name__)


class KnkParseError(Exception):
    """Raised when KNK payload parsing or validation fails."""

    def __init__(self, message: str, field: str) -> None:
        self.message = message
        self.field = field
        super().__init__(self.message)


class NhpKnkParser:
    """NHP-KNK payload parser with comprehensive validation."""

    VALID_ACTIONS = {"monitor", "remediate", "provision", "optimize"}

    @classmethod
    def parse(cls, raw_payload: bytes) -> NhpKnkPayload:
        """Parse raw bytes into a validated NhpKnkPayload."""
        import json

        try:
            data = json.loads(raw_payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise KnkParseError(
                f"Invalid JSON payload: {exc}",
                "payload",
            ) from exc

        try:
            payload = NhpKnkPayload.model_validate(data)
        except Exception as exc:
            raise KnkParseError(
                f"Schema validation failed: {exc}",
                "schema",
            ) from exc

        return payload

    @classmethod
    async def validate_schema(cls, payload: NhpKnkPayload) -> None:
        """Validate the KNK payload schema beyond Pydantic defaults."""
        if payload.version != "1.0":
            raise KnkParseError(
                f"Unsupported version: {payload.version}. Expected 1.0",
                "version",
            )
            
        intent = payload.ztcpp_intent
        context = payload.ztcpp_context

        if intent.action_class not in cls.VALID_ACTIONS:
            raise KnkParseError(
                f"Invalid action class: {intent.action_class}",
                "action_class",
            )

        if not (0.0 <= context.current_edns <= 1.0):
            raise KnkParseError(
                f"EDNS score out of range: {context.current_edns}. Must be 0.0-1.0",
                "current_edns",
            )
            
        if not (0.0 <= context.agent_confidence_score <= 1.0):
            raise KnkParseError(
                f"Confidence score out of range: {context.agent_confidence_score}. Must be 0.0-1.0",
                "agent_confidence_score",
            )
            
        # Validate public key decodes to 32 bytes
        import base64
        try:
            pk_bytes = base64.b64decode(payload.public_key)
            if len(pk_bytes) != 32:
                raise KnkParseError(
                    f"Public key must decode to 32 bytes, got {len(pk_bytes)}",
                    "public_key",
                )
        except Exception as exc:
            if isinstance(exc, KnkParseError):
                raise
            raise KnkParseError(
                f"Public key is not valid base64: {exc}",
                "public_key",
            ) from exc

    @classmethod
    async def validate_nonce(cls, payload: NhpKnkPayload) -> None:
        import base64
        try:
            nonce_bytes = base64.b64decode(payload.nonce)
        except Exception as exc:
            raise KnkParseError(
                f"Nonce is not valid base64: {exc}",
                "nonce",
            ) from exc

        if len(nonce_bytes) < 16:
            raise KnkParseError(
                f"Nonce too short: {len(nonce_bytes)} bytes. "
                f"Minimum 16 bytes required",
                "nonce",
            )

        if all(b == 0 for b in nonce_bytes):
            raise KnkParseError(
                "Nonce has zero entropy (all zeros)",
                "nonce",
            )

    @classmethod
    async def validate_timestamp(cls, payload: NhpKnkPayload) -> None:
        import time
        now = time.time()
        drift = abs(now - payload.timestamp)

        if payload.timestamp > now + 300:
            raise KnkParseError(
                f"Timestamp is too far in the future. "
                f"timestamp={payload.timestamp}, now={now:.1f}, "
                f"max_drift=300s",
                "timestamp",
            )

        if drift > 300:
            raise KnkParseError(
                f"Timestamp drift too large: {drift:.1f}s. "
                f"Max allowed: 300s",
                "timestamp",
            )

    @classmethod
    async def full_validate(cls, raw_payload: bytes) -> NhpKnkPayload:
        """Perform all validation steps on a raw KNK payload."""
        payload = cls.parse(raw_payload)
        await cls.validate_schema(payload)
        await cls.validate_nonce(payload)
        await cls.validate_timestamp(payload)
        logger.info(
            "KNK payload validated: action_class=%s, target_service=%s",
            payload.ztcpp_intent.action_class,
            payload.ztcpp_intent.target_service,
        )
        return payload

