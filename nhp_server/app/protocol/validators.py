"""Schema validators for KNK payload using jsonschema.

Provides additional validation layers beyond Pydantic model validation
using JSON Schema definitions for maximum compatibility with the
Rust runtime's validation logic.
"""

from __future__ import annotations

import json
import logging

import jsonschema

logger = logging.getLogger(__name__)

NHP_KNK_JSON_SCHEMA: dict = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": [
        "version",
        "node_id",
        "timestamp",
        "nonce",
        "public_key",
        "jws",
        "edns_score",
        "capabilities",
    ],
    "properties": {
        "version": {
            "type": "string",
            "const": "1.0",
        },
        "node_id": {
            "type": "string",
            "minLength": 1,
            "maxLength": 256,
        },
        "timestamp": {
            "type": "integer",
            "minimum": 1,
        },
        "nonce": {
            "type": "string",
            "minLength": 16,
            "maxLength": 64,
        },
        "public_key": {
            "type": "string",
            "minLength": 1,
        },
        "jws": {
            "type": "string",
            "minLength": 1,
        },
        "edns_score": {
            "type": "number",
            "minimum": 0.0,
            "maximum": 1.0,
        },
        "capabilities": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "string",
                "minLength": 1,
            },
        },
    },
    "additionalProperties": False,
}


class SchemaValidationError(Exception):
    """Raised when JSON Schema validation fails."""

    def __init__(self, message: str, errors: list[str]) -> None:
        self.message = message
        self.errors = errors
        super().__init__(self.message)


def validate_knk_schema(data: dict) -> list[str]:
    """Validate a KNK payload dictionary against the JSON Schema.

    Args:
        data: Dictionary representation of the KNK payload.

    Returns:
        List of validation error messages (empty if valid).

    Raises:
        SchemaValidationError: If schema validation fails.
    """
    validator = jsonschema.Draft7Validator(NHP_KNK_JSON_SCHEMA)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))

    error_messages = [
        f"{'.'.join(str(p) for p in err.path) or 'root'}: {err.message}"
        for err in errors
    ]

    if error_messages:
        logger.warning("Schema validation failed: %s", error_messages)
        raise SchemaValidationError(
            f"JSON Schema validation failed with {len(error_messages)} errors",
            error_messages,
        )

    return error_messages
