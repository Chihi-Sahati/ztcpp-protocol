"""NHP JWT/JWS Validation Engine.

This is the most critical security module in the NHP-Server (PDP).
It validates the NHP-KNK payload by verifying the embedded JWS token
using real Ed25519 (EdDSA) signature verification.

Validation Pipeline (fail-closed at every step):
1. Decode the base64-encoded public_key from the KNK cleartext.
2. Verify the public_key is trusted via TrustStore.
3. Verify the JWS signature with the Ed25519 public key.
4. Validate standard JWT claims: iss, aud, exp.
5. Enforce strict 60-second expiration bound.
6. Validate ztcpp_intent structure (action_class, aomm_level).
7. Cross-validate cleartext KNK fields (nonce, node_id, timestamp)
   against the corresponding claims in the signed JWS payload.

Cleartext Headers (in KNK, NOT signed): nonce, timestamp, public_key
Signed Payload Claims (in JWS): iss, aud, exp, edns_score, capabilities,
  node_id, ztcpp_intent, ztcpp_context, nonce, timestamp
"""

from __future__ import annotations

import base64
import time
import logging
from typing import Optional

from app.models.knk import NhpKnkPayload, ZtcppIntent
from app.security.jws import JwsVerifier, JwsVerificationError
from app.security.trust_store import TrustStore, TrustStoreError

logger = logging.getLogger(__name__)


class JwtValidationError(Exception):
    """Raised on any JWT validation failure. Triggers immediate fail-closed
    session termination. The rejection_reason field allows the caller to
    generate precise audit logs and error responses.
    """

    def __init__(self, message: str, rejection_reason: str) -> None:
        self.message = message
        self.rejection_reason = rejection_reason
        super().__init__(self.message)


class NhpJwtValidator:
    """Validates the NHP-KNK payload by verifying the embedded JWS.

    Enforces strict Ed25519 signature verification and comprehensive
    claim validation. All failures result in immediate JwtValidationError
    which maps to REJECT in the policy decision engine.

    The validator enforces a strict 60-second expiration bound meaning
    tokens that expire more than 60 seconds from now are considered
    potentially compromised and will be rejected.
    """

    EXPECTED_AUDIENCE: str = "ztcpp-nhp-server"
    MAX_CLOCK_SKEW_SECONDS: int = 5
    STRICT_EXP_BOUND_SECONDS: int = 60
    VALID_ISSUERS: list[str] = [
        "ztcpp-agent",
        "ztcpp-soc",
        "ztcpp-operator",
    ]

    def __init__(self, trust_store: TrustStore) -> None:
        """Initialize the validator with a TrustStore.

        Args:
            trust_store: Pre-loaded TrustStore with trusted Ed25519 public keys.
        """
        self._trust_store = trust_store
        self._seen_nonces: dict[str, float] = {}
        self._nonce_expiry_seconds: int = 300
        logger.info(
            "NhpJwtValidator initialized. audience=%s, exp_bound=%ds, skew=%ds",
            self.EXPECTED_AUDIENCE,
            self.STRICT_EXP_BOUND_SECONDS,
            self.MAX_CLOCK_SKEW_SECONDS,
        )

    async def validate(self, payload: NhpKnkPayload) -> dict:
        """Full validation pipeline for an NHP-KNK payload.

        Steps:
        1. Decode public_key from base64
        2. Verify public key is trusted
        3. Verify JWS signature (Ed25519)
        4. Validate standard claims (iss, aud, exp)
        5. Validate ztcpp_intent structure
        6. Cross-validate cleartext fields vs JWS claims

        Args:
            payload: Validated NhpKnkPayload Pydantic model.

        Returns:
            Dictionary of verified claims from the JWS payload.

        Raises:
            JwtValidationError: On ANY validation failure (fail-closed).
        """
        # Step 1: Decode the base64 public key from cleartext
        public_key_bytes = self._decode_public_key(payload.public_key)

        # Step 2: Verify the node is trusted
        self._verify_trust(payload.node_id, public_key_bytes)

        # Step 3: Verify JWS signature with Ed25519
        claims = self._verify_jws_signature(payload.jws, public_key_bytes)

        # Step 4: Validate standard JWT claims
        self._validate_issuer(claims)
        self._validate_audience(claims)
        self._validate_expiration(claims)

        # Step 5: Validate ztcpp_intent
        self._validate_ztcpp_intent(claims)

        # Step 6: Cross-validate cleartext with signed claims
        self._cross_validate(payload, claims)

        # Step 7: Validate nonce freshness
        self._validate_nonce(payload.nonce)

        logger.info(
            "JWT validation PASSED for node_id=%s, iss=%s",
            payload.node_id,
            claims.get("iss", "unknown"),
        )
        return claims

    def _decode_public_key(self, public_key_b64: str) -> bytes:
        """Decode base64-encoded Ed25519 public key.

        Args:
            public_key_b64: Base64-encoded public key string.

        Returns:
            Raw 32-byte public key.

        Raises:
            JwtValidationError: If decoding fails or key is not 32 bytes.
        """
        try:
            raw = base64.b64decode(public_key_b64)
            if len(raw) != 32:
                raise JwtValidationError(
                    f"Ed25519 public key must be 32 bytes, got {len(raw)}",
                    "invalid_public_key",
                )
            return raw
        except Exception as exc:
            if isinstance(exc, JwtValidationError):
                raise
            raise JwtValidationError(
                f"Failed to decode public key: {exc}",
                "invalid_public_key",
            ) from exc

    def _verify_trust(self, node_id: str, public_key_bytes: bytes) -> None:
        """Verify the node's public key is in the trust store.

        Args:
            node_id: Node identifier from the KNK payload.
            public_key_bytes: Raw 32-byte Ed25519 public key.

        Raises:
            JwtValidationError: If the key is not trusted.
        """
        if not self._trust_store.is_trusted(node_id, public_key_bytes):
            raise JwtValidationError(
                f"Untrusted node: '{node_id}'. Public key not found in trust store.",
                "untrusted_node",
            )

    def _verify_jws_signature(self, jws_token: str, public_key_bytes: bytes) -> dict:
        """Verify the JWS signature using Ed25519.

        Delegates to JwsVerifier for actual cryptographic verification.

        Args:
            jws_token: Compact JWS token.
            public_key_bytes: Raw 32-byte Ed25519 public key.

        Returns:
            Verified claims dictionary.

        Raises:
            JwtValidationError: If signature verification fails.
        """
        try:
            return JwsVerifier.verify_compact(jws_token, public_key_bytes)
        except JwsVerificationError as exc:
            raise JwtValidationError(
                f"JWS signature verification failed: {exc.message}",
                "invalid_signature",
            ) from exc

    def _validate_issuer(self, claims: dict) -> None:
        """Validate the 'iss' (issuer) claim.

        The issuer must be one of the allowed ZTCPP issuers.

        Args:
            claims: Verified JWS claims.

        Raises:
            JwtValidationError: If issuer is missing or not allowed.
        """
        iss = claims.get("iss")
        if not iss or not isinstance(iss, str):
            raise JwtValidationError(
                "Missing or invalid 'iss' claim in JWS payload",
                "missing_claim",
            )
        if iss not in self.VALID_ISSUERS:
            raise JwtValidationError(
                f"Invalid issuer '{iss}'. Allowed: {self.VALID_ISSUERS}",
                "invalid_issuer",
            )

    def _validate_audience(self, claims: dict) -> None:
        """Validate the 'aud' (audience) claim.

        Must exactly match EXPECTED_AUDIENCE.

        Args:
            claims: Verified JWS claims.

        Raises:
            JwtValidationError: If audience is missing or incorrect.
        """
        aud = claims.get("aud")
        if not aud or not isinstance(aud, str):
            raise JwtValidationError(
                "Missing or invalid 'aud' claim in JWS payload",
                "invalid_audience",
            )
        if aud != self.EXPECTED_AUDIENCE:
            raise JwtValidationError(
                f"Invalid audience '{aud}'. Expected '{self.EXPECTED_AUDIENCE}'",
                "invalid_audience",
            )

    def _validate_expiration(self, claims: dict) -> None:
        """Validate the 'exp' (expiration) claim with strict 60s bound.

        Two checks are performed:
        1. Token must not be expired (exp > now - skew).
        2. Token must not expire more than 60s in the future (prevents
           long-lived token abuse or clock manipulation).

        Args:
            claims: Verified JWS claims.

        Raises:
            JwtValidationError: If exp is missing, expired, or too far in future.
        """
        exp = claims.get("exp")
        if not isinstance(exp, (int, float)):
            raise JwtValidationError(
                "Missing or invalid 'exp' claim in JWS payload",
                "missing_claim",
            )

        now = time.time()

        # Check 1: Token must not be expired (with clock skew tolerance)
        if exp < (now - self.MAX_CLOCK_SKEW_SECONDS):
            raise JwtValidationError(
                f"Token expired. exp={exp}, now={now:.1f}, skew={self.MAX_CLOCK_SKEW_SECONDS}s",
                "expired_token",
            )

        # Check 2: Token must not expire more than STRICT_EXP_BOUND_SECONDS from now
        max_allowed_exp = now + self.STRICT_EXP_BOUND_SECONDS + self.MAX_CLOCK_SKEW_SECONDS
        if exp > max_allowed_exp:
            raise JwtValidationError(
                f"Token expiration too far in future. exp={exp}, "
                f"max_allowed={max_allowed_exp:.1f}, "
                f"bound={self.STRICT_EXP_BOUND_SECONDS}s",
                "clock_skew_exceeded",
            )

    def _validate_ztcpp_intent(self, claims: dict) -> None:
        """Validate the 'ztcpp_intent' claim structure.

        Must contain 'action_class' (one of: read, write, execute, manage)
        and 'aomm_level' (integer 0-5).

        Args:
            claims: Verified JWS claims.

        Raises:
            JwtValidationError: If ztcpp_intent is missing or malformed.
        """
        intent = claims.get("ztcpp_intent")
        if not isinstance(intent, dict):
            raise JwtValidationError(
                "Missing or invalid 'ztcpp_intent' claim. Must be a JSON object.",
                "missing_claim",
            )

        action_class = intent.get("action_class")
        if not isinstance(action_class, str):
            raise JwtValidationError(
                f"Invalid action_class '{action_class}'. Must be a string.",
                "missing_claim",
            )

        target_service = intent.get("target_service")
        if not isinstance(target_service, str):
            raise JwtValidationError(
                f"Invalid target_service '{target_service}'. Must be a string.",
                "missing_claim",
            )

    def _cross_validate(self, payload: NhpKnkPayload, claims: dict) -> None:
        """Cross-validate cleartext KNK fields with signed JWS claims.

        The following fields MUST match between cleartext and signed payload:
        - node_id: Must match exactly
        - timestamp: Must match exactly (prevents tampering)
        - nonce: Must match exactly (prevents tampering)

        This prevents an attacker from modifying cleartext fields while
        keeping the signature valid, since the signed claims bind to
        the original values.

        Args:
            payload: Original KNK payload with cleartext fields.
            claims: Verified JWS claims.

        Raises:
            JwtValidationError: If any cross-validation fails.
        """
        # Cross-validate node_id
        signed_node_id = claims.get("node_id")
        if signed_node_id != payload.node_id:
            raise JwtValidationError(
                f"Cross-validation failed: cleartext node_id '{payload.node_id}' "
                f"does not match signed claim '{signed_node_id}'",
                "cross_validation_failed",
            )

        # Cross-validate timestamp
        signed_timestamp = claims.get("timestamp")
        if signed_timestamp != payload.timestamp:
            raise JwtValidationError(
                f"Cross-validation failed: cleartext timestamp '{payload.timestamp}' "
                f"does not match signed claim '{signed_timestamp}'",
                "cross_validation_failed",
            )

        # Cross-validate nonce
        signed_nonce = claims.get("nonce")
        if signed_nonce != payload.nonce:
            raise JwtValidationError(
                f"Cross-validation failed: cleartext nonce '{payload.nonce}' "
                f"does not match signed claim '{signed_nonce}'",
                "cross_validation_failed",
            )

        logger.debug("Cross-validation passed for node_id=%s", payload.node_id)

    def _validate_nonce(self, nonce: str) -> None:
        """Validate nonce freshness to prevent replay attacks.

        Nonces must not have been seen within the expiry window.
        Old nonces are periodically cleaned up.

        Args:
            nonce: Base64-encoded nonce string.

        Raises:
            JwtValidationError: If nonce has been used before.
        """
        now = time.time()
        if nonce in self._seen_nonces:
            raise JwtValidationError(
                f"Nonce reuse detected: '{nonce[:16]}...'. Possible replay attack.",
                "invalid_nonce",
            )
        self._seen_nonces[nonce] = now
        self._cleanup_nonces(now)
        logger.debug("Nonce validated: %s", nonce[:16])

    def _cleanup_nonces(self, now: float) -> None:
        """Remove expired nonces from the seen set."""
        expired = [
            n for n, ts in self._seen_nonces.items()
            if (now - ts) > self._nonce_expiry_seconds
        ]
        for n in expired:
            del self._seen_nonces[n]
        if expired:
            logger.debug("Cleaned up %d expired nonces", len(expired))

    def clear_nonce_cache(self) -> None:
        """Clear the nonce cache. Used in tests."""
        self._seen_nonces.clear()
