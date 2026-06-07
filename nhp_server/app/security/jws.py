"""JWS verification module using the jwcrypto library.

Implements real Ed25519 (EdDSA) signature verification on compact JWS tokens.
No mock logic - every operation performs actual cryptographic verification.
"""

from __future__ import annotations

import base64
import json
import logging

from jwcrypto import jwk, jws

logger = logging.getLogger(__name__)


class JwsVerificationError(Exception):
    """Raised when JWS signature verification fails."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class JwsVerifier:
    """Ed25519 JWS compact token verifier.

    Verifies compact JWS tokens using EdDSA (Ed25519) signatures.
    The verifier expects tokens formatted as: header.payload.signature
    where the header contains alg=EdDSA and the payload is base64url-encoded JSON.
    """

    @staticmethod
    def _bytes_to_jwk(public_key_bytes: bytes) -> jwk.JWK:
        """Convert raw 32-byte Ed25519 public key to a JWK object.

        The JWK must have:
            kty: OKP
            crv: Ed25519
            x: base64url-encoded 32 bytes

        Args:
            public_key_bytes: Raw 32-byte Ed25519 public key.

        Returns:
            JWK object configured for Ed25519 verification.

        Raises:
            JwsVerificationError: If key is not 32 bytes.
        """
        if len(public_key_bytes) != 32:
            raise JwsVerificationError(
                f"Ed25519 public key must be exactly 32 bytes, got {len(public_key_bytes)}"
            )
        try:
            key_b64 = base64.urlsafe_b64encode(public_key_bytes).rstrip(b"=").decode("ascii")
            jwk_obj = jwk.JWK(
                kty="OKP",
                crv="Ed25519",
                x=key_b64,
            )
            return jwk_obj
        except Exception as exc:
            raise JwsVerificationError(
                f"Failed to create JWK from Ed25519 key bytes: {exc}"
            ) from exc

    @classmethod
    def verify_compact(cls, jws_token: str, public_key_bytes: bytes) -> dict:
        """Verify a compact JWS token with an Ed25519 public key.

        Performs the following steps:
        1. Convert the raw 32-byte Ed25519 key to JWK format.
        2. Parse the compact JWS token (header.payload.signature).
        3. Verify the EdDSA signature.
        4. Decode and return the payload claims as a dict.

        Args:
            jws_token: Compact JWS token string (header.payload.signature).
            public_key_bytes: Raw 32-byte Ed25519 public key for verification.

        Returns:
            Dictionary of verified payload claims.

        Raises:
            JwsVerificationError: On any signature, format, or decoding failure.
        """
        if not jws_token or not isinstance(jws_token, str):
            raise JwsVerificationError("JWS token must be a non-empty string")

        parts = jws_token.split(".")
        if len(parts) != 3:
            raise JwsVerificationError(
                f"Invalid compact JWS format: expected 3 parts, got {len(parts)}"
            )

        try:
            # Decode header to verify algorithm
            header_b64 = parts[0]
            header_b64_padded = header_b64 + "=" * (4 - len(header_b64) % 4) if len(header_b64) % 4 else header_b64
            header_json = base64.urlsafe_b64decode(header_b64_padded)
            header = json.loads(header_json)

            alg = header.get("alg", "")
            if alg != "EdDSA":
                raise JwsVerificationError(
                    f"Unsupported JWS algorithm: '{alg}'. Only EdDSA (Ed25519) is allowed."
                )
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            raise JwsVerificationError(
                f"Failed to decode JWS header: {exc}"
            ) from exc

        # Create JWK and verify
        jwk_key = cls._bytes_to_jwk(public_key_bytes)

        try:
            jws_obj = jws.JWS()
            jws_obj.deserialize(jws_token)
            jws_obj.verify(jwk_key)
            payload_json = jws_obj.payload
            if isinstance(payload_json, bytes):
                claims = json.loads(payload_json.decode("utf-8"))
            else:
                claims = json.loads(payload_json)

            logger.info(
                "JWS verified successfully. Claims keys: %s",
                list(claims.keys()),
            )
            return claims

        except jws.InvalidJWSSignature as exc:
            raise JwsVerificationError(
                f"Ed25519 signature verification failed: {exc}"
            ) from exc
        except jws.InvalidJWSObject as exc:
            raise JwsVerificationError(
                f"Invalid JWS object: {exc}"
            ) from exc
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise JwsVerificationError(
                f"Failed to decode JWS payload: {exc}"
            ) from exc
        except Exception as exc:
            raise JwsVerificationError(
                f"Unexpected JWS verification error: {exc}"
            ) from exc

    @staticmethod
    def create_compact_eddsa(payload_claims: dict, private_key_bytes: bytes) -> str:
        """Create a compact JWS token signed with Ed25519 (EdDSA).

        Utility method for creating test tokens. In production, tokens
        are created by the LLM agent nodes.

        Args:
            payload_claims: Dictionary of claims to sign.
            private_key_bytes: Raw 32-byte Ed25519 private key (64-byte seed+public).

        Returns:
            Compact JWS token string.
        """
        key_b64 = base64.urlsafe_b64encode(private_key_bytes[:32]).rstrip(b"=").decode("ascii")
        jwk_key = jwk.JWK(
            kty="OKP",
            crv="Ed25519",
            d=key_b64,
            x=base64.urlsafe_b64encode(private_key_bytes[32:]).rstrip(b"=").decode("ascii"),
        )

        header = {"alg": "EdDSA", "typ": "JWS"}
        payload_bytes = json.dumps(payload_claims).encode("utf-8")

        jws_obj = jws.JWS(payload=payload_bytes)
        jws_obj.add_signature(
            key=jwk_key,
            alg="EdDSA",
            protected=json.dumps(header),
        )

        json_obj = json.loads(jws_obj.serialize(compact=True))
        return json_obj if isinstance(json_obj, str) else jws_obj.serialize(compact=True)
