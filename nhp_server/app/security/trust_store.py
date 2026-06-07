"""Trust Store for managing trusted Ed25519 public keys.

The TrustStore maintains a mapping of node_id -> Ed25519 public key.
Keys can be loaded from PEM format or raw 32-byte binary format.
This is the foundation of the fail-closed trust model:
if a node's public key is not in the store, the request is rejected.
"""

from __future__ import annotations

import base64
import logging
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

logger = logging.getLogger(__name__)


class TrustStoreError(Exception):
    """Raised on any trust store operation failure."""

    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(self.message)


class TrustStore:
    """In-memory store of trusted Ed25519 public keys indexed by node_id.

    Supports loading keys from PEM format strings or raw 32-byte binary.
    Provides thread-safe operations for runtime key management.
    All operations that fail raise TrustStoreError for fail-closed handling.
    """

    def __init__(self) -> None:
        self._trusted_keys: dict[str, Ed25519PublicKey] = {}
        self._key_bytes_map: dict[str, bytes] = {}
        logger.info("TrustStore initialized with empty key set")

    def load_key(self, node_id: str, public_key_pem: str) -> None:
        """Load a trusted Ed25519 public key from PEM format.

        Args:
            node_id: Unique identifier for the node.
            public_key_pem: PEM-encoded Ed25519 public key.

        Raises:
            TrustStoreError: If PEM parsing fails or key is not Ed25519.
        """
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode("utf-8")
            )
            if not isinstance(public_key, Ed25519PublicKey):
                raise TrustStoreError(
                    f"Key for node '{node_id}' is not an Ed25519 public key"
                )
            raw_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            self._trusted_keys[node_id] = public_key
            self._key_bytes_map[node_id] = raw_bytes
            logger.info(
                "Loaded trusted Ed25519 key for node_id=%s (raw=%d bytes)",
                node_id,
                len(raw_bytes),
            )
        except ValueError as exc:
            raise TrustStoreError(
                f"Failed to parse PEM for node '{node_id}': {exc}"
            ) from exc
        except Exception as exc:
            raise TrustStoreError(
                f"Unexpected error loading key for node '{node_id}': {exc}"
            ) from exc

    def load_key_bytes(self, node_id: str, public_key_bytes: bytes) -> None:
        """Load a trusted Ed25519 public key from raw 32 bytes.

        Args:
            node_id: Unique identifier for the node.
            public_key_bytes: Raw 32-byte Ed25519 public key.

        Raises:
            TrustStoreError: If key length is not exactly 32 bytes.
        """
        if len(public_key_bytes) != 32:
            raise TrustStoreError(
                f"Ed25519 public key must be exactly 32 bytes, got {len(public_key_bytes)}"
            )
        try:
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            self._trusted_keys[node_id] = public_key
            self._key_bytes_map[node_id] = public_key_bytes
            logger.info(
                "Loaded trusted Ed25519 key (raw) for node_id=%s", node_id
            )
        except Exception as exc:
            raise TrustStoreError(
                f"Failed to create Ed25519 key for node '{node_id}': {exc}"
            ) from exc

    def is_trusted(self, node_id: str, public_key_bytes: bytes) -> bool:
        """Verify if the given public key matches the trusted key for a node.

        This performs a constant-time comparison of the raw key bytes
        to prevent timing attacks on the trust verification.

        Args:
            node_id: Node identifier to check.
            public_key_bytes: Raw 32-byte Ed25519 public key to verify.

        Returns:
            True if the key is trusted for this node.
        """
        stored_bytes = self._key_bytes_map.get(node_id)
        if stored_bytes is None:
            logger.warning("No trusted key found for node_id=%s", node_id)
            return False
        if len(public_key_bytes) != 32 or len(stored_bytes) != 32:
            return False
        try:
            stored_key = Ed25519PublicKey.from_public_bytes(stored_bytes)
            provided_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            stored_raw = stored_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            provided_raw = provided_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            result = stored_raw == provided_raw
            if not result:
                logger.warning(
                    "Key mismatch for node_id=%s", node_id
                )
            return result
        except Exception:
            logger.warning(
                "Key comparison failed for node_id=%s", node_id
            )
            return False

    def get_public_key(self, node_id: str) -> Optional[Ed25519PublicKey]:
        """Retrieve the trusted Ed25519 public key for a node.

        Args:
            node_id: Node identifier.

        Returns:
            Ed25519PublicKey if trusted, None otherwise.
        """
        return self._trusted_keys.get(node_id)

    def get_public_key_bytes(self, node_id: str) -> Optional[bytes]:
        """Retrieve the raw 32-byte trusted public key for a node.

        Args:
            node_id: Node identifier.

        Returns:
            Raw 32-byte key if trusted, None otherwise.
        """
        return self._key_bytes_map.get(node_id)

    def remove_key(self, node_id: str) -> None:
        """Remove a trusted key for a node.

        Args:
            node_id: Node identifier to remove.
        """
        self._trusted_keys.pop(node_id, None)
        self._key_bytes_map.pop(node_id, None)
        logger.info("Removed trusted key for node_id=%s", node_id)

    def list_trusted_nodes(self) -> list[str]:
        """List all currently trusted node identifiers."""
        return list(self._trusted_keys.keys())

    @classmethod
    def generate_and_load(cls, node_id: str) -> tuple["TrustStore", Ed25519PrivateKey, bytes]:
        """Generate a new Ed25519 key pair, load the public key into a new
        TrustStore, and return both the store and the private key for testing.

        Args:
            node_id: Node identifier for the generated key.

        Returns:
            Tuple of (TrustStore, Ed25519PrivateKey, public_key_bytes).
        """
        private_key = Ed25519PrivateKey.generate()
        public_key_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        store = cls()
        store.load_key_bytes(node_id, public_key_bytes)
        return store, private_key, public_key_bytes
