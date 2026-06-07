"""SBA (Service-Based Architecture) HTTP/2 client.

Implements the HTTP/2 client used to communicate with 3GPP SBA services
(NRF, AMF, PCF) using the httpx library with HTTP/2 support.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import httpx

logger = logging.getLogger(__name__)

DEFAULT_SBA_TIMEOUT_SECONDS: float = 10.0
DEFAULT_SBA_BASE_URL: str = "http://nrf:8000"


class SBAHttpClient:
    """HTTP/2 client for 3GPP SBA communication.

    Provides authenticated HTTP/2 connections to 3GPP Network Repository
    Function (NRF) and other SBA services. Uses OAuth2 token-based
    authentication per 3GPP TS 33.501.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_SBA_BASE_URL,
        timeout: float = DEFAULT_SBA_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the SBA HTTP/2 client.

        Args:
            base_url: Base URL for the NRF/SBA service.
            timeout: Request timeout in seconds.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._access_token: Optional[str] = None
        logger.info(
            "SBAHttpClient initialized: base_url=%s, timeout=%.1fs",
            self._base_url,
            self._timeout,
        )

    def _get_client(self) -> httpx.AsyncClient:
        """Create an httpx AsyncClient with HTTP/2 support.

        Returns:
            Configured httpx.AsyncClient instance.
        """
        headers = {"Accept": "application/json"}
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"

        return httpx.AsyncClient(
            base_url=self._base_url,
            http2=True,
            timeout=self._timeout,
            headers=headers,
        )

    async def post_json(
        self,
        path: str,
        data: dict[str, Any],
        headers: Optional[dict[str, str]] = None,
    ) -> dict[str, Any]:
        """Send an HTTP/2 POST request with JSON body.

        Args:
            path: API path relative to base_url.
            data: JSON body dictionary.
            headers: Additional headers.

        Returns:
            Response JSON dictionary.

        Raises:
            httpx.HTTPStatusError: On HTTP error status.
        """
        extra_headers = headers or {}
        async with self._get_client() as client:
            response = await client.post(path, json=data, headers=extra_headers)
            response.raise_for_status()
            return response.json()

    async def get_json(
        self,
        path: str,
        params: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Send an HTTP/2 GET request.

        Args:
            path: API path relative to base_url.
            params: Query parameters.

        Returns:
            Response JSON dictionary.

        Raises:
            httpx.HTTPStatusError: On HTTP error status.
        """
        async with self._get_client() as client:
            response = await client.get(path, params=params)
            response.raise_for_status()
            return response.json()

    async def set_access_token(self, token: str) -> None:
        """Set the OAuth2 access token for SBA authentication."""
        self._access_token = token
        logger.info("SBA access token set (length=%d)", len(token))
