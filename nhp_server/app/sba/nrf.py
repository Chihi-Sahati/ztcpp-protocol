"""Network Repository Function (NRF) SBA interface.

Implements the 3GPP NRF service discovery and registration APIs
as defined in 3GPP TS 29.510.
"""

from __future__ import annotations

import logging
from typing import Any

from app.sba.http2_client import SBAHttpClient

logger = logging.getLogger(__name__)


class NRFClient:
    """Client for the 3GPP Network Repository Function.

    Provides:
    - Service registration (NF Registration)
    - Service discovery
    - NF status subscription
    """

    def __init__(self, client: SBAHttpClient) -> None:
        self._client = client

    async def discover_service(
        self,
        service_name: str,
        nf_type: str = "NHPS",
    ) -> list[dict[str, Any]]:
        """Discover service instances from the NRF.

        Args:
            service_name: Name of the service to discover.
            nf_type: Network Function type (default: NHPS).

        Returns:
            List of service instance descriptors.
        """
        params = {
            "service-name": service_name,
            "nf-type": nf_type,
        }
        result = await self._client.get_json("/nnrf-disc/v1/nf-instances", params=params)
        logger.info(
            "NRF service discovery: service=%s, nf_type=%s, results=%d",
            service_name,
            nf_type,
            len(result) if isinstance(result, list) else 1,
        )
        return result if isinstance(result, list) else [result]

    async def register_nf(
        self,
        nf_instance_id: str,
        nf_profile: dict[str, Any],
    ) -> dict[str, Any]:
        """Register a Network Function instance with the NRF.

        Args:
            nf_instance_id: Unique NF instance identifier.
            nf_profile: NF profile configuration.

        Returns:
            NRF registration response.
        """
        result = await self._client.post_json(
            f"/nnrf-nfm/v1/nf-instances/{nf_instance_id}",
            data=nf_profile,
        )
        logger.info("NRF registration: nf_id=%s", nf_instance_id)
        return result
