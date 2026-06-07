"""Policy Control Function (PCF) SBA interface."""

from __future__ import annotations

import logging
from typing import Any

from app.sba.http2_client import SBAHttpClient

logger = logging.getLogger(__name__)


class PCFClient:
    """Client for the 3GPP Policy Control Function.

    Provides policy decision retrieval and session policy management.
    """

    def __init__(self, client: SBAHttpClient) -> None:
        self._client = client

    async def get_policy_decision(
        self, pcf_id: str, policy_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Retrieve a policy decision from the PCF.

        Args:
            pcf_id: Policy Control Function instance ID.
            policy_data: Policy request data.

        Returns:
            Policy decision dictionary.
        """
        result = await self._client.post_json(
            f"/npcf-policydecision/v1/decisions/{pcf_id}",
            data=policy_data,
        )
        logger.info("PCF policy decision retrieved: pcf_id=%s", pcf_id)
        return result

    async def create_policy_session(
        self, session_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a new policy session at the PCF.

        Args:
            session_data: Policy session configuration.

        Returns:
            Policy session response.
        """
        result = await self._client.post_json(
            "/npcf-policyauthorization/v1/policy-sessions",
            data=session_data,
        )
        logger.info("PCF policy session created")
        return result
