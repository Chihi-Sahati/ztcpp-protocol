"""Access and Mobility Management Function (AMF) SBA interface."""

from __future__ import annotations

import logging
from typing import Any

from app.sba.http2_client import SBAHttpClient

logger = logging.getLogger(__name__)


class AMFClient:
    """Client for the 3GPP Access and Mobility Management Function.

    Provides session management and subscriber context retrieval.
    """

    def __init__(self, client: SBAHttpClient) -> None:
        self._client = client

    async def get_ue_context(self, supi: str) -> dict[str, Any]:
        """Retrieve UE context from AMF.

        Args:
            supi: Subscription Permanent Identifier.

        Returns:
            UE context dictionary.
        """
        result = await self._client.get_json(
            f"/namf-comm/v1/ue-contexts/{supi}"
        )
        logger.info("AMF UE context retrieved: supi=%s", supi)
        return result

    async def create_amf_session(
        self, supi: str, session_data: dict[str, Any]
    ) -> dict[str, Any]:
        """Create an AMF session for a subscriber.

        Args:
            supi: Subscription Permanent Identifier.
            session_data: Session configuration.

        Returns:
            Session creation response.
        """
        result = await self._client.post_json(
            f"/namf-comm/v1/ue-contexts/{supi}/n1-n2-msg-transfer",
            data=session_data,
        )
        logger.info("AMF session created: supi=%s", supi)
        return result
