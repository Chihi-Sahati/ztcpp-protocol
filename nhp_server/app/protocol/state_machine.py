"""NHP State Machine implementation.

Implements the 5-state NHP protocol state machine as specified in the research draft:
S0: IDLE -> S1: KNOCK_SENT -> S2: POLICY_EVAL -> S3: TUNNEL_PROVISIONED -> S4: SESSION_ACTIVE
Any state -> S5: SESSION_TERMINATED
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class NhpState(str, Enum):
    """NHP protocol states."""

    IDLE = "S0_IDLE"
    KNOCK_SENT = "S1_KNOCK_SENT"
    POLICY_EVAL = "S2_POLICY_EVAL"
    TUNNEL_PROVISIONED = "S3_TUNNEL_PROVISIONED"
    SESSION_ACTIVE = "S4_SESSION_ACTIVE"
    SESSION_TERMINATED = "S5_SESSION_TERMINATED"


VALID_TRANSITIONS: dict[NhpState, set[NhpState]] = {
    NhpState.IDLE: {NhpState.KNOCK_SENT, NhpState.SESSION_TERMINATED},
    NhpState.KNOCK_SENT: {NhpState.POLICY_EVAL, NhpState.SESSION_TERMINATED},
    NhpState.POLICY_EVAL: {NhpState.TUNNEL_PROVISIONED, NhpState.SESSION_TERMINATED},
    NhpState.TUNNEL_PROVISIONED: {NhpState.SESSION_ACTIVE, NhpState.SESSION_TERMINATED},
    NhpState.SESSION_ACTIVE: {NhpState.SESSION_TERMINATED},
    NhpState.SESSION_TERMINATED: {NhpState.IDLE},
}


class InvalidStateTransition(Exception):
    """Raised when an invalid state transition is attempted."""

    def __init__(self, current: NhpState, target: NhpState) -> None:
        self.current = current
        self.target = target
        super().__init__(
            f"Invalid transition: {current.value} -> {target.value}"
        )


class NhpStateMachine:
    """NHP protocol state machine with strict transition enforcement.

    The state machine tracks the progression of an NHP handshake from
    initial state through to session establishment or termination.

    Usage:
        sm = NhpStateMachine()
        sm.process_knk()         # S0 -> S1
        sm.evaluate_policy()     # S1 -> S2
        sm.provision_tunnel()    # S2 -> S3
        sm.activate_session()    # S3 -> S4
        sm.terminate("reason")   # Any -> S5
    """

    def __init__(self) -> None:
        self._state = NhpState.IDLE
        self._termination_reason: Optional[str] = None
        self._session_id: Optional[str] = None
        self._node_id: Optional[str] = None
        self._transition_count = 0
        logger.info("NhpStateMachine initialized in state: %s", self._state.value)

    @property
    def state(self) -> NhpState:
        """Current state of the state machine."""
        return self._state

    @property
    def termination_reason(self) -> Optional[str]:
        """Termination reason if state is SESSION_TERMINATED."""
        return self._termination_reason

    @property
    def is_terminal(self) -> bool:
        """Whether the machine is in a terminal state."""
        return self._state in (NhpState.SESSION_ACTIVE, NhpState.SESSION_TERMINATED)

    def _transition(self, target: NhpState) -> None:
        """Execute a state transition with validation."""
        allowed = VALID_TRANSITIONS.get(self._state, set())
        if target not in allowed:
            raise InvalidStateTransition(self._state, target)

        old_state = self._state
        self._state = target
        self._transition_count += 1
        logger.info(
            "State transition: %s -> %s (count=%d)",
            old_state.value,
            target.value,
            self._transition_count,
        )

    def process_knk(self, node_id: str) -> None:
        """Process incoming KNK payload. Transition: S0_IDLE -> S1_KNOCK_SENT.

        Args:
            node_id: Node identifier from the KNK payload.
        """
        if self._state != NhpState.IDLE:
            raise InvalidStateTransition(self._state, NhpState.KNOCK_SENT)
        self._node_id = node_id
        self._transition(NhpState.KNOCK_SENT)

    def evaluate_policy(self) -> None:
        """Evaluate policy (NHP-AOP). Transition: S1_KNOCK_SENT -> S2_POLICY_EVAL."""
        self._transition(NhpState.POLICY_EVAL)

    def provision_tunnel(self) -> None:
        """Provision Tunnel (NHP-ART received, sending NHP-ACK). Transition: S2_POLICY_EVAL -> S3_TUNNEL_PROVISIONED."""
        self._transition(NhpState.TUNNEL_PROVISIONED)

    def activate_session(self, session_id: str) -> None:
        """Activate session (NHP-ACC). Transition: S3_TUNNEL_PROVISIONED -> S4_SESSION_ACTIVE."""
        self._session_id = session_id
        self._transition(NhpState.SESSION_ACTIVE)

    def terminate(self, reason: str) -> None:
        """Terminate the session. Transition: Any -> S5_SESSION_TERMINATED.

        Args:
            reason: Termination reason for audit logging.
        """
        self._termination_reason = reason
        self._transition(NhpState.SESSION_TERMINATED)
        logger.warning(
            "Session TERMINATED: reason=%s, node_id=%s",
            reason,
            self._node_id,
        )

    def reset(self) -> None:
        """Reset the state machine to initial state. Transition: S5_SESSION_TERMINATED -> S0_IDLE."""
        if self._state != NhpState.SESSION_TERMINATED and self._state != NhpState.IDLE:
             raise InvalidStateTransition(self._state, NhpState.IDLE)
        self._state = NhpState.IDLE
        self._termination_reason = None
        self._session_id = None
        self._node_id = None
        self._transition_count = 0
        logger.info("NhpStateMachine reset to S0_IDLE")
