"""Tests for NHP State Machine transitions."""

from __future__ import annotations

import pytest

from app.protocol.state_machine import (
    InvalidStateTransition,
    NhpState,
    NhpStateMachine,
)


class TestNhpStateMachine:

    def test_initial_state(self):
        """State machine should start in IDLE state."""
        sm = NhpStateMachine()
        assert sm.state == NhpState.IDLE
        assert sm.termination_reason is None
        assert not sm.is_terminal

    def test_full_happy_path(self):
        """Complete happy path: IDLE -> KNOCK_SENT -> POLICY_EVAL -> TUNNEL_PROVISIONED -> SESSION_ACTIVE."""
        sm = NhpStateMachine()
        sm.process_knk("agent-001")
        assert sm.state == NhpState.KNOCK_SENT

        sm.evaluate_policy()
        assert sm.state == NhpState.POLICY_EVAL

        sm.provision_tunnel()
        assert sm.state == NhpState.TUNNEL_PROVISIONED

        sm.activate_session("sess-123")
        assert sm.state == NhpState.SESSION_ACTIVE
        assert sm.is_terminal

    def test_terminate_from_idle(self):
        """Terminate from IDLE state should work."""
        sm = NhpStateMachine()
        sm.terminate("test reason")
        assert sm.state == NhpState.SESSION_TERMINATED
        assert sm.termination_reason == "test reason"
        assert sm.is_terminal

    def test_terminate_from_any_state(self):
        """Terminate should work from any non-terminal state."""
        for state_name in ["knock_sent", "policy_eval", "tunnel_provisioned", "session_active"]:
            sm = NhpStateMachine()
            if state_name == "knock_sent":
                sm.process_knk("agent-001")
            elif state_name == "policy_eval":
                sm.process_knk("agent-001")
                sm.evaluate_policy()
            elif state_name == "tunnel_provisioned":
                sm.process_knk("agent-001")
                sm.evaluate_policy()
                sm.provision_tunnel()
            elif state_name == "session_active":
                sm.process_knk("agent-001")
                sm.evaluate_policy()
                sm.provision_tunnel()
                sm.activate_session("sess")

            sm.terminate("security violation")
            assert sm.state == NhpState.SESSION_TERMINATED
            assert sm.termination_reason == "security violation"

    def test_invalid_transition_raises(self):
        """Invalid state transitions should raise InvalidStateTransition."""
        sm = NhpStateMachine()

        # Cannot evaluate policy before processing KNK
        with pytest.raises(InvalidStateTransition):
            sm.evaluate_policy()

        # Cannot provision tunnel before evaluating policy
        sm.process_knk("agent-001")
        with pytest.raises(InvalidStateTransition):
            sm.provision_tunnel()

        # Cannot activate session before tunnel provisioning
        sm.evaluate_policy()
        with pytest.raises(InvalidStateTransition):
            sm.activate_session("sess-123")

    def test_transition_from_terminated_raises(self):
        """Any transition from TERMINATED state should raise except reset."""
        sm = NhpStateMachine()
        sm.terminate("reason")

        with pytest.raises(InvalidStateTransition):
            sm.process_knk("agent-001")
        with pytest.raises(InvalidStateTransition):
            sm.evaluate_policy()
        with pytest.raises(InvalidStateTransition):
            sm.provision_tunnel()
        with pytest.raises(InvalidStateTransition):
            sm.activate_session("sess-123")
        with pytest.raises(InvalidStateTransition):
            sm.terminate("another reason")

    def test_double_process_knk_raises(self):
        """Calling process_knk twice should raise."""
        sm = NhpStateMachine()
        sm.process_knk("agent-001")
        with pytest.raises(InvalidStateTransition):
            sm.process_knk("agent-002")

    def test_reset_returns_to_idle(self):
        """Reset should return to IDLE state."""
        sm = NhpStateMachine()
        sm.process_knk("agent-001")
        sm.evaluate_policy()
        sm.terminate("reason")

        sm.reset()
        assert sm.state == NhpState.IDLE
        assert sm.termination_reason is None
        assert not sm.is_terminal
