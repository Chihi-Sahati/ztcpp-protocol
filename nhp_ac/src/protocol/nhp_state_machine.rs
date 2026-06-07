use thiserror::Error;

/// NHP protocol states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NhpState {
    Idle,
    KnockSent,
    PolicyEval,
    TunnelProvisioned,
    SessionActive,
    SessionTerminated,
}

/// Error type for state machine transitions.
#[derive(Debug, Error)]
pub enum StateMachineError {
    #[error("Invalid transition: {from} -> {to}")]
    InvalidTransition {
        from: String,
        to: String,
    },

    #[error("Already in terminal state: {0}")]
    TerminalState(String),
}

/// NHP State Machine - mirrors the Python implementation.
///
/// States: Idle -> KnockSent -> PolicyEval -> TunnelProvisioned -> SessionActive
/// Any state -> SessionTerminated
pub struct NhpStateMachine {
    state: NhpState,
    termination_reason: Option<String>,
    node_id: Option<String>,
    session_id: Option<String>,
    transition_count: u32,
}

impl NhpStateMachine {
    /// Create a new state machine in Idle state.
    pub fn new() -> Self {
        Self {
            state: NhpState::Idle,
            termination_reason: None,
            node_id: None,
            session_id: None,
            transition_count: 0,
        }
    }

    /// Get the current state.
    pub fn current_state(&self) -> &NhpState {
        &self.state
    }

    /// Get the termination reason (if terminated).
    pub fn termination_reason(&self) -> Option<&str> {
        self.termination_reason.as_deref()
    }

    /// Process incoming KNK payload: Idle -> KnockSent.
    pub fn process_knk(&mut self, node_id: String) -> Result<(), StateMachineError> {
        self.ensure_not_terminated()?;
        self.ensure_state(&NhpState::Idle, "KnockSent")?;
        self.node_id = Some(node_id);
        self.transition(NhpState::KnockSent)
    }

    /// Evaluate policy: KnockSent -> PolicyEval.
    pub fn evaluate_policy(&mut self) -> Result<(), StateMachineError> {
        self.ensure_not_terminated()?;
        self.ensure_state(&NhpState::KnockSent, "PolicyEval")?;
        self.transition(NhpState::PolicyEval)
    }

    /// Provision tunnel: PolicyEval -> TunnelProvisioned.
    pub fn provision_tunnel(&mut self) -> Result<(), StateMachineError> {
        self.ensure_not_terminated()?;
        self.ensure_state(&NhpState::PolicyEval, "TunnelProvisioned")?;
        self.transition(NhpState::TunnelProvisioned)
    }

    /// Activate session: TunnelProvisioned -> SessionActive.
    pub fn activate_session(&mut self, session_id: String) -> Result<(), StateMachineError> {
        self.ensure_not_terminated()?;
        self.ensure_state(&NhpState::TunnelProvisioned, "SessionActive")?;
        self.session_id = Some(session_id);
        self.transition(NhpState::SessionActive)
    }

    /// Terminate the session: Any -> SessionTerminated.
    pub fn terminate(&mut self, reason: &str) -> Result<(), StateMachineError> {
        if self.state == NhpState::SessionTerminated {
            return Err(StateMachineError::TerminalState("terminated".to_string()));
        }
        self.termination_reason = Some(reason.to_string());
        self.transition(NhpState::SessionTerminated)
    }

    /// Check if the machine is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self.state, NhpState::SessionActive | NhpState::SessionTerminated)
    }

    /// Reset to initial state.
    pub fn reset(&mut self) {
        self.state = NhpState::Idle;
        self.termination_reason = None;
        self.node_id = None;
        self.session_id = None;
        self.transition_count = 0;
    }

    fn ensure_not_terminated(&self) -> Result<(), StateMachineError> {
        if self.state == NhpState::SessionTerminated {
            Err(StateMachineError::TerminalState("terminated".to_string()))
        } else {
            Ok(())
        }
    }

    fn ensure_state(&self, expected: &NhpState, target_name: &str) -> Result<(), StateMachineError> {
        if self.state != *expected {
            Err(StateMachineError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: target_name.to_string(),
            })
        } else {
            Ok(())
        }
    }

    fn transition(&mut self, target: NhpState) -> Result<(), StateMachineError> {
        self.state = target;
        self.transition_count += 1;
        Ok(())
    }
}

impl Default for NhpStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sm = NhpStateMachine::new();
        assert_eq!(sm.current_state(), &NhpState::Idle);
        assert!(!sm.is_terminal());
    }

    #[test]
    fn test_full_happy_path() {
        let mut sm = NhpStateMachine::new();
        sm.process_knk("agent-001".to_string()).unwrap();
        assert_eq!(sm.current_state(), &NhpState::KnockSent);

        sm.evaluate_policy().unwrap();
        assert_eq!(sm.current_state(), &NhpState::PolicyEval);

        sm.provision_tunnel().unwrap();
        assert_eq!(sm.current_state(), &NhpState::TunnelProvisioned);

        sm.activate_session("sess-123".to_string()).unwrap();
        assert_eq!(sm.current_state(), &NhpState::SessionActive);
        assert!(sm.is_terminal());
    }

    #[test]
    fn test_terminate_from_idle() {
        let mut sm = NhpStateMachine::new();
        sm.terminate("test reason").unwrap();
        assert_eq!(sm.current_state(), &NhpState::SessionTerminated);
        assert_eq!(sm.termination_reason(), Some("test reason"));
    }

    #[test]
    fn test_invalid_transition() {
        let mut sm = NhpStateMachine::new();
        let result = sm.evaluate_policy();
        assert!(result.is_err());
    }

    #[test]
    fn test_transition_from_terminated() {
        let mut sm = NhpStateMachine::new();
        sm.terminate("reason").unwrap();
        assert!(sm.process_knk("agent".to_string()).is_err());
        assert!(sm.evaluate_policy().is_err());
        assert!(sm.provision_tunnel().is_err());
        assert!(sm.activate_session("sess".to_string()).is_err());
    }

    #[test]
    fn test_reset() {
        let mut sm = NhpStateMachine::new();
        sm.process_knk("agent".to_string()).unwrap();
        sm.evaluate_policy().unwrap();
        sm.terminate("reason").unwrap();
        sm.reset();
        assert_eq!(sm.current_state(), &NhpState::Idle);
        assert!(!sm.is_terminal());
    }
}
