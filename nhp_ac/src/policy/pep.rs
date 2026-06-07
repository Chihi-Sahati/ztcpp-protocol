/// NHP Policy Enforcement Point (PEP).
///
/// The PEP enforces policy decisions received from the PDP (NHP-Server).
/// It manages session lifecycle, applies crypto operations, and
/// controls network access based on policy decisions.
pub struct NhpPep {
    max_sessions: usize,
    active_sessions: usize,
}

impl NhpPep {
    /// Create a new PEP with the given session limit.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            max_sessions,
            active_sessions: 0,
        }
    }

    /// Check if a new session can be established.
    pub fn can_accept_session(&self) -> bool {
        self.active_sessions < self.max_sessions
    }

    /// Increment active session count.
    pub fn increment_sessions(&mut self) {
        self.active_sessions += 1;
    }

    /// Decrement active session count.
    pub fn decrement_sessions(&mut self) {
        self.active_sessions = self.active_sessions.saturating_sub(1);
    }

    /// Get the number of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.active_sessions
    }

    /// Get the maximum session limit.
    pub fn max_session_limit(&self) -> usize {
        self.max_sessions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pep() {
        let pep = NhpPep::new(100);
        assert!(pep.can_accept_session());
        assert_eq!(pep.active_session_count(), 0);
    }

    #[test]
    fn test_session_limit() {
        let mut pep = NhpPep::new(2);
        assert!(pep.can_accept_session());
        pep.increment_sessions();
        assert!(pep.can_accept_session());
        pep.increment_sessions();
        assert!(!pep.can_accept_session());
    }

    #[test]
    fn test_session_teardown() {
        let mut pep = NhpPep::new(2);
        pep.increment_sessions();
        pep.increment_sessions();
        pep.decrement_sessions();
        assert!(pep.can_accept_session());
    }
}
