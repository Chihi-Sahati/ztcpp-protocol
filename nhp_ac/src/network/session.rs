use std::collections::HashMap;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// An active NHP session.
pub struct NhpSession {
    pub session_id: String,
    pub node_id: String,
    pub created_at: Instant,
    pub expires_at: Instant,
    pub encryption_key: Option<[u8; 32]>,
    pub allowed_capabilities: Vec<String>,
}

impl NhpSession {
    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Session manager for tracking active NHP sessions.
pub struct SessionManager {
    sessions: HashMap<String, NhpSession>,
    session_timeout: Duration,
}

impl SessionManager {
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            session_timeout: Duration::from_secs(timeout_secs),
        }
    }

    pub fn create_session(
        &mut self,
        node_id: String,
        capabilities: Vec<String>,
    ) -> String {
        let session_id = Uuid::new_v4().to_string();
        let now = Instant::now();
        let session = NhpSession {
            session_id: session_id.clone(),
            node_id,
            created_at: now,
            expires_at: now + self.session_timeout,
            encryption_key: None,
            allowed_capabilities: capabilities,
        };
        self.sessions.insert(session_id.clone(), session);
        session_id
    }

    pub fn get_session(&self, session_id: &str) -> Option<&NhpSession> {
        self.sessions.get(session_id)
    }

    pub fn remove_session(&mut self, session_id: &str) -> Option<NhpSession> {
        self.sessions.remove(session_id)
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn cleanup_expired(&mut self) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| !s.is_expired());
        before - self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_session() {
        let mut sm = SessionManager::new(3600);
        let id = sm.create_session("agent-001".to_string(), vec!["read".to_string()]);
        let session = sm.get_session(&id).expect("session");
        assert_eq!(session.node_id, "agent-001");
        assert_eq!(sm.active_count(), 1);
    }

    #[test]
    fn test_remove_session() {
        let mut sm = SessionManager::new(3600);
        let id = sm.create_session("agent-001".to_string(), vec![]);
        sm.remove_session(&id);
        assert!(sm.get_session(&id).is_none());
    }

    #[test]
    fn test_cleanup() {
        let mut sm = SessionManager::new(0); // 0 timeout = immediately expired
        sm.create_session("agent-001".to_string(), vec![]);
        std::thread::sleep(Duration::from_millis(10));
        let cleaned = sm.cleanup_expired();
        assert_eq!(cleaned, 1);
        assert_eq!(sm.active_count(), 0);
    }
}
