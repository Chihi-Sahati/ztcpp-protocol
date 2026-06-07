use thiserror::Error;

/// Top-level NHP-AC error type.
#[derive(Debug, Error)]
pub enum NhpAcError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("State machine error: {0}")]
    StateMachine(String),

    #[error("Policy error: {0}")]
    Policy(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session limit reached: {0}/{1}")]
    SessionLimitReached(usize, usize),

    #[error("Replay detected: nonce={0}")]
    ReplayDetected(String),
}
