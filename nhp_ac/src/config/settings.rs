use serde::Deserialize;
use std::path::PathBuf;

/// NHP-AC (Policy Enforcement Point) configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct NhpAcConfig {
    /// Server bind address
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Server bind port
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,

    /// Maximum concurrent sessions
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Session timeout in seconds
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,

    /// Nonce length in bytes
    #[serde(default = "default_nonce_len")]
    pub nonce_len: usize,

    /// Timestamp drift tolerance in seconds
    #[serde(default = "default_timestamp_drift")]
    pub timestamp_drift_secs: u64,

    /// Maximum JWS token age in seconds (strict bound)
    #[serde(default = "default_max_exp_bound")]
    pub max_exp_bound_secs: u64,

    /// PDP (Python) server URL
    #[serde(default = "default_pdp_url")]
    pub pdp_server_url: String,

    /// Path to trusted public keys directory
    pub trusted_keys_path: Option<PathBuf>,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

fn default_bind_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_bind_port() -> u16 {
    9090
}

fn default_max_sessions() -> usize {
    10_000
}

fn default_session_timeout() -> u64 {
    3600
}

fn default_nonce_len() -> usize {
    24
}

fn default_timestamp_drift() -> u64 {
    300
}

fn default_max_exp_bound() -> u64 {
    60
}

fn default_pdp_url() -> String {
    "http://127.0.0.1:8000/api/v1".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Default for NhpAcConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            bind_port: default_bind_port(),
            max_sessions: default_max_sessions(),
            session_timeout_secs: default_session_timeout(),
            nonce_len: default_nonce_len(),
            timestamp_drift_secs: default_timestamp_drift(),
            max_exp_bound_secs: default_max_exp_bound(),
            pdp_server_url: default_pdp_url(),
            trusted_keys_path: None,
            log_level: default_log_level(),
        }
    }
}
