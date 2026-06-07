use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImpactScope {
    pub max_subscribers: u32,
    pub max_edns_delta: f64,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionWindow {
    pub start_time: u64,
    pub end_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZtcppIntent {
    pub action_class: String,
    pub target_service: String,
    pub impact_scope: ImpactScope,
    pub temporal_bounds: HashMap<String, u64>, // e.g., session_duration_ms
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZtcppContext {
    pub current_edns: f64,
    pub current_cei: u32,
    pub active_alarms: u32,
    pub ongoing_remediations: u32,
    pub agent_confidence_score: f64,
}

/// NHP-KNK payload - the canonical shared JSON structure.
///
/// This struct mirrors the Python `NhpKnkPayload` model exactly.
/// Both runtimes must serialize/deserialize this identically.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NhpKnkPayload {
    pub ztcpp_intent: ZtcppIntent,
    pub ztcpp_context: ZtcppContext,
    pub ztcpp_sat_fragment: String,
    // Note: outer envelope or standard JWS claims handled elsewhere
}

/// Error type for KNK parsing and validation.
#[derive(Debug, Error)]
pub enum KnkParseError {
    #[error("Invalid JSON: {0}")]
    InvalidJson(String),

    #[error("Schema validation failed: {0}")]
    SchemaValidation(String),

    #[error("Invalid intent action: {0}")]
    InvalidAction(String),
}

/// NhpKnkParser trait - mirrors the Python interface.
pub trait NhpKnkParser {
    type Error;

    /// Parse raw bytes into an NhpKnkPayload.
    fn parse(payload: &[u8]) -> Result<NhpKnkPayload, Self::Error>;

    /// Validate the payload schema.
    fn validate_schema(payload: &NhpKnkPayload) -> Result<(), Self::Error>;
}

/// Default KNK parser implementation.
pub struct DefaultKnkParser;

impl NhpKnkParser for DefaultKnkParser {
    type Error = KnkParseError;

    fn parse(payload: &[u8]) -> Result<NhpKnkPayload, Self::Error> {
        serde_json::from_slice(payload).map_err(|e| KnkParseError::InvalidJson(e.to_string()))
    }

    fn validate_schema(payload: &NhpKnkPayload) -> Result<(), Self::Error> {
        let valid_actions = ["monitor", "remediate", "provision", "optimize"];
        if !valid_actions.contains(&payload.ztcpp_intent.action_class.as_str()) {
            return Err(KnkParseError::InvalidAction(payload.ztcpp_intent.action_class.clone()));
        }
        if payload.ztcpp_context.current_edns < 0.0 || payload.ztcpp_context.current_edns > 1.0 {
            return Err(KnkParseError::SchemaValidation(
                format!("EDNS score out of range: {}", payload.ztcpp_context.current_edns),
            ));
        }
        if payload.ztcpp_context.agent_confidence_score < 0.0 || payload.ztcpp_context.agent_confidence_score > 1.0 {
            return Err(KnkParseError::SchemaValidation(
                "Confidence score out of range".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_payload() -> NhpKnkPayload {
        let mut temporal = HashMap::new();
        temporal.insert("session_duration_ms".to_string(), 300000);

        NhpKnkPayload {
            ztcpp_intent: ZtcppIntent {
                action_class: "monitor".to_string(),
                target_service: "amf.5gc.svc".to_string(),
                impact_scope: ImpactScope {
                    max_subscribers: 1000,
                    max_edns_delta: 0.05,
                    domain: "core".to_string(),
                },
                temporal_bounds: temporal,
            },
            ztcpp_context: ZtcppContext {
                current_edns: 0.15,
                current_cei: 85,
                active_alarms: 0,
                ongoing_remediations: 0,
                agent_confidence_score: 0.98,
            },
            ztcpp_sat_fragment: "base64encodedfragment".to_string(),
        }
    }

    #[test]
    fn test_parse_valid_payload() {
        let payload = make_payload();
        let json = serde_json::to_vec(&payload).expect("serialize");
        let parsed = DefaultKnkParser::parse(&json).expect("parse");
        assert_eq!(parsed.ztcpp_intent.action_class, "monitor");
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = DefaultKnkParser::parse(b"not json");
        assert!(result.is_err());
        match result.unwrap_err() {
            KnkParseError::InvalidJson(_) => {},
            other => panic!("Expected InvalidJson, got {:?}", other),
        }
    }

    #[test]
    fn test_validate_schema_passes() {
        let payload = make_payload();
        assert!(DefaultKnkParser::validate_schema(&payload).is_ok());
    }

    #[test]
    fn test_validate_schema_invalid_action() {
        let mut payload = make_payload();
        payload.ztcpp_intent.action_class = "read".to_string(); // Invalid per paper
        assert!(matches!(
            DefaultKnkParser::validate_schema(&payload).unwrap_err(),
            KnkParseError::InvalidAction(_)
        ));
    }
}
