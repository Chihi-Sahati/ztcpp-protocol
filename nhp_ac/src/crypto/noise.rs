//! Noise Protocol Framework integration for NHP.
//!
//! Uses the `snow` crate to implement Noise_XK and Noise_IK patterns
//! for the initial NHP handshake.

use snow::{Builder, HandshakeState, TransportState};

/// Noise pattern constants.
pub const NOISE_XK_PATTERN: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_IK_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Create a Noise XK initiator handshake state.
///
/// XK pattern: X (ephemeral-static) + K (known key)
/// The responder's static public key must be known beforehand.
pub fn create_xk_initiator(
    our_static_private: &[u8],
    their_static_public: &[u8],
) -> Result<HandshakeState, String> {
    Builder::new(NOISE_XK_PATTERN.parse().map_err(|e| format!("{e}"))?)
        .local_private_key(our_static_private)
        .remote_public_key(their_static_public)
        .build_initiator()
        .map_err(|e| format!("Failed to build Noise XK initiator: {}", e))
}

/// Create a Noise XK responder handshake state.
pub fn create_xk_responder(
    our_static_private: &[u8],
) -> Result<HandshakeState, String> {
    Builder::new(NOISE_XK_PATTERN.parse().map_err(|e| format!("{e}"))?)
        .local_private_key(our_static_private)
        .build_responder()
        .map_err(|e| format!("Failed to build Noise XK responder: {}", e))
}

/// Create a Noise IK initiator handshake state.
///
/// IK pattern: I (static) + K (known key)
/// Both parties know each other's static public keys.
pub fn create_ik_initiator(
    our_static_private: &[u8],
    our_public_key: &[u8],
    their_static_public: &[u8],
) -> Result<HandshakeState, String> {
    Builder::new(NOISE_IK_PATTERN.parse().map_err(|e| format!("{e}"))?)
        .local_private_key(our_static_private)
        .local_public_key(our_public_key)
        .remote_public_key(their_static_public)
        .build_initiator()
        .map_err(|e| format!("Failed to build Noise IK initiator: {}", e))
}

/// Create a Noise IK responder handshake state.
pub fn create_ik_responder(
    our_static_private: &[u8],
    our_public_key: &[u8],
    their_static_public: &[u8],
) -> Result<HandshakeState, String> {
    Builder::new(NOISE_IK_PATTERN.parse().map_err(|e| format!("{e}"))?)
        .local_private_key(our_static_private)
        .local_public_key(our_public_key)
        .remote_public_key(their_static_public)
        .build_responder()
        .map_err(|e| format!("Failed to build Noise IK responder: {}", e))
}

/// Perform a full Noise handshake (1-RTT).
///
/// Returns the transport state for encrypted communication.
pub fn complete_handshake(
    mut initiator: HandshakeState,
    mut responder: HandshakeState,
    message: &[u8],
) -> Result<(TransportState, TransportState, Vec<u8>), String> {
    // Initiator -> Responder
    let mut buf = vec![0u8; 2048];
    let len = initiator
        .write_message(message, &mut buf)
        .map_err(|e| format!("Initiator write failed: {}", e))?;
    let msg1 = buf[..len].to_vec();

    // Responder reads
    let mut buf2 = vec![0u8; 2048];
    let _len = responder
        .read_message(&msg1, &mut buf2)
        .map_err(|e| format!("Responder read failed: {}", e))?;

    // Responder -> Initiator
    let mut buf3 = vec![0u8; 2048];
    let len = responder
        .write_message(&[], &mut buf3)
        .map_err(|e| format!("Responder write failed: {}", e))?;
    let msg2 = buf3[..len].to_vec();

    // Initiator reads
    let mut buf4 = vec![0u8; 2048];
    let _len = initiator
        .read_message(&msg2, &mut buf4)
        .map_err(|e| format!("Initiator read failed: {}", e))?;

    let initiator_transport = initiator
        .into_transport_mode()
        .map_err(|e| format!("Initiator transport mode: {}", e))?;
    let responder_transport = responder
        .into_transport_mode()
        .map_err(|e| format!("Responder transport mode: {}", e))?;

    Ok((initiator_transport, responder_transport, msg1))
}
