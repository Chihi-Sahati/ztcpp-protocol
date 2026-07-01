use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

// Include the generated FlatBuffers schema
use crate::nhp_sba_schema::nhp_sba::nhp::{root_as_knk_payload, KnkPayload};

/// Strongly typed, deterministic error enum for the crypto pipeline.
/// No panics or internal state leaks allowed.
#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("AEAD Decryption failed. Packet dropped.")]
    DecryptionFailed,
    #[error("Ed25519 Signature verification failed. Integrity compromised.")]
    SignatureVerificationFailed,
    #[error("FlatBuffers parsing failed or invalid schema structure.")]
    ParsingFailed,
    #[error("Buffer too small to contain required headers/signatures.")]
    BufferTooSmall,
}

/// The high-performance ingress pipeline.
/// This function performs Decrypt -> Verify -> Parse with strictly ZERO heap allocations
/// where possible, processing the raw byte slice `&mut [u8]` in-place.
/// 
/// `buffer`: The incoming UDP packet buffer containing the encrypted Noise payload.
/// `cipher_key`: The derived ChaCha20 symmetric key for this session (32 bytes).
/// `cipher_nonce`: The ChaCha20 nonce for this packet (12 bytes).
/// `agent_pubkey`: The Ed25519 public key of the Agent to verify the detached signature.
/// 
/// Note: The `buffer` is mutated in-place for AEAD decryption.
pub fn process_ingress_packet<'a>(
    buffer: &'a mut [u8],
    cipher_key: &[u8; 32],
    cipher_nonce: &[u8; 12],
    agent_pubkey: &VerifyingKey,
    signature_bytes: &[u8; 64],
) -> Result<KnkPayload<'a>, PipelineError> {
    
    // ---------------------------------------------------------
    // 1. DECRYPT: ChaCha20-Poly1305 (In-Place)
    // ---------------------------------------------------------
    // We strictly use in-place decryption to avoid allocating a new Vec<u8>
    // for the plaintext. The `buffer` holds ciphertext + MAC tag.
    let key = Key::from_slice(cipher_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(cipher_nonce);

    // AeadInPlace requires the buffer to contain the ciphertext followed by the 16-byte Poly1305 tag.
    // It decrypts the ciphertext in place and truncates the slice to remove the tag.
    // However, since we are working with a mutable slice (not a Vec), we pass the buffer
    // and rely on `decrypt_in_place_detached` if the tag is separate, or we slice it manually.
    // For this implementation, we assume the tag is at the end of the buffer.
    
    // To do true zero-allocation on a slice, we must split the tag off.
    if buffer.len() < 16 {
        return Err(PipelineError::BufferTooSmall);
    }
    
    let (ciphertext_area, tag_area) = buffer.split_at_mut(buffer.len() - 16);
    let tag = chacha20poly1305::Tag::from_slice(tag_area);
    
    cipher
        .decrypt_in_place_detached(nonce, b"", ciphertext_area, tag)
        .map_err(|_| PipelineError::DecryptionFailed)?;

    // After this point, `ciphertext_area` holds the plaintext FlatBuffers binary.

    // ---------------------------------------------------------
    // 2. VERIFY: Ed25519 Detached Signature
    // ---------------------------------------------------------
    // Cryptographic integrity constraint: the payload must be signed by the initiator's Ed25519 key.
    let signature = Signature::from_bytes(signature_bytes);
    agent_pubkey
        .verify(ciphertext_area, &signature)
        .map_err(|_| PipelineError::SignatureVerificationFailed)?;

    // ---------------------------------------------------------
    // 3. PARSE: Zero-Copy FlatBuffers Deserialization
    // ---------------------------------------------------------
    // Cast the verified plaintext byte slice directly into the FlatBuffers generated struct.
    // No data is copied. The returned `KnkPayload` holds a lifetime `'a` tied to `buffer`.
    let payload = root_as_knk_payload(ciphertext_area)
        .map_err(|_| PipelineError::ParsingFailed)?;

    // Ensure the payload structure is valid and safe to read
    if payload.agent_uri().is_none() || payload.target_service().is_none() {
        return Err(PipelineError::ParsingFailed);
    }

    Ok(payload)
}
