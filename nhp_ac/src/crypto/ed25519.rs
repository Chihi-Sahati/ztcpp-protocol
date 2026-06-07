use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature};
use rand_core::OsRng;
use zeroize::Zeroize;

/// Ed25519 key pair for NHP identity signing.
#[derive(Zeroize)]
pub struct NhpEd25519KeyPair {
    signing_key: SigningKey,
}

impl NhpEd25519KeyPair {
    /// Generate a new Ed25519 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(OsRng);
        Self { signing_key }
    }

    /// Get the verifying (public) key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the signing key seed (32 bytes).
    pub fn seed_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// An Ed25519 signature (64 bytes).
#[derive(Clone)]
pub struct NhpSignature(Signature);

impl NhpSignature {
    /// Create a signature from raw 64 bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(Signature::from_bytes(&bytes))
    }

    /// Get the raw signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        self.0.as_bytes()
    }

    /// Convert to base64 string.
    pub fn to_base64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(self.0.to_bytes())
    }
}

/// Sign a payload using Ed25519.
///
/// # Arguments
/// * `keypair` - The signing key pair
/// * `message` - The message bytes to sign
///
/// # Returns
/// A 64-byte Ed25519 signature.
pub fn sign_payload(keypair: &NhpEd25519KeyPair, message: &[u8]) -> NhpSignature {
    let signature = keypair.signing_key.sign(message);
    NhpSignature(signature)
}

/// Verify an Ed25519 signature.
///
/// # Arguments
/// * `public_key_bytes` - The signer's 32-byte Ed25519 public key
/// * `message` - The original message bytes
/// * `signature_bytes` - The 64-byte signature
///
/// # Returns
/// Ok(()) if the signature is valid, Err otherwise.
pub fn verify_signature(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> Result<(), String> {
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|e| format!("Invalid public key: {}", e))?;
    let signature = Signature::from_bytes(signature_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))
}

/// Verify an Ed25519 signature from a base64-encoded signature string.
pub fn verify_signature_base64(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature_base64: &str,
) -> Result<(), String> {
    use base64::Engine;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_base64)
        .map_err(|e| format!("Invalid base64 signature: {}", e))?;
    if sig_bytes.len() != 64 {
        return Err(format!("Signature must be 64 bytes, got {}", sig_bytes.len()));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    verify_signature(public_key_bytes, message, &sig_array)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = NhpEd25519KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
        assert_eq!(kp.seed_bytes().len(), 32);
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let kp = NhpEd25519KeyPair::generate();
        let message = b"Hello, NHP Protocol!";

        let sig = sign_payload(&kp, message);
        let result = verify_signature(&kp.public_key_bytes(), message, sig.as_bytes());
        assert!(result.is_ok());
    }

    #[test]
    fn test_wrong_key_rejects() {
        let kp1 = NhpEd25519KeyPair::generate();
        let kp2 = NhpEd25519KeyPair::generate();
        let message = b"Hello, NHP Protocol!";

        let sig = sign_payload(&kp1, message);
        let result = verify_signature(&kp2.public_key_bytes(), message, sig.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_message_rejects() {
        let kp = NhpEd25519KeyPair::generate();
        let message = b"Hello, NHP Protocol!";
        let tampered = b"Hello, TAMPERED!";

        let sig = sign_payload(&kp, message);
        let result = verify_signature(&kp.public_key_bytes(), tampered, sig.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_signature_rejects() {
        let kp = NhpEd25519KeyPair::generate();
        let message = b"Hello, NHP Protocol!";

        let sig = sign_payload(&kp, message);
        let mut tampered_sig = sig.as_bytes().to_vec();
        tampered_sig[0] ^= 0xFF;
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&tampered_sig);

        let result = verify_signature(&kp.public_key_bytes(), message, &sig_array);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message() {
        let kp = NhpEd25519KeyPair::generate();
        let message = b"";

        let sig = sign_payload(&kp, message);
        let result = verify_signature(&kp.public_key_bytes(), message, sig.as_bytes());
        assert!(result.is_ok());
    }
}
