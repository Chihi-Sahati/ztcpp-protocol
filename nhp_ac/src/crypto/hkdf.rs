use hkdf::Hkdf;
use sha2::Sha256;

/// NHP session key material derived from the X25519 shared secret.
#[derive(Clone)]
pub struct SessionKeyMaterial {
    /// Session encryption key (32 bytes)
    pub encryption_key: [u8; 32],
    /// Session decryption key (32 bytes, for bidirectional)
    pub decryption_key: [u8; 32],
    /// Session nonce (12 bytes)
    pub session_nonce: [u8; 12],
}

/// Derive session keys from an X25519 shared secret using HKDF-SHA256.
///
/// Uses HKDF with the following parameters:
/// - Hash: SHA-256
/// - Salt: "ztcpp-nhp-session" (protocol-specific)
/// - Info: "nhp-session-keys-v1" (key derivation label)
///
/// Extracts 76 bytes: 32 (enc key) + 32 (dec key) + 12 (nonce)
///
/// # Arguments
/// * `shared_secret` - Raw 32-byte X25519 shared secret
///
/// # Returns
/// Derived session key material.
///
/// # Errors
/// Returns an error if key derivation fails.
pub fn derive_session_keys(shared_secret: &[u8]) -> Result<SessionKeyMaterial, String> {
    let hk = Hkdf::<Sha256>::new(
        Some(b"ztcpp-nhp-session"),
        shared_secret,
    );

    let mut output = [0u8; 76];
    hk.expand(b"nhp-session-keys-v1", &mut output)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;

    let mut encryption_key = [0u8; 32];
    let mut decryption_key = [0u8; 32];
    let mut session_nonce = [0u8; 12];

    encryption_key.copy_from_slice(&output[0..32]);
    decryption_key.copy_from_slice(&output[32..64]);
    session_nonce.copy_from_slice(&output[64..76]);

    // Zeroize intermediate output
    output.zeroize();

    Ok(SessionKeyMaterial {
        encryption_key,
        decryption_key,
        session_nonce,
    })
}

/// Derive a single key from shared secret with custom info label.
pub fn derive_key(shared_secret: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(
        Some(b"ztcpp-nhp-session"),
        shared_secret,
    );
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output)
        .map_err(|e| format!("HKDF expand failed: {}", e))?;
    Ok(output)
}

/// Zeroize trait implementation for arrays.
trait Zeroize {
    fn zeroize(&mut self);
}

impl Zeroize for [u8; 76] {
    fn zeroize(&mut self) {
        for byte in self.iter_mut() {
            *byte = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_session_keys() {
        let shared_secret = [0x42u8; 32];
        let keys = derive_session_keys(&shared_secret).expect("derive");

        assert_eq!(keys.encryption_key.len(), 32);
        assert_eq!(keys.decryption_key.len(), 32);
        assert_eq!(keys.session_nonce.len(), 12);

        // Encryption and decryption keys should be different
        assert_ne!(keys.encryption_key, keys.decryption_key);
    }

    #[test]
    fn test_deterministic_derivation() {
        let shared_secret = [0x55u8; 32];
        let keys1 = derive_session_keys(&shared_secret).expect("derive1");
        let keys2 = derive_session_keys(&shared_secret).expect("derive2");

        assert_eq!(keys1.encryption_key, keys2.encryption_key);
        assert_eq!(keys1.decryption_key, keys2.decryption_key);
        assert_eq!(keys1.session_nonce, keys2.session_nonce);
    }

    #[test]
    fn test_different_secrets_produce_different_keys() {
        let secret1 = [0x11u8; 32];
        let secret2 = [0x22u8; 32];
        let keys1 = derive_session_keys(&secret1).expect("derive1");
        let keys2 = derive_session_keys(&secret2).expect("derive2");

        assert_ne!(keys1.encryption_key, keys2.encryption_key);
    }
}
