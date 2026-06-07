use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use zeroize::Zeroize;

/// NHP AEAD (Authenticated Encryption with Associated Data) key.
/// Uses ChaCha20-Poly1305 for session data encryption.
#[derive(Clone, Zeroize)]
pub struct NhpAeadKey([u8; 32]);

impl NhpAeadKey {
    /// Create a new AEAD key from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate a random AEAD key.
    pub fn generate() -> Self {
        let key = ChaCha20Poly1305::generate_key(OsRng);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&key);
        Self(bytes)
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// NHP AEAD nonce (12 bytes for ChaCha20-Poly1305).
#[derive(Clone, Copy)]
pub struct NhpAeadNonce([u8; 12]);

impl NhpAeadNonce {
    /// Create a nonce from raw 12 bytes.
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    /// Generate a random nonce.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 12];
        getrandom::getrandom(&mut bytes).expect("RNG failure");
        Self(bytes)
    }

    /// Increment the nonce counter (for sequential encryption).
    pub fn increment(&mut self) {
        let counter = u128::from_le_bytes(*self.as_ref());
        let incremented = counter.wrapping_add(1);
        self.0.copy_from_slice(&incremented.to_le_bytes()[..12]);
    }

    /// Get the raw nonce bytes.
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

impl AsRef<[u8]> for NhpAeadNonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for NhpAeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Encrypt plaintext using ChaCha20-Poly1305 AEAD.
///
/// Returns the ciphertext (plaintext + authentication tag).
///
/// # Errors
/// Returns an error if encryption fails.
pub fn encrypt(key: &NhpAeadKey, nonce: &NhpAeadNonce, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());
    cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))
}

/// Decrypt ciphertext using ChaCha20-Poly1305 AEAD.
///
/// # Errors
/// Returns an error if decryption or authentication fails.
pub fn decrypt(key: &NhpAeadKey, nonce: &NhpAeadNonce, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.as_bytes())
        .map_err(|e| format!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(nonce.as_bytes());
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption/authentication failed: {}", e))
}

/// Generate a random 32-byte key and 12-byte nonce, then encrypt.
/// Returns (ciphertext, key, nonce) for the caller to manage.
pub fn generate_and_encrypt(plaintext: &[u8]) -> (Vec<u8>, NhpAeadKey, NhpAeadNonce) {
    let key = NhpAeadKey::generate();
    let nonce = NhpAeadNonce::generate();
    let ciphertext = encrypt(&key, &nonce, plaintext).expect("Encryption with fresh key must succeed");
    (ciphertext, key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = NhpAeadKey::generate();
        let nonce = NhpAeadNonce::generate();
        let plaintext = b"Hello, NHP Protocol!";

        let ciphertext = encrypt(&key, &nonce, plaintext).expect("encrypt");
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decrypt");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = NhpAeadKey::generate();
        let key2 = NhpAeadKey::generate();
        let nonce = NhpAeadNonce::generate();
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key1, &nonce, plaintext).expect("encrypt");
        let result = decrypt(&key2, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = NhpAeadKey::generate();
        let nonce1 = NhpAeadNonce::generate();
        let nonce2 = NhpAeadNonce::generate();
        let plaintext = b"Secret data";

        let ciphertext = encrypt(&key, &nonce1, plaintext).expect("encrypt");
        let result = decrypt(&key, &nonce2, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let key = NhpAeadKey::generate();
        let nonce = NhpAeadNonce::generate();
        let plaintext = b"Secret data";

        let mut ciphertext = encrypt(&key, &nonce, plaintext).expect("encrypt");
        ciphertext[0] ^= 0xFF; // Tamper with first byte
        let result = decrypt(&key, &nonce, &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = NhpAeadKey::generate();
        let nonce = NhpAeadNonce::generate();
        let plaintext = b"";

        let ciphertext = encrypt(&key, &nonce, plaintext).expect("encrypt");
        let decrypted = decrypt(&key, &nonce, &ciphertext).expect("decrypt");
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = NhpAeadNonce([0u8; 12]);
        nonce.increment();
        assert_eq!(nonce.0[0], 1);
        assert_eq!(nonce.0[1..], [0u8; 11]);
    }
}
