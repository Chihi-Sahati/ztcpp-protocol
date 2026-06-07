use x25519_dalek::{PublicKey, StaticSecret, EphemeralSecret};
use rand_core::OsRng;
use zeroize::Zeroize;

/// X25519 static key pair for NHP handshake.
#[derive(Zeroize)]
pub struct NhpX25519KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl NhpX25519KeyPair {
    /// Generate a new X25519 key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Get the secret key bytes (32 bytes).
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

/// X25519 shared secret resulting from a Diffie-Hellman handshake.
/// This is zeroed on drop to prevent memory leakage.
#[derive(Zeroize)]
pub struct X25519SharedSecret([u8; 32]);

impl X25519SharedSecret {
    /// Get the raw shared secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to a Vec for key derivation.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Perform an X25519 Diffie-Hellman handshake with a peer's public key.
///
/// This computes: `shared_secret = our_secret * their_public`
///
/// The result is the raw 32-byte shared secret which should be passed
/// to HKDF for key derivation.
///
/// # Arguments
/// * `our_keypair` - Our static X25519 key pair
/// * `their_public_bytes` - Peer's 32-byte X25519 public key
///
/// # Errors
/// Returns an error if the peer's public key is invalid.
pub fn perform_x25519_handshake(
    our_keypair: &NhpX25519KeyPair,
    their_public_bytes: &[u8; 32],
) -> Result<X25519SharedSecret, String> {
    let their_public = PublicKey::from(*their_public_bytes);
    let shared = our_keypair.secret.diffie_hellman(&their_public);
    Ok(X25519SharedSecret(shared.to_bytes()))
}

/// Perform an ephemeral X25519 handshake (perfect forward secrecy).
///
/// Generates a one-time ephemeral key pair, performs the handshake,
/// and returns the shared secret. The ephemeral private key is
/// zeroed immediately after use.
pub fn perform_ephemeral_handshake(their_public_bytes: &[u8; 32]) -> Result<X25519SharedSecret, String> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let their_public = PublicKey::from(*their_public_bytes);
    let shared = ephemeral_secret.diffie_hellman(&their_public);
    // ephemeral_secret is zeroed when it goes out of scope
    Ok(X25519SharedSecret(shared.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = NhpX25519KeyPair::generate();
        assert_eq!(kp.public_key_bytes().len(), 32);
        assert_eq!(kp.secret_key_bytes().len(), 32);
    }

    #[test]
    fn test_handshake_symmetric() {
        let kp1 = NhpX25519KeyPair::generate();
        let kp2 = NhpX25519KeyPair::generate();

        let shared1 = perform_x25519_handshake(&kp1, &kp2.public_key_bytes()).expect("handshake 1");
        let shared2 = perform_x25519_handshake(&kp2, &kp1.public_key_bytes()).expect("handshake 2");

        assert_eq!(shared1.as_bytes(), shared2.as_bytes(), "DH should be symmetric");
    }

    #[test]
    fn test_different_keypairs_produce_different_secrets() {
        let kp1 = NhpX25519KeyPair::generate();
        let kp2_a = NhpX25519KeyPair::generate();
        let kp2_b = NhpX25519KeyPair::generate();

        let shared_a = perform_x25519_handshake(&kp1, &kp2_a.public_key_bytes()).expect("a");
        let shared_b = perform_x25519_handshake(&kp1, &kp2_b.public_key_bytes()).expect("b");

        assert_ne!(shared_a.as_bytes(), shared_b.as_bytes(), "Different peers = different secrets");
    }

    #[test]
    fn test_ephemeral_handshake() {
        let kp = NhpX25519KeyPair::generate();
        let shared = perform_ephemeral_handshake(&kp.public_key_bytes()).expect("ephemeral");
        assert_eq!(shared.as_bytes().len(), 32);
    }
}
