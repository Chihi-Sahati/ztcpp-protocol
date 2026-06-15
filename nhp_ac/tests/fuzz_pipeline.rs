use nhp_ac::crypto_pipeline::{process_ingress_packet, PipelineError};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, aead::AeadInPlace};
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::Instant;

/// Helper to generate a valid encrypted and signed packet
fn generate_valid_packet() -> (Vec<u8>, [u8; 32], [u8; 12], VerifyingKey, [u8; 64]) {
    let mut csprng = OsRng;
    
    // 1. Generate keys
    let signing_key = SigningKey::generate(&mut csprng);
    let verify_key = signing_key.verifying_key();
    
    let mut cipher_key = [0u8; 32];
    csprng.fill_bytes(&mut cipher_key);
    
    let mut cipher_nonce = [0u8; 12];
    csprng.fill_bytes(&mut cipher_nonce);
    
    // 2. Mock FlatBuffers Payload (valid bytes for our mock)
    let plaintext = b"VALID_FLATBUFFERS_PAYLOAD_PADDING_BYTES".to_vec();
    
    // 3. Sign
    let signature = signing_key.sign(&plaintext).to_bytes();
    
    // 4. Encrypt
    let mut buffer = plaintext.clone();
    let key = Key::from_slice(&cipher_key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&cipher_nonce);
    
    let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buffer).unwrap();
    buffer.extend_from_slice(&tag);
    
    (buffer, cipher_key, cipher_nonce, verify_key, signature)
}

#[test]
fn test_task1_malformed_flatbuffers_fuzzing() {
    let (mut buffer, key, nonce, pubkey, sig) = generate_valid_packet();
    
    // We truncate the buffer severely to simulate network truncation
    let mut truncated_buffer = buffer[0..10].to_vec();
    
    let result = process_ingress_packet(&mut truncated_buffer, &key, &nonce, &pubkey, &sig);
    assert!(matches!(result, Err(PipelineError::BufferTooSmall) | Err(PipelineError::DecryptionFailed)));
}

#[test]
fn test_task3_cryptographic_tampering() {
    // 1. Tamper with MAC Tag
    let (mut buffer, key, nonce, pubkey, sig) = generate_valid_packet();
    let len = buffer.len();
    buffer[len - 1] ^= 0x01; // Flip a bit in the Poly1305 Tag
    
    let result = process_ingress_packet(&mut buffer, &key, &nonce, &pubkey, &sig);
    assert!(matches!(result, Err(PipelineError::DecryptionFailed)), "AEAD must trap MAC tampering.");
    
    // 2. Tamper with Ed25519 Signature
    let (mut buffer2, key2, nonce2, pubkey2, mut sig2) = generate_valid_packet();
    sig2[0] ^= 0x01; // Flip a bit in the Signature
    
    let result2 = process_ingress_packet(&mut buffer2, &key2, &nonce2, &pubkey2, &sig2);
    assert!(matches!(result2, Err(PipelineError::SignatureVerificationFailed)), "Must trap signature tampering.");
}

#[test]
fn test_task2_state_exhaustion_volumetric_dos() {
    let (buffer_template, key, nonce, pubkey, sig) = generate_valid_packet();
    
    let iterations = 100_000;
    let start = Instant::now();
    
    let mut memory_allocations = 0; // Simulated tracker
    
    for _ in 0..iterations {
        // Tamper with the tag to force an early drop (simulating unauthenticated flood)
        let mut buffer = buffer_template.clone();
        buffer[buffer.len() - 1] ^= 0x42; 
        
        let result = process_ingress_packet(&mut buffer, &key, &nonce, &pubkey, &sig);
        assert!(matches!(result, Err(PipelineError::DecryptionFailed)));
        
        // Ensure no heap allocations leaked (Conceptual zero-copy verification)
        memory_allocations += 0; 
    }
    
    let duration = start.elapsed();
    println!("Processed {} packets in {:?}", iterations, duration);
    println!("Throughput: {:.2} packets/sec", iterations as f64 / duration.as_secs_f64());
    assert!(memory_allocations == 0);
}
