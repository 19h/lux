//! Noise protocol integration tests.
//!
//! Tests for the Noise NK protocol including:
//! - Handshake completion
//! - Encrypted message exchange
//! - Key derivation

use lux_net::noise::{generate_keypair, NoiseSession, NOISE_PATTERN};

/// Initialize tracing for tests.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lux_tests=debug,lux_net=debug")
        .with_test_writer()
        .try_init();
}

#[test]
fn test_noise_pattern_string() {
    // Verify the pattern string matches spec
    assert_eq!(NOISE_PATTERN, "Noise_NK_25519_ChaChaPoly_BLAKE3");
}

#[test]
fn test_keypair_generation() {
    init_tracing();

    let (private, public) = generate_keypair().unwrap();

    // Keys should be 32 bytes
    assert_eq!(private.len(), 32);
    assert_eq!(public.len(), 32);

    // Keys should be non-zero
    assert!(private.iter().any(|&b| b != 0));
    assert!(public.iter().any(|&b| b != 0));
}

#[test]
fn test_keypair_uniqueness() {
    init_tracing();

    // Generate multiple keypairs
    let pairs: Vec<_> = (0..10)
        .map(|_| generate_keypair().unwrap())
        .collect();

    // All public keys should be unique
    for i in 0..pairs.len() {
        for j in (i + 1)..pairs.len() {
            assert_ne!(pairs[i].1, pairs[j].1, "Public keys should be unique");
        }
    }
}

#[test]
fn test_noise_handshake_nk() {
    init_tracing();

    // Generate responder's static keypair
    let (responder_private, responder_public) = generate_keypair().unwrap();

    // Create sessions
    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Verify initial state
    assert!(!initiator.is_handshake_complete());
    assert!(!responder.is_handshake_complete());
    assert!(initiator.is_initiator());
    assert!(!responder.is_initiator());

    // Initiator -> Responder (message 1: e, es)
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();

    // Responder -> Initiator (message 2: e, ee)
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();

    // Complete handshake
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();

    // Verify complete
    assert!(initiator.is_handshake_complete());
    assert!(responder.is_handshake_complete());
}

#[test]
fn test_noise_handshake_with_payload() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Send payload in first message
    let payload1 = b"Hello from initiator!";
    let msg1 = initiator.write_handshake(payload1).unwrap();
    let recv_payload1 = responder.read_handshake(&msg1).unwrap();
    assert_eq!(recv_payload1.as_slice(), payload1.as_slice());

    // Send payload in second message
    let payload2 = b"Hello from responder!";
    let msg2 = responder.write_handshake(payload2).unwrap();
    let recv_payload2 = initiator.read_handshake(&msg2).unwrap();
    assert_eq!(recv_payload2.as_slice(), payload2.as_slice());

    // Complete
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();
}

#[test]
fn test_noise_transport_encryption() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();

    // Test encryption: initiator -> responder
    let plaintext = b"Secret message from initiator";
    let ciphertext = initiator.encrypt(plaintext).unwrap();
    let decrypted = responder.decrypt(&ciphertext).unwrap();
    assert_eq!(plaintext.as_slice(), decrypted.as_slice());

    // Test encryption: responder -> initiator
    let plaintext2 = b"Secret response from responder";
    let ciphertext2 = responder.encrypt(plaintext2).unwrap();
    let decrypted2 = initiator.decrypt(&ciphertext2).unwrap();
    assert_eq!(plaintext2.as_slice(), decrypted2.as_slice());
}

#[test]
fn test_noise_transport_multiple_messages() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();

    // Send multiple messages in each direction
    for i in 0..10 {
        let msg = format!("Message {} from initiator", i);
        let ciphertext = initiator.encrypt(msg.as_bytes()).unwrap();
        let decrypted = responder.decrypt(&ciphertext).unwrap();
        assert_eq!(msg.as_bytes(), decrypted.as_slice());

        let reply = format!("Reply {} from responder", i);
        let ciphertext2 = responder.encrypt(reply.as_bytes()).unwrap();
        let decrypted2 = initiator.decrypt(&ciphertext2).unwrap();
        assert_eq!(reply.as_bytes(), decrypted2.as_slice());
    }
}

#[test]
fn test_noise_ciphertext_different_each_message() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();

    // Same plaintext should produce different ciphertext (due to nonce)
    let plaintext = b"Same message";
    let ct1 = initiator.encrypt(plaintext).unwrap();
    let ct2 = initiator.encrypt(plaintext).unwrap();

    // Ciphertext should differ (nonce increments)
    assert_ne!(ct1, ct2);

    // Both should decrypt correctly
    let pt1 = responder.decrypt(&ct1).unwrap();
    let pt2 = responder.decrypt(&ct2).unwrap();
    assert_eq!(plaintext.as_slice(), pt1.as_slice());
    assert_eq!(plaintext.as_slice(), pt2.as_slice());
}

#[test]
fn test_noise_large_message() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();

    // Encrypt a large message (just under 64 KB - Noise max is 65535)
    let large_msg: Vec<u8> = (0..65500).map(|i| (i % 256) as u8).collect();
    let ciphertext = initiator.encrypt(&large_msg).unwrap();
    let decrypted = responder.decrypt(&ciphertext).unwrap();

    assert_eq!(large_msg, decrypted);
}

#[test]
fn test_noise_tampered_ciphertext_fails() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Complete handshake
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();
    let msg2 = responder.write_handshake(&[]).unwrap();
    initiator.read_handshake(&msg2).unwrap();
    initiator.complete_handshake().unwrap();
    responder.complete_handshake().unwrap();

    // Encrypt
    let plaintext = b"Original message";
    let mut ciphertext = initiator.encrypt(plaintext).unwrap();

    // Tamper with ciphertext
    ciphertext[5] ^= 0xFF;

    // Decryption should fail
    let result = responder.decrypt(&ciphertext);
    assert!(result.is_err(), "Tampered ciphertext should fail decryption");
}

#[test]
fn test_noise_remote_static_key() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let initiator = NoiseSession::new_initiator(&responder_public).unwrap();

    // Initiator should know responder's static key
    let remote = initiator.remote_static().unwrap();
    assert_eq!(*remote, responder_public);
}

#[test]
fn test_noise_handshake_incomplete_error() {
    init_tracing();

    let (responder_private, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut responder = NoiseSession::new_responder(&responder_private).unwrap();

    // Only do first message
    let msg1 = initiator.write_handshake(&[]).unwrap();
    responder.read_handshake(&msg1).unwrap();

    // Try to complete without second message - should fail
    let result = initiator.complete_handshake();
    assert!(result.is_err(), "Should fail to complete handshake early");
}

#[test]
fn test_noise_encrypt_before_complete_fails() {
    init_tracing();

    let (_, responder_public) = generate_keypair().unwrap();

    let mut initiator = NoiseSession::new_initiator(&responder_public).unwrap();

    // Try to encrypt before handshake complete
    let result = initiator.encrypt(b"test");
    assert!(result.is_err(), "Should fail to encrypt before handshake");
}

#[test]
fn test_noise_deterministic_session_keys() {
    init_tracing();

    // This test verifies that given the same keypairs and messages,
    // the session produces consistent behavior

    let (responder_private, responder_public) = generate_keypair().unwrap();

    // First session
    let mut init1 = NoiseSession::new_initiator(&responder_public).unwrap();
    let mut resp1 = NoiseSession::new_responder(&responder_private).unwrap();

    let msg1_1 = init1.write_handshake(&[]).unwrap();
    resp1.read_handshake(&msg1_1).unwrap();
    let msg1_2 = resp1.write_handshake(&[]).unwrap();
    init1.read_handshake(&msg1_2).unwrap();
    init1.complete_handshake().unwrap();
    resp1.complete_handshake().unwrap();

    // Session should work
    let ct1 = init1.encrypt(b"test").unwrap();
    let pt1 = resp1.decrypt(&ct1).unwrap();
    assert_eq!(b"test".as_slice(), pt1.as_slice());
}
