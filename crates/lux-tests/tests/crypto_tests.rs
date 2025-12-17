//! Comprehensive crypto primitive tests.
//!
//! Tests for cryptographic primitives including:
//! - BLAKE3 hashing
//! - HKDF-SHA-256 key derivation
//! - XChaCha20-Poly1305 AEAD
//! - Ed25519 signatures
//! - Key schedule

use lux_core::crypto::{
    blake3_hash,
    hkdf_sha256,
    encrypt_xchacha20poly1305,
    decrypt_xchacha20poly1305,
    sign_ed25519,
    verify_ed25519,
    derive_public_key,
    generate_keypair,
    hmac_sha256,
    KeySchedule,
};
use lux_core::{BlobId, ChunkId, NodeId};

// ============================================================================
// BLAKE3 Tests
// ============================================================================

#[test]
fn test_blake3_empty_input() {
    let hash = blake3_hash(&[]);
    // BLAKE3("") is the well-known empty hash
    assert_eq!(
        hex::encode(hash),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

#[test]
fn test_blake3_hello_world() {
    let hash = blake3_hash(b"Hello, World!");
    // Known BLAKE3 hash
    assert_eq!(hash.len(), 32);
    // Different content = different hash
    let hash2 = blake3_hash(b"Hello, World");
    assert_ne!(hash, hash2);
}

#[test]
fn test_blake3_deterministic() {
    let data = b"Test data for BLAKE3";
    let hash1 = blake3_hash(data);
    let hash2 = blake3_hash(data);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_blake3_different_inputs() {
    let hash1 = blake3_hash(b"Input 1");
    let hash2 = blake3_hash(b"Input 2");
    assert_ne!(hash1, hash2);
}

#[test]
fn test_blake3_large_input() {
    let large_data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
    let hash = blake3_hash(&large_data);
    assert_eq!(hash.len(), 32);
}

// ============================================================================
// HKDF-SHA-256 Tests
// ============================================================================

#[test]
fn test_hkdf_basic() {
    let ikm = [0x0b; 32];
    let salt = [0x00; 32];
    let info = b"test info";

    let output = hkdf_sha256(&ikm, &salt, info, 32);
    assert_eq!(output.len(), 32);
}

#[test]
fn test_hkdf_different_lengths() {
    let ikm = [0x42; 32];
    let salt = [];
    let info = b"info";

    let out16 = hkdf_sha256(&ikm, &salt, info, 16);
    let out24 = hkdf_sha256(&ikm, &salt, info, 24);
    let out32 = hkdf_sha256(&ikm, &salt, info, 32);
    let out64 = hkdf_sha256(&ikm, &salt, info, 64);

    assert_eq!(out16.len(), 16);
    assert_eq!(out24.len(), 24);
    assert_eq!(out32.len(), 32);
    assert_eq!(out64.len(), 64);

    // Shorter outputs should be prefixes of longer ones
    assert_eq!(&out32[..16], &out16[..]);
    assert_eq!(&out32[..24], &out24[..]);
}

#[test]
fn test_hkdf_empty_salt() {
    let ikm = [0xAB; 32];
    let info = b"test";

    let output = hkdf_sha256(&ikm, &[], info, 32);
    assert_eq!(output.len(), 32);
}

#[test]
fn test_hkdf_empty_info() {
    let ikm = [0xCD; 32];
    let salt = [0xEF; 16];

    let output = hkdf_sha256(&ikm, &salt, &[], 32);
    assert_eq!(output.len(), 32);
}

#[test]
fn test_hkdf_deterministic() {
    let ikm = [0x11; 32];
    let salt = [0x22; 32];
    let info = b"determinism test";

    let out1 = hkdf_sha256(&ikm, &salt, info, 32);
    let out2 = hkdf_sha256(&ikm, &salt, info, 32);
    assert_eq!(out1, out2);
}

#[test]
fn test_hkdf_different_ikm() {
    let ikm1 = [0x00; 32];
    let ikm2 = [0x01; 32];
    let salt = [];
    let info = b"test";

    let out1 = hkdf_sha256(&ikm1, &salt, info, 32);
    let out2 = hkdf_sha256(&ikm2, &salt, info, 32);
    assert_ne!(out1, out2);
}

#[test]
fn test_hkdf_different_info() {
    let ikm = [0x42; 32];
    let salt = [];

    let out1 = hkdf_sha256(&ikm, &salt, b"info1", 32);
    let out2 = hkdf_sha256(&ikm, &salt, b"info2", 32);
    assert_ne!(out1, out2);
}

// ============================================================================
// XChaCha20-Poly1305 Tests
// ============================================================================

#[test]
fn test_xchacha_encrypt_decrypt() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"Hello, encryption!";
    let aad = b"additional data";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_xchacha_empty_plaintext() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = &[];
    let aad = b"aad";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();

    assert!(decrypted.is_empty());
}

#[test]
fn test_xchacha_empty_aad() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"message";
    let aad = &[];

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext.as_slice(), decrypted.as_slice());
}

#[test]
fn test_xchacha_wrong_key_fails() {
    let key1 = [0x42; 32];
    let key2 = [0x43; 32];
    let nonce = [0x24; 24];
    let plaintext = b"secret";
    let aad = b"";

    let ciphertext = encrypt_xchacha20poly1305(&key1, &nonce, plaintext, aad).unwrap();
    let result = decrypt_xchacha20poly1305(&key2, &nonce, &ciphertext, aad);

    assert!(result.is_err(), "Wrong key should fail decryption");
}

#[test]
fn test_xchacha_wrong_nonce_fails() {
    let key = [0x42; 32];
    let nonce1 = [0x24; 24];
    let nonce2 = [0x25; 24];
    let plaintext = b"secret";
    let aad = b"";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce1, plaintext, aad).unwrap();
    let result = decrypt_xchacha20poly1305(&key, &nonce2, &ciphertext, aad);

    assert!(result.is_err(), "Wrong nonce should fail decryption");
}

#[test]
fn test_xchacha_wrong_aad_fails() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"secret";
    let aad1 = b"aad1";
    let aad2 = b"aad2";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad1).unwrap();
    let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad2);

    assert!(result.is_err(), "Wrong AAD should fail decryption");
}

#[test]
fn test_xchacha_tampered_ciphertext_fails() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext = b"secret message";
    let aad = b"";

    let mut ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();

    // Tamper with ciphertext
    ciphertext[0] ^= 0xFF;

    let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad);
    assert!(result.is_err(), "Tampered ciphertext should fail");
}

#[test]
fn test_xchacha_large_message() {
    let key = [0x42; 32];
    let nonce = [0x24; 24];
    let plaintext: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let aad = b"large message test";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, &plaintext, aad).unwrap();
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(plaintext, decrypted);
}

// ============================================================================
// Ed25519 Tests
// ============================================================================

#[test]
fn test_ed25519_sign_verify() {
    let (secret, public) = generate_keypair();
    let message = b"Test message";

    let signature = sign_ed25519(&secret, message).unwrap();
    let result = verify_ed25519(&public, message, &signature);

    assert!(result.is_ok());
}

#[test]
fn test_ed25519_deterministic() {
    let (secret, _) = generate_keypair();
    let message = b"Test message";

    let sig1 = sign_ed25519(&secret, message).unwrap();
    let sig2 = sign_ed25519(&secret, message).unwrap();

    assert_eq!(sig1, sig2, "Ed25519 signatures should be deterministic");
}

#[test]
fn test_ed25519_wrong_message_fails() {
    let (secret, public) = generate_keypair();
    let message1 = b"Original message";
    let message2 = b"Different message";

    let signature = sign_ed25519(&secret, message1).unwrap();
    let result = verify_ed25519(&public, message2, &signature);

    assert!(result.is_err(), "Signature should fail for wrong message");
}

#[test]
fn test_ed25519_wrong_key_fails() {
    let (secret1, _) = generate_keypair();
    let (_, public2) = generate_keypair();
    let message = b"Test message";

    let signature = sign_ed25519(&secret1, message).unwrap();
    let result = verify_ed25519(&public2, message, &signature);

    assert!(result.is_err(), "Signature should fail for wrong key");
}

#[test]
fn test_ed25519_derive_public_key() {
    let (secret, expected_public) = generate_keypair();
    let derived = derive_public_key(&secret);

    assert_eq!(derived, expected_public);
}

#[test]
fn test_ed25519_empty_message() {
    let (secret, public) = generate_keypair();
    let message = &[];

    let signature = sign_ed25519(&secret, message).unwrap();
    let result = verify_ed25519(&public, message, &signature);

    assert!(result.is_ok());
}

// ============================================================================
// HMAC-SHA-256 Tests
// ============================================================================

#[test]
fn test_hmac_basic() {
    let key = [0x42; 32];
    let message = b"Test message for HMAC";

    let mac = hmac_sha256(&key, message);
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_hmac_deterministic() {
    let key = [0x42; 32];
    let message = b"Test message";

    let mac1 = hmac_sha256(&key, message);
    let mac2 = hmac_sha256(&key, message);

    assert_eq!(mac1, mac2);
}

#[test]
fn test_hmac_different_keys() {
    let key1 = [0x00; 32];
    let key2 = [0x01; 32];
    let message = b"Same message";

    let mac1 = hmac_sha256(&key1, message);
    let mac2 = hmac_sha256(&key2, message);

    assert_ne!(mac1, mac2);
}

#[test]
fn test_hmac_different_messages() {
    let key = [0x42; 32];
    let msg1 = b"Message 1";
    let msg2 = b"Message 2";

    let mac1 = hmac_sha256(&key, msg1);
    let mac2 = hmac_sha256(&key, msg2);

    assert_ne!(mac1, mac2);
}

// ============================================================================
// Key Schedule Tests
// ============================================================================

#[test]
fn test_key_schedule_network_mac_key() {
    let network_key = [0x42; 32];
    let mac_key = KeySchedule::network_mac_key(&network_key);

    assert_eq!(mac_key.len(), 32);

    // Deterministic
    let mac_key2 = KeySchedule::network_mac_key(&network_key);
    assert_eq!(mac_key, mac_key2);
}

#[test]
fn test_key_schedule_manifest_key() {
    let capability_secret = [0xAA; 32];
    let object_id = [0xBB; 32];

    let key = KeySchedule::manifest_key(&capability_secret, &object_id);
    assert_eq!(key.len(), 32);
}

#[test]
fn test_key_schedule_manifest_nonce() {
    let capability_secret = [0xAA; 32];
    let object_id = [0xBB; 32];
    let revision1 = 1u64;
    let revision2 = 2u64;

    let nonce1 = KeySchedule::manifest_nonce(&capability_secret, &object_id, revision1);
    let nonce2 = KeySchedule::manifest_nonce(&capability_secret, &object_id, revision2);

    assert_eq!(nonce1.len(), 24);
    assert_ne!(nonce1, nonce2, "Different revisions should have different nonces");
}

#[test]
fn test_key_schedule_chunk_derivation() {
    let capability_secret = [0xAA; 32];
    let object_id = [0xBB; 32];
    let chunk_id = [0xCC; 32];

    let base = KeySchedule::chunk_key_base(&capability_secret, &object_id);
    let key = KeySchedule::chunk_key(&base, &chunk_id);
    let nonce = KeySchedule::chunk_nonce(&base, &chunk_id);

    assert_eq!(base.len(), 32);
    assert_eq!(key.len(), 32);
    assert_eq!(nonce.len(), 24);
}

#[test]
fn test_key_schedule_blob_key() {
    let blob_id = [0xDD; 32];
    let chunk_id = [0xEE; 32];

    let blob_key = KeySchedule::blob_key(&blob_id);
    let chunk_key = KeySchedule::blob_chunk_key(&blob_key, &chunk_id);
    let chunk_nonce = KeySchedule::blob_chunk_nonce(&blob_key, &chunk_id);

    assert_eq!(blob_key.len(), 32);
    assert_eq!(chunk_key.len(), 32);
    assert_eq!(chunk_nonce.len(), 24);
}

#[test]
fn test_key_schedule_aad_construction() {
    let object_id = [0xAA; 32];
    let chunk_id = [0xBB; 32];
    let blob_id = [0xCC; 32];

    let manifest_aad = KeySchedule::manifest_aad(&object_id);
    let object_chunk_aad = KeySchedule::object_chunk_aad(&object_id, &chunk_id);
    let blob_chunk_aad = KeySchedule::blob_chunk_aad(&blob_id, &chunk_id);

    assert_eq!(manifest_aad.len(), 32);
    assert_eq!(object_chunk_aad.len(), 64);
    assert_eq!(blob_chunk_aad.len(), 64);

    // Verify concatenation
    assert_eq!(&object_chunk_aad[..32], &object_id);
    assert_eq!(&object_chunk_aad[32..], &chunk_id);
}

// ============================================================================
// Identifier Tests
// ============================================================================

#[test]
fn test_node_id_from_public_key() {
    let public_key = [0x42; 32];
    let node_id = NodeId::from_public_key(&public_key);

    // NodeId should be hash of public key
    let expected = blake3_hash(&public_key);
    assert_eq!(node_id.0, expected);
}

#[test]
fn test_chunk_id_from_plaintext() {
    let data = b"Test chunk data";
    let chunk_id = ChunkId::from_plaintext(data);

    let expected = blake3_hash(data);
    assert_eq!(chunk_id.0, expected);
}

#[test]
fn test_blob_id_from_plaintext() {
    let data = b"Test blob data";
    let blob_id = BlobId::from_plaintext(data);

    let expected = blake3_hash(data);
    assert_eq!(blob_id.0, expected);
}

#[test]
fn test_blob_id_empty() {
    let empty_blob_id = BlobId::empty();
    let from_empty = BlobId::from_plaintext(&[]);

    assert_eq!(empty_blob_id, from_empty);
    assert_eq!(
        empty_blob_id.to_hex(),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

#[test]
fn test_xor_distance() {
    let id1 = NodeId::new([0xFF; 32]);
    let id2 = NodeId::new([0x00; 32]);
    let distance = id1.xor_distance(&id2);
    assert_eq!(distance, [0xFF; 32]);

    let id3 = NodeId::new([0xFF; 32]);
    let self_distance = id1.xor_distance(&id3);
    assert_eq!(self_distance, [0x00; 32]);
}

#[test]
fn test_leading_zeros() {
    let zero = NodeId::new([0x00; 32]);
    assert_eq!(zero.leading_zeros(), 256);

    let mut high_bit = [0x00; 32];
    high_bit[0] = 0x80;
    let id = NodeId::new(high_bit);
    assert_eq!(id.leading_zeros(), 0);

    let mut seven_zeros = [0x00; 32];
    seven_zeros[0] = 0x01;
    let id2 = NodeId::new(seven_zeros);
    assert_eq!(id2.leading_zeros(), 7);
}
