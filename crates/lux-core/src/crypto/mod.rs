//! Cryptographic primitives for Lux.
//!
//! Implements the algorithm suite specified in §5.1:
//! - HKDF-SHA-256 (RFC 5869)
//! - HMAC-SHA-256 (RFC 2104)
//! - XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
//! - BLAKE3 (256-bit default mode)
//! - Ed25519 (RFC 8032 pure mode)
//! - X25519 (RFC 7748)

mod aead;
mod blake3_hash;
mod hkdf;
mod keys;
mod signature;

pub use aead::{decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, AeadError};
pub use blake3_hash::blake3_hash;
pub use hkdf::{hkdf_sha256, hmac_sha256};
pub use keys::KeySchedule;
pub use signature::{derive_public_key, generate_keypair, sign_ed25519, verify_ed25519, SignatureError};

/// AEAD nonce size for XChaCha20-Poly1305
pub const NONCE_SIZE: usize = 24;

/// AEAD tag size for XChaCha20-Poly1305
pub const TAG_SIZE: usize = 16;

/// Key size for all symmetric operations
pub const KEY_SIZE: usize = 32;

/// Signature size for Ed25519
pub const SIGNATURE_SIZE: usize = 64;
