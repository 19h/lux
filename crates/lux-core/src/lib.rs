//! Lux Core - Core types, traits, and primitives for the Lux distributed filesystem.
//!
//! This crate provides:
//! - Cryptographic primitives (HKDF, AEAD, BLAKE3)
//! - Canonical encoding for deterministic serialization
//! - Identifier types (NodeId, ObjectId, ChunkId, etc.)
//! - Timestamp and clock skew validation

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod crypto;
pub mod encoding;
pub mod identifiers;
pub mod keys;
pub mod time;

pub use crypto::*;
pub use encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
pub use identifiers::*;
pub use keys::*;
pub use time::*;

/// Protocol major version as per specification §5.
pub const PROTOCOL_VERSION_MAJOR: u32 = 1;
/// Protocol minor version as per specification §5.
pub const PROTOCOL_VERSION_MINOR: u32 = 0;

/// Maximum clock skew allowed in milliseconds (5 minutes)
pub const MAX_CLOCK_SKEW_MS: i64 = 300_000;

/// Maximum DHT record size in bytes
pub const DHT_MAX_RECORD_SIZE: usize = 65536;

/// Maximum number of chunk holders per DHT record
pub const MAX_CHUNK_HOLDERS: usize = 64;
