//! Key types per specification §7.2.
//!
//! Defines secret key types used for network authentication and object decryption.

use std::fmt;

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};

/// Network membership secret key.
///
/// Used to authenticate DHT messages via MAC.
/// Possession of this key grants participation in DHT operations.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkKey(pub [u8; 32]);

impl NetworkKey {
    /// Creates a new network key from bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generates a random network key.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Returns the inner bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for NetworkKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NetworkKey([REDACTED])")
    }
}

impl From<[u8; 32]> for NetworkKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl CanonicalEncode for NetworkKey {
    fn encode(&self, buf: &mut BytesMut) {
        self.0.encode(buf);
    }
}

impl CanonicalDecode for NetworkKey {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self(<[u8; 32]>::decode(buf)?))
    }
}

/// Zeroizes the key on drop for security.
impl Drop for NetworkKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Object decryption capability secret.
///
/// Provides read access to an object. Encoded in object URIs.
/// Possession of this key allows decryption of the object and its chunks.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySecret(pub [u8; 32]);

impl CapabilitySecret {
    /// Creates a new capability secret from bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generates a random capability secret.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Returns the inner bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Encodes as base64url (for URI embedding).
    pub fn to_base64url(&self) -> String {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Decodes from base64url.
    pub fn from_base64url(s: &str) -> Result<Self, base64::DecodeError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let bytes = URL_SAFE_NO_PAD.decode(s)?;
        if bytes.len() != 32 {
            return Err(base64::DecodeError::InvalidLength(bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Debug for CapabilitySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CapabilitySecret([REDACTED])")
    }
}

impl From<[u8; 32]> for CapabilitySecret {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl CanonicalEncode for CapabilitySecret {
    fn encode(&self, buf: &mut BytesMut) {
        self.0.encode(buf);
    }
}

impl CanonicalDecode for CapabilitySecret {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self(<[u8; 32]>::decode(buf)?))
    }
}

/// Zeroizes the secret on drop for security.
impl Drop for CapabilitySecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Ed25519 signing key for creating manifests and signing leases.
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKey(pub [u8; 32]);

impl SigningKey {
    /// Creates a new signing key from bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a signing key from bytes (alias for new).
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(*bytes)
    }

    /// Generates a random signing key.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Returns the inner bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the public key.
    pub fn public_key(&self) -> [u8; 32] {
        crate::crypto::derive_public_key(&self.0)
    }

    /// Signs a message.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64], crate::crypto::SignatureError> {
        crate::crypto::sign_ed25519(&self.0, message)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey([REDACTED])")
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.0.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

impl Eq for SigningKey {}

impl From<[u8; 32]> for SigningKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl CanonicalEncode for SigningKey {
    fn encode(&self, buf: &mut BytesMut) {
        self.0.encode(buf);
    }
}

impl CanonicalDecode for SigningKey {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self(<[u8; 32]>::decode(buf)?))
    }
}

/// Zeroizes the key on drop for security.
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_secret_base64url() {
        let secret = CapabilitySecret::random();
        let encoded = secret.to_base64url();
        let decoded = CapabilitySecret::from_base64url(&encoded).unwrap();
        assert_eq!(secret.0, decoded.0);
    }

    #[test]
    fn test_signing_key_sign_verify() {
        let key = SigningKey::random();
        let public_key = key.public_key();
        let message = b"Hello, Lux!";

        let signature = key.sign(message).unwrap();

        let result = crate::crypto::verify_ed25519(&public_key, message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_network_key_debug_redacted() {
        let key = NetworkKey::random();
        let debug_str = format!("{:?}", key);
        assert!(debug_str.contains("REDACTED"));
        assert!(!debug_str.contains(&hex::encode(key.0)));
    }

    #[test]
    fn test_signing_key_equality_constant_time() {
        let key1 = SigningKey::new([0x42; 32]);
        let key2 = SigningKey::new([0x42; 32]);
        let key3 = SigningKey::new([0x43; 32]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
