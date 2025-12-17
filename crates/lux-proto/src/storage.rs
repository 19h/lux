//! Storage formats per specification §9.1.
//!
//! Defines the on-disk and network format for encrypted chunks.

use bytes::{Bytes, BytesMut};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
use lux_core::CiphertextHash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Nonce size for XChaCha20-Poly1305
pub const NONCE_SIZE: usize = 24;
/// Tag size for XChaCha20-Poly1305
pub const TAG_SIZE: usize = 16;

/// Error during chunk parsing.
#[derive(Debug, Error)]
pub enum ChunkParseError {
    /// Chunk too small to contain required fields
    #[error("Chunk too small: expected at least {expected} bytes, got {actual}")]
    TooSmall { expected: usize, actual: usize },

    /// Decoding error
    #[error("Decode error: {0}")]
    Decode(#[from] DecodeError),
}

/// Encrypted chunk storage format per specification §9.1.
///
/// ```text
/// ┌────────────────────┬────────────────────┬──────────────┐
/// │    nonce (24)      │  ciphertext (var)  │   tag (16)   │
/// └────────────────────┴────────────────────┴──────────────┘
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredChunk {
    /// 24-byte nonce for XChaCha20-Poly1305
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext concatenated with 16-byte authentication tag
    pub ciphertext_with_tag: Vec<u8>,
}

impl StoredChunk {
    /// Creates a new stored chunk.
    pub fn new(nonce: [u8; NONCE_SIZE], ciphertext_with_tag: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext_with_tag,
        }
    }

    /// Returns the ciphertext (without tag).
    pub fn ciphertext(&self) -> &[u8] {
        if self.ciphertext_with_tag.len() >= TAG_SIZE {
            &self.ciphertext_with_tag[..self.ciphertext_with_tag.len() - TAG_SIZE]
        } else {
            &[]
        }
    }

    /// Returns the authentication tag.
    pub fn tag(&self) -> Option<&[u8]> {
        if self.ciphertext_with_tag.len() >= TAG_SIZE {
            Some(&self.ciphertext_with_tag[self.ciphertext_with_tag.len() - TAG_SIZE..])
        } else {
            None
        }
    }

    /// Returns the plaintext size (ciphertext size minus tag).
    pub fn plaintext_size(&self) -> usize {
        self.ciphertext_with_tag.len().saturating_sub(TAG_SIZE)
    }

    /// Serializes to bytes: nonce || ciphertext || tag
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(NONCE_SIZE + self.ciphertext_with_tag.len());
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext_with_tag);
        bytes
    }

    /// Deserializes from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ChunkParseError> {
        let min_size = NONCE_SIZE + TAG_SIZE;
        if bytes.len() < min_size {
            return Err(ChunkParseError::TooSmall {
                expected: min_size,
                actual: bytes.len(),
            });
        }

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&bytes[..NONCE_SIZE]);
        let ciphertext_with_tag = bytes[NONCE_SIZE..].to_vec();

        Ok(Self {
            nonce,
            ciphertext_with_tag,
        })
    }

    /// Computes the CiphertextHash per specification §17.1.
    ///
    /// CiphertextHash = BLAKE3(nonce || ciphertext || tag)
    pub fn ciphertext_hash(&self) -> CiphertextHash {
        let bytes = self.to_bytes();
        CiphertextHash::from_stored_bytes(&bytes)
    }

    /// Returns the total stored size in bytes.
    pub fn stored_size(&self) -> usize {
        NONCE_SIZE + self.ciphertext_with_tag.len()
    }
}

impl CanonicalEncode for StoredChunk {
    fn encode(&self, buf: &mut BytesMut) {
        self.nonce.encode(buf);
        self.ciphertext_with_tag.encode(buf);
    }
}

impl CanonicalDecode for StoredChunk {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let nonce = <[u8; NONCE_SIZE]>::decode(buf)?;
        let ciphertext_with_tag = Vec::<u8>::decode(buf)?;
        Ok(Self {
            nonce,
            ciphertext_with_tag,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stored_chunk_roundtrip() {
        let nonce = [0x42u8; NONCE_SIZE];
        let ciphertext_with_tag = vec![0xAA; 100];

        let chunk = StoredChunk::new(nonce, ciphertext_with_tag.clone());
        let bytes = chunk.to_bytes();
        let restored = StoredChunk::from_bytes(&bytes).unwrap();

        assert_eq!(restored.nonce, nonce);
        assert_eq!(restored.ciphertext_with_tag, ciphertext_with_tag);
    }

    #[test]
    fn test_stored_chunk_hash() {
        let nonce = [0x42u8; NONCE_SIZE];
        let ciphertext_with_tag = vec![0xAA; 100];

        let chunk = StoredChunk::new(nonce, ciphertext_with_tag);
        let hash1 = chunk.ciphertext_hash();
        let hash2 = chunk.ciphertext_hash();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_stored_chunk_too_small() {
        let bytes = vec![0u8; 10]; // Less than NONCE_SIZE + TAG_SIZE
        let result = StoredChunk::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_stored_chunk_sizes() {
        let nonce = [0u8; NONCE_SIZE];
        let ciphertext = vec![0u8; 50]; // 50 bytes of ciphertext
        let tag = vec![0u8; TAG_SIZE];
        let mut ciphertext_with_tag = ciphertext.clone();
        ciphertext_with_tag.extend_from_slice(&tag);

        let chunk = StoredChunk::new(nonce, ciphertext_with_tag);

        assert_eq!(chunk.plaintext_size(), 50);
        assert_eq!(chunk.stored_size(), NONCE_SIZE + 50 + TAG_SIZE);
    }
}
