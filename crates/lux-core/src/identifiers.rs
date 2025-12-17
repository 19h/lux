//! Identifier types per specification §7.
//!
//! Defines all 32-byte identifier types used throughout Lux:
//! - `NodeId` - Node identity (typically H(pubkey))
//! - `ObjectId` - Mutable object identifier (random)
//! - `ChunkId` - BLAKE3(plaintext_chunk)
//! - `CiphertextHash` - BLAKE3(stored_bytes)
//! - `BlobId` - BLAKE3(full_plaintext)
//! - `DagRef` - BLAKE3(canonical_encode(DagNode)) or EMPTY

use std::fmt;

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};

use crate::crypto::blake3_hash;
use crate::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};

/// Well-known constant: BLAKE3("") per specification §9.4
pub const EMPTY_BLOB_ID: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

/// Well-known constant: BLAKE3("lux/v1/empty-dag") per specification §9.4
pub const EMPTY_DAG_REF: [u8; 32] = [
    0x98, 0x40, 0x6f, 0x28, 0xac, 0x2f, 0x17, 0xf4, 0xfa, 0x1b, 0x6f, 0x75, 0x6a, 0x51, 0xa6, 0xb9,
    0x1b, 0x1d, 0x95, 0x3f, 0x46, 0x6a, 0x5e, 0x77, 0x30, 0xf9, 0xee, 0x6a, 0xcc, 0x7c, 0x3e, 0x59,
];

/// Macro to define a 32-byte identifier type with common implementations.
macro_rules! define_id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
        pub struct $name(pub [u8; 32]);

        impl $name {
            /// Creates a new identifier from a 32-byte array.
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Creates a zero identifier.
            pub const fn zero() -> Self {
                Self([0u8; 32])
            }

            /// Returns the inner bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Returns the inner bytes as a slice.
            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }

            /// Creates from a hex string.
            pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
                let bytes = hex::decode(s)?;
                if bytes.len() != 32 {
                    return Err(hex::FromHexError::InvalidStringLength);
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Self(arr))
            }

            /// Returns as a hex string.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            /// Computes XOR distance for Kademlia routing.
            pub fn xor_distance(&self, other: &Self) -> [u8; 32] {
                let mut result = [0u8; 32];
                for i in 0..32 {
                    result[i] = self.0[i] ^ other.0[i];
                }
                result
            }

            /// Returns the leading zero bits count (for k-bucket indexing).
            pub fn leading_zeros(&self) -> u32 {
                let mut zeros = 0u32;
                for byte in &self.0 {
                    if *byte == 0 {
                        zeros += 8;
                    } else {
                        zeros += byte.leading_zeros();
                        break;
                    }
                }
                zeros
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), &self.to_hex()[..16])
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", &self.to_hex()[..16])
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl CanonicalEncode for $name {
            fn encode(&self, buf: &mut BytesMut) {
                self.0.encode(buf);
            }
        }

        impl CanonicalDecode for $name {
            fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
                Ok(Self(<[u8; 32]>::decode(buf)?))
            }
        }
    };
}

define_id_type!(
    /// Node identity, typically derived as H(public_key).
    ///
    /// Uniquely identifies a node in the network.
    NodeId
);

define_id_type!(
    /// Mutable object identifier (random 32 bytes).
    ///
    /// Identifies a mutable object independent of its content.
    ObjectId
);

define_id_type!(
    /// Content hash of a plaintext chunk: BLAKE3(plaintext_chunk).
    ///
    /// Enables deduplication across objects.
    ChunkId
);

define_id_type!(
    /// Hash of stored (encrypted) bytes: BLAKE3(nonce || ciphertext || tag).
    ///
    /// Used for storage addressing.
    CiphertextHash
);

define_id_type!(
    /// Content hash of full plaintext: BLAKE3(full_plaintext).
    ///
    /// Used for blob addressing and convergent encryption key derivation.
    BlobId
);

define_id_type!(
    /// Reference to a DAG node: BLAKE3(canonical_encode(DagNode)).
    ///
    /// Special value EMPTY_DAG_REF represents an empty DAG.
    DagRef
);

impl NodeId {
    /// Creates a NodeId from a public key by hashing it.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self(blake3_hash(public_key))
    }

    /// Generates a random NodeId.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl ObjectId {
    /// Generates a random ObjectId.
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }
}

impl ChunkId {
    /// Computes ChunkId from plaintext chunk data.
    pub fn from_plaintext(data: &[u8]) -> Self {
        Self(blake3_hash(data))
    }
}

impl CiphertextHash {
    /// Computes CiphertextHash from stored bytes.
    pub fn from_stored_bytes(data: &[u8]) -> Self {
        Self(blake3_hash(data))
    }
}

impl BlobId {
    /// Computes BlobId from full plaintext.
    pub fn from_plaintext(data: &[u8]) -> Self {
        Self(blake3_hash(data))
    }

    /// Computes BlobId from a DAG root reference per specification §7.1.
    ///
    /// BlobId = BLAKE3(DagRef bytes)
    pub fn from_dag_root(dag_ref: &DagRef) -> Self {
        Self(blake3_hash(&dag_ref.0))
    }

    /// Returns the empty blob ID constant.
    pub const fn empty() -> Self {
        Self(EMPTY_BLOB_ID)
    }
}

impl DagRef {
    /// Computes DagRef from the canonical encoding of a DAG node.
    pub fn from_encoded(data: &[u8]) -> Self {
        Self(blake3_hash(data))
    }

    /// Returns the empty DAG reference constant.
    pub const fn empty() -> Self {
        Self(EMPTY_DAG_REF)
    }

    /// Returns true if this is the empty DAG reference.
    pub fn is_empty(&self) -> bool {
        self.0 == EMPTY_DAG_REF
    }
}

/// Revision identifier - strictly monotonic per ObjectId.
///
/// Per specification §7.1, this serves dual purposes:
/// - Preventing AEAD nonce reuse
/// - Enabling point-in-time recovery
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
pub struct RevisionId(pub u64);

impl RevisionId {
    /// Creates a new revision ID.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the inner value.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Increments the revision ID.
    pub fn increment(&self) -> Self {
        Self(self.0.saturating_add(1))
    }

    /// Returns the initial revision ID.
    pub const fn initial() -> Self {
        Self(0)
    }
}

impl CanonicalEncode for RevisionId {
    fn encode(&self, buf: &mut BytesMut) {
        self.0.encode(buf);
    }
}

impl CanonicalDecode for RevisionId {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self(u64::decode(buf)?))
    }
}

impl fmt::Display for RevisionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r{}", self.0)
    }
}

/// Crypto version enum per specification §7.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u32)]
pub enum CryptoVersion {
    /// Version 1 - current and only version.
    #[default]
    V1 = 1,
}

impl CryptoVersion {
    /// Returns the tag value for encoding.
    pub const fn tag(&self) -> u32 {
        match self {
            CryptoVersion::V1 => 1,
        }
    }

    /// Creates from a tag value.
    pub fn from_tag(tag: u32) -> Result<Self, DecodeError> {
        match tag {
            1 => Ok(CryptoVersion::V1),
            _ => Err(DecodeError::InvalidEnumTag(tag)),
        }
    }
}

impl CanonicalEncode for CryptoVersion {
    fn encode(&self, buf: &mut BytesMut) {
        self.tag().encode(buf);
    }
}

impl CanonicalDecode for CryptoVersion {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let tag = u32::decode(buf)?;
        Self::from_tag(tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_blob_id() {
        let blob_id = BlobId::from_plaintext(&[]);
        assert_eq!(blob_id.0, EMPTY_BLOB_ID);
        assert_eq!(
            blob_id.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn test_empty_dag_ref() {
        let expected = blake3_hash(b"lux/v1/empty-dag");
        assert_eq!(expected, EMPTY_DAG_REF);

        let dag_ref = DagRef::empty();
        assert!(dag_ref.is_empty());
        assert_eq!(
            dag_ref.to_hex(),
            "98406f28ac2f17f4fa1b6f756a51a6b91b1d953f466a5e7730f9ee6acc7c3e59"
        );
    }

    #[test]
    fn test_crypto_version_encoding() {
        let v1 = CryptoVersion::V1;
        let encoded = v1.to_bytes();
        assert_eq!(encoded.to_vec(), vec![0x01, 0x00, 0x00, 0x00]);

        let decoded = CryptoVersion::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, CryptoVersion::V1);
    }

    #[test]
    fn test_revision_id_encoding() {
        let rev = RevisionId::new(42);
        let encoded = rev.to_bytes();
        let decoded = RevisionId::from_bytes(&encoded).unwrap();
        assert_eq!(rev, decoded);
    }

    #[test]
    fn test_revision_id_increment() {
        let rev = RevisionId::new(5);
        let next = rev.increment();
        assert_eq!(next.value(), 6);
    }

    #[test]
    fn test_xor_distance() {
        let id1 = NodeId::new([0xFF; 32]);
        let id2 = NodeId::new([0x00; 32]);
        let distance = id1.xor_distance(&id2);
        assert_eq!(distance, [0xFF; 32]);

        let id3 = NodeId::new([0xFF; 32]);
        let distance2 = id1.xor_distance(&id3);
        assert_eq!(distance2, [0x00; 32]);
    }

    #[test]
    fn test_leading_zeros() {
        let id1 = NodeId::new([0x00; 32]);
        assert_eq!(id1.leading_zeros(), 256);

        let mut bytes = [0x00; 32];
        bytes[0] = 0x80; // 10000000
        let id2 = NodeId::new(bytes);
        assert_eq!(id2.leading_zeros(), 0);

        bytes[0] = 0x01; // 00000001
        let id3 = NodeId::new(bytes);
        assert_eq!(id3.leading_zeros(), 7);
    }

    #[test]
    fn test_from_hex() {
        let hex_str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
        let id = BlobId::from_hex(hex_str).unwrap();
        assert_eq!(id.to_hex(), hex_str);
    }

    #[test]
    fn test_chunk_id_from_plaintext() {
        let data = b"Hello, Lux!";
        let chunk_id = ChunkId::from_plaintext(data);
        let expected = blake3_hash(data);
        assert_eq!(chunk_id.0, expected);
    }

    #[test]
    fn test_canonical_encoding_roundtrip() {
        let original = ObjectId::random();
        let encoded = original.to_bytes();
        let decoded = ObjectId::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }
}
