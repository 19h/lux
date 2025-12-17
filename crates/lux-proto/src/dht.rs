//! DHT record types per specification §11.
//!
//! Defines the record types stored in the Kademlia DHT:
//! - NodeAnnouncement: Node presence announcements
//! - ManifestAnnouncement: Object manifest announcements
//! - ChunkHolders: Chunk storage location tracking

use std::collections::HashMap;

use bytes::{Bytes, BytesMut};
use lux_core::crypto::{hmac_sha256, KeySchedule};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
use lux_core::{
    ChunkId, CiphertextHash, NetworkKey, NodeId, ObjectId, Timestamp, MAX_CHUNK_HOLDERS,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::dag::CiphertextCommitment;
use crate::manifest::Manifest;

/// Error during DHT record validation.
#[derive(Debug, Error)]
pub enum DhtError {
    /// Invalid MAC
    #[error("Invalid record MAC")]
    InvalidMac,

    /// Record too large
    #[error("Record size {size} exceeds maximum {max}")]
    RecordTooLarge { size: usize, max: usize },

    /// Timestamp outside acceptable skew
    #[error("Timestamp outside acceptable skew")]
    ClockSkew,

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Holder key mismatch
    #[error("Holder key in record doesn't match lease")]
    HolderMismatch,

    /// Encoding error
    #[error("Encoding error: {0}")]
    Encode(#[from] DecodeError),
}

/// Chunk locator combining content and storage addresses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkLocator {
    /// Plaintext identity
    pub chunk_id: ChunkId,
    /// Storage address
    pub ciphertext_hash: CiphertextHash,
}

impl CanonicalEncode for ChunkLocator {
    fn encode(&self, buf: &mut BytesMut) {
        self.chunk_id.encode(buf);
        self.ciphertext_hash.encode(buf);
    }
}

impl CanonicalDecode for ChunkLocator {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            chunk_id: ChunkId::decode(buf)?,
            ciphertext_hash: CiphertextHash::decode(buf)?,
        })
    }
}

/// Storage lease body (signed by both parties).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageLeaseBody {
    /// Chunk being stored
    pub locator: ChunkLocator,
    /// Integrity commitment
    pub commitment: CiphertextCommitment,
    /// Storage node
    pub holder: NodeId,
    /// Lease issuer (client)
    pub issuer: NodeId,
    /// When the lease was issued
    pub issued_at: Timestamp,
    /// When the lease expires
    pub expires_at: Timestamp,
}

impl StorageLeaseBody {
    /// Returns true if the lease has expired.
    pub fn is_expired(&self) -> bool {
        Timestamp::now().is_after(&self.expires_at)
    }

    /// Returns the remaining time until expiration.
    pub fn time_remaining(&self) -> Option<std::time::Duration> {
        self.expires_at.duration_since(&Timestamp::now())
    }
}

impl CanonicalEncode for StorageLeaseBody {
    fn encode(&self, buf: &mut BytesMut) {
        self.locator.encode(buf);
        self.commitment.encode(buf);
        self.holder.encode(buf);
        self.issuer.encode(buf);
        self.issued_at.encode(buf);
        self.expires_at.encode(buf);
    }
}

impl CanonicalDecode for StorageLeaseBody {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            locator: ChunkLocator::decode(buf)?,
            commitment: CiphertextCommitment::decode(buf)?,
            holder: NodeId::decode(buf)?,
            issuer: NodeId::decode(buf)?,
            issued_at: Timestamp::decode(buf)?,
            expires_at: Timestamp::decode(buf)?,
        })
    }
}

/// Complete storage lease with both signatures.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageLease {
    /// The lease terms
    pub body: StorageLeaseBody,
    /// Signature from the issuer (client)
    #[serde_as(as = "[_; 64]")]
    pub issuer_signature: [u8; 64],
    /// Signature from the holder (storage node)
    #[serde_as(as = "[_; 64]")]
    pub holder_signature: [u8; 64],
}

impl StorageLease {
    /// Verifies both signatures on the lease.
    pub fn verify(
        &self,
        issuer_pubkey: &[u8; 32],
        holder_pubkey: &[u8; 32],
    ) -> Result<(), DhtError> {
        let body_bytes = self.body.to_vec();

        lux_core::crypto::verify_ed25519(issuer_pubkey, &body_bytes, &self.issuer_signature)
            .map_err(|_| DhtError::InvalidSignature)?;

        lux_core::crypto::verify_ed25519(holder_pubkey, &body_bytes, &self.holder_signature)
            .map_err(|_| DhtError::InvalidSignature)?;

        Ok(())
    }
}

impl CanonicalEncode for StorageLease {
    fn encode(&self, buf: &mut BytesMut) {
        self.body.encode(buf);
        self.issuer_signature.encode(buf);
        self.holder_signature.encode(buf);
    }
}

impl CanonicalDecode for StorageLease {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            body: StorageLeaseBody::decode(buf)?,
            issuer_signature: <[u8; 64]>::decode(buf)?,
            holder_signature: <[u8; 64]>::decode(buf)?,
        })
    }
}

/// Chunk storage announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkAnnouncement {
    /// The storage lease
    pub lease: StorageLease,
}

impl ChunkAnnouncement {
    /// Quality function for merge ordering per specification §11.5.
    ///
    /// Returns (expires_at, holder_id) for ordering. Higher expiration time wins,
    /// with holder_id as a deterministic tiebreaker.
    pub fn quality(&self) -> (i64, [u8; 32]) {
        (self.lease.body.expires_at.0, self.lease.body.holder.0)
    }
}

impl CanonicalEncode for ChunkAnnouncement {
    fn encode(&self, buf: &mut BytesMut) {
        self.lease.encode(buf);
    }
}

impl CanonicalDecode for ChunkAnnouncement {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            lease: StorageLease::decode(buf)?,
        })
    }
}

/// Chunk holders record (CRDT merge per specification §11.5).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChunkHolders {
    /// Map from holder NodeId to their announcement
    pub holders: HashMap<NodeId, ChunkAnnouncement>,
}

impl ChunkHolders {
    /// Creates a new empty chunk holders record.
    pub fn new() -> Self {
        Self {
            holders: HashMap::new(),
        }
    }

    /// Returns the number of holders.
    pub fn len(&self) -> usize {
        self.holders.len()
    }

    /// Returns true if there are no holders.
    pub fn is_empty(&self) -> bool {
        self.holders.is_empty()
    }

    /// Merges another chunk holders record into this one.
    ///
    /// Per specification §11.5:
    /// 1. Per-holder: retain announcement with maximum quality
    /// 2. Bounded set: retain top-K holders by quality (K = MAX_CHUNK_HOLDERS)
    pub fn merge(&mut self, other: &ChunkHolders) {
        for (holder, announcement) in &other.holders {
            match self.holders.get(holder) {
                Some(existing) => {
                    // Keep the one with higher quality
                    if announcement.quality() > existing.quality() {
                        self.holders.insert(*holder, announcement.clone());
                    }
                }
                None => {
                    self.holders.insert(*holder, announcement.clone());
                }
            }
        }

        // Bound the set if needed
        self.enforce_bounds();
    }

    /// Adds an announcement, merging if the holder already exists.
    pub fn add(&mut self, announcement: ChunkAnnouncement) {
        let holder = announcement.lease.body.holder;
        match self.holders.get(&holder) {
            Some(existing) => {
                if announcement.quality() > existing.quality() {
                    self.holders.insert(holder, announcement);
                }
            }
            None => {
                self.holders.insert(holder, announcement);
                self.enforce_bounds();
            }
        }
    }

    /// Removes expired leases.
    pub fn remove_expired(&mut self) {
        let now = Timestamp::now();
        self.holders
            .retain(|_, ann| ann.lease.body.expires_at.is_after(&now));
    }

    /// Returns holders sorted by quality (highest first).
    pub fn sorted_holders(&self) -> Vec<(&NodeId, &ChunkAnnouncement)> {
        let mut holders: Vec<_> = self.holders.iter().collect();
        holders.sort_by(|a, b| b.1.quality().cmp(&a.1.quality()));
        holders
    }

    fn enforce_bounds(&mut self) {
        while self.holders.len() > MAX_CHUNK_HOLDERS {
            // Find and remove the lowest quality holder
            let lowest = self
                .holders
                .iter()
                .min_by(|a, b| a.1.quality().cmp(&b.1.quality()))
                .map(|(k, _)| *k);

            if let Some(holder) = lowest {
                self.holders.remove(&holder);
            }
        }
    }
}

impl CanonicalEncode for ChunkHolders {
    fn encode(&self, buf: &mut BytesMut) {
        let len = self.holders.len() as u32;
        len.encode(buf);

        // Sort by holder NodeId for deterministic encoding
        let mut sorted: Vec<_> = self.holders.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);

        for (holder, announcement) in sorted {
            holder.encode(buf);
            announcement.encode(buf);
        }
    }
}

impl CanonicalDecode for ChunkHolders {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let len = u32::decode(buf)? as usize;
        let mut holders = HashMap::with_capacity(len);
        let mut last_key: Option<NodeId> = None;

        for _ in 0..len {
            let holder = NodeId::decode(buf)?;

            // Verify strictly ascending key order for canonical encoding
            if let Some(prev) = &last_key {
                if holder.0 <= prev.0 {
                    return Err(DecodeError::Custom(
                        "Map keys must be in strictly ascending order".to_string(),
                    ));
                }
            }
            last_key = Some(holder);

            let announcement = ChunkAnnouncement::decode(buf)?;
            holders.insert(holder, announcement);
        }

        Ok(Self { holders })
    }
}

/// Node announcement body (the signed portion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAnnouncementBody {
    /// Node ID (should match public key)
    pub node_id: NodeId,
    /// Announcement timestamp
    pub timestamp: Timestamp,
    /// Network addresses (e.g., QUIC endpoints)
    pub addresses: Vec<String>,
    /// Node capabilities/services
    pub services: u64,
    /// Public key for connection establishment
    pub public_key: [u8; 32],
}

impl CanonicalEncode for NodeAnnouncementBody {
    fn encode(&self, buf: &mut BytesMut) {
        self.node_id.encode(buf);
        self.timestamp.encode(buf);
        self.addresses.encode(buf);
        self.services.encode(buf);
        self.public_key.encode(buf);
    }
}

impl CanonicalDecode for NodeAnnouncementBody {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            node_id: NodeId::decode(buf)?,
            timestamp: Timestamp::decode(buf)?,
            addresses: Vec::<String>::decode(buf)?,
            services: u64::decode(buf)?,
            public_key: <[u8; 32]>::decode(buf)?,
        })
    }
}

/// Node presence announcement with signature.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeAnnouncement {
    /// Node ID
    pub node_id: NodeId,
    /// Announcement timestamp
    pub timestamp: Timestamp,
    /// Network addresses (e.g., QUIC endpoints)
    pub addresses: Vec<String>,
    /// Node capabilities/services
    pub services: u64,
    /// Public key for connection establishment
    pub public_key: [u8; 32],
    /// Ed25519 signature over the announcement body
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

impl NodeAnnouncement {
    /// Creates a new signed node announcement.
    pub fn new(
        node_id: NodeId,
        addresses: Vec<String>,
        services: u64,
        signing_key: &lux_core::SigningKey,
    ) -> Result<Self, lux_core::crypto::SignatureError> {
        let public_key = signing_key.public_key();
        let timestamp = Timestamp::now();

        // Create body for signing
        let body = NodeAnnouncementBody {
            node_id,
            timestamp,
            addresses: addresses.clone(),
            services,
            public_key,
        };

        let body_bytes = body.to_vec();
        let signature = signing_key.sign(&body_bytes)?;

        Ok(Self {
            node_id,
            timestamp,
            addresses,
            services,
            public_key,
            signature,
        })
    }

    /// Verifies the announcement signature.
    pub fn verify(&self) -> Result<(), DhtError> {
        // Verify node_id matches public key
        let expected_node_id = NodeId::from_public_key(&self.public_key);
        if self.node_id != expected_node_id {
            return Err(DhtError::InvalidSignature);
        }

        // Reconstruct the body for verification
        let body = NodeAnnouncementBody {
            node_id: self.node_id,
            timestamp: self.timestamp,
            addresses: self.addresses.clone(),
            services: self.services,
            public_key: self.public_key,
        };

        let body_bytes = body.to_vec();
        lux_core::crypto::verify_ed25519(&self.public_key, &body_bytes, &self.signature)
            .map_err(|_| DhtError::InvalidSignature)
    }

    /// Quality for supersede logic: (timestamp, encoded_bytes)
    pub fn quality(&self) -> (i64, Vec<u8>) {
        (self.timestamp.0, self.to_vec())
    }
}

impl CanonicalEncode for NodeAnnouncement {
    fn encode(&self, buf: &mut BytesMut) {
        self.node_id.encode(buf);
        self.timestamp.encode(buf);
        self.addresses.encode(buf);
        self.services.encode(buf);
        self.public_key.encode(buf);
        self.signature.encode(buf);
    }
}

impl CanonicalDecode for NodeAnnouncement {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            node_id: NodeId::decode(buf)?,
            timestamp: Timestamp::decode(buf)?,
            addresses: Vec::<String>::decode(buf)?,
            services: u64::decode(buf)?,
            public_key: <[u8; 32]>::decode(buf)?,
            signature: <[u8; 64]>::decode(buf)?,
        })
    }
}

/// Manifest announcement for mutable objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestAnnouncement {
    /// Object ID
    pub object_id: ObjectId,
    /// The full manifest
    pub manifest: Manifest,
}

impl ManifestAnnouncement {
    /// Quality function for manifest supersede logic per specification §11.4.
    ///
    /// Returns (revision, timestamp, encoded_bytes) for ordering. When merging
    /// manifest announcements for the same ObjectId:
    /// 1. Higher revision number wins (monotonically increasing)
    /// 2. If revisions equal, later timestamp wins
    /// 3. If timestamps equal, deterministic tiebreaker using encoded bytes
    ///
    /// This ensures exactly one manifest wins and all nodes converge to the
    /// same result.
    pub fn quality(&self) -> (u64, i64, Vec<u8>) {
        (
            self.manifest.body.revision.value(),
            self.manifest.body.modified_at.0,
            self.to_vec(),
        )
    }
}

impl CanonicalEncode for ManifestAnnouncement {
    fn encode(&self, buf: &mut BytesMut) {
        self.object_id.encode(buf);
        self.manifest.encode(buf);
    }
}

impl CanonicalDecode for ManifestAnnouncement {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            object_id: ObjectId::decode(buf)?,
            manifest: Manifest::decode(buf)?,
        })
    }
}

/// DHT record body types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DhtRecordBody {
    /// Node announcement (tag = 0)
    Node(NodeAnnouncement),
    /// Manifest announcement (tag = 1)
    Manifest(ManifestAnnouncement),
    /// Chunk holders (tag = 2)
    ChunkHolders(ChunkHolders),
}

impl DhtRecordBody {
    /// Returns the tag value for encoding.
    pub fn tag(&self) -> u32 {
        match self {
            DhtRecordBody::Node(_) => 0,
            DhtRecordBody::Manifest(_) => 1,
            DhtRecordBody::ChunkHolders(_) => 2,
        }
    }
}

impl CanonicalEncode for DhtRecordBody {
    fn encode(&self, buf: &mut BytesMut) {
        self.tag().encode(buf);
        match self {
            DhtRecordBody::Node(node) => node.encode(buf),
            DhtRecordBody::Manifest(manifest) => manifest.encode(buf),
            DhtRecordBody::ChunkHolders(holders) => holders.encode(buf),
        }
    }
}

impl CanonicalDecode for DhtRecordBody {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let tag = u32::decode(buf)?;
        match tag {
            0 => Ok(DhtRecordBody::Node(NodeAnnouncement::decode(buf)?)),
            1 => Ok(DhtRecordBody::Manifest(ManifestAnnouncement::decode(buf)?)),
            2 => Ok(DhtRecordBody::ChunkHolders(ChunkHolders::decode(buf)?)),
            _ => Err(DecodeError::InvalidEnumTag(tag)),
        }
    }
}

/// Authenticated DHT record per specification §11.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRecord {
    /// Record body
    pub body: DhtRecordBody,
    /// MAC: HMAC(network_mac_key, canonical_encode(body))
    pub mac: [u8; 32],
}

impl DhtRecord {
    /// Creates a new DHT record with MAC.
    pub fn new(body: DhtRecordBody, network_key: &NetworkKey) -> Self {
        let mac_key = KeySchedule::network_mac_key(network_key.as_bytes());
        let body_bytes = body.to_vec();
        let mac = hmac_sha256(&mac_key, &body_bytes);

        Self { body, mac }
    }

    /// Verifies the record MAC.
    pub fn verify(&self, network_key: &NetworkKey) -> Result<(), DhtError> {
        let mac_key = KeySchedule::network_mac_key(network_key.as_bytes());
        let body_bytes = self.body.to_vec();
        let expected_mac = hmac_sha256(&mac_key, &body_bytes);

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in self.mac.iter().zip(expected_mac.iter()) {
            diff |= a ^ b;
        }

        if diff == 0 {
            Ok(())
        } else {
            Err(DhtError::InvalidMac)
        }
    }

    /// Validates record size per specification §11.3.
    pub fn validate_size(&self) -> Result<(), DhtError> {
        let encoded = self.to_vec();
        if encoded.len() > lux_core::DHT_MAX_RECORD_SIZE {
            Err(DhtError::RecordTooLarge {
                size: encoded.len(),
                max: lux_core::DHT_MAX_RECORD_SIZE,
            })
        } else {
            Ok(())
        }
    }
}

impl CanonicalEncode for DhtRecord {
    fn encode(&self, buf: &mut BytesMut) {
        self.body.encode(buf);
        self.mac.encode(buf);
    }
}

impl CanonicalDecode for DhtRecord {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            body: DhtRecordBody::decode(buf)?,
            mac: <[u8; 32]>::decode(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lux_core::SigningKey;

    #[test]
    fn test_dht_record_mac() {
        let network_key = NetworkKey::random();
        let signing_key = SigningKey::random();
        let public_key = signing_key.public_key();
        let node_id = NodeId::from_public_key(&public_key);

        let node = NodeAnnouncement::new(
            node_id,
            vec!["127.0.0.1:8080".to_string()],
            0,
            &signing_key,
        )
        .unwrap();

        let record = DhtRecord::new(DhtRecordBody::Node(node), &network_key);
        assert!(record.verify(&network_key).is_ok());

        // Wrong key should fail
        let wrong_key = NetworkKey::random();
        assert!(record.verify(&wrong_key).is_err());
    }

    #[test]
    fn test_chunk_holders_merge() {
        let mut holders1 = ChunkHolders::new();
        let mut holders2 = ChunkHolders::new();

        // Create two announcements for different holders
        let lease1 = create_test_lease(NodeId::new([0x11; 32]), Timestamp::new(1000));
        let lease2 = create_test_lease(NodeId::new([0x22; 32]), Timestamp::new(2000));

        holders1.add(ChunkAnnouncement { lease: lease1.clone() });
        holders2.add(ChunkAnnouncement { lease: lease2.clone() });

        holders1.merge(&holders2);

        assert_eq!(holders1.len(), 2);
    }

    #[test]
    fn test_chunk_holders_quality_merge() {
        let mut holders = ChunkHolders::new();

        let holder_id = NodeId::new([0x11; 32]);
        let lease1 = create_test_lease(holder_id, Timestamp::new(1000));
        let lease2 = create_test_lease(holder_id, Timestamp::new(2000));

        holders.add(ChunkAnnouncement { lease: lease1 });
        holders.add(ChunkAnnouncement { lease: lease2 });

        // Should keep the one with higher quality (later expiration)
        assert_eq!(holders.len(), 1);
        let ann = holders.holders.get(&holder_id).unwrap();
        assert_eq!(ann.lease.body.expires_at.0, 2000);
    }

    #[test]
    fn test_chunk_holders_bounds() {
        let mut holders = ChunkHolders::new();

        // Add more than MAX_CHUNK_HOLDERS
        for i in 0..(MAX_CHUNK_HOLDERS + 10) {
            let mut holder_bytes = [0u8; 32];
            holder_bytes[0] = i as u8;
            let lease = create_test_lease(NodeId::new(holder_bytes), Timestamp::new(i as i64));
            holders.add(ChunkAnnouncement { lease });
        }

        assert_eq!(holders.len(), MAX_CHUNK_HOLDERS);
    }

    #[test]
    fn test_chunk_holders_encoding_roundtrip() {
        let mut holders = ChunkHolders::new();

        // Add multiple holders
        let lease1 = create_test_lease(NodeId::new([0x11; 32]), Timestamp::new(1000));
        let lease2 = create_test_lease(NodeId::new([0x22; 32]), Timestamp::new(2000));
        let lease3 = create_test_lease(NodeId::new([0x33; 32]), Timestamp::new(3000));

        holders.add(ChunkAnnouncement { lease: lease1 });
        holders.add(ChunkAnnouncement { lease: lease2 });
        holders.add(ChunkAnnouncement { lease: lease3 });

        // Encode and decode
        let encoded = holders.to_vec();
        let decoded = ChunkHolders::from_bytes(&encoded).unwrap();

        assert_eq!(holders.len(), decoded.len());
    }

    #[test]
    fn test_chunk_holders_reject_unordered_keys() {
        use bytes::BytesMut;

        // Manually construct invalid encoded data with keys out of order
        let mut buf = BytesMut::new();

        // Write length (2 entries)
        2u32.encode(&mut buf);

        // Write second key first (wrong order: 0x22 before 0x11)
        let holder2 = NodeId::new([0x22; 32]);
        holder2.encode(&mut buf);
        let lease2 = create_test_lease(holder2, Timestamp::new(2000));
        ChunkAnnouncement { lease: lease2 }.encode(&mut buf);

        // Write first key second
        let holder1 = NodeId::new([0x11; 32]);
        holder1.encode(&mut buf);
        let lease1 = create_test_lease(holder1, Timestamp::new(1000));
        ChunkAnnouncement { lease: lease1 }.encode(&mut buf);

        // Attempt to decode - should fail due to unordered keys
        let result = ChunkHolders::from_bytes(&buf.freeze());
        assert!(result.is_err());
    }

    fn create_test_lease(holder: NodeId, expires_at: Timestamp) -> StorageLease {
        StorageLease {
            body: StorageLeaseBody {
                locator: ChunkLocator {
                    chunk_id: ChunkId::new([0xAA; 32]),
                    ciphertext_hash: CiphertextHash::new([0xBB; 32]),
                },
                commitment: CiphertextCommitment {
                    merkle_root: [0; 32],
                    size: 1000,
                    block_size: 1000,
                    block_count: 1,
                },
                holder,
                issuer: NodeId::new([0xFF; 32]),
                issued_at: Timestamp::new(0),
                expires_at,
            },
            issuer_signature: [0; 64],
            holder_signature: [0; 64],
        }
    }
}
