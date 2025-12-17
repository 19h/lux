//! DHT record storage and CRDT merge logic.
//!
//! Implements the record storage per specification §11 with proper
//! merge semantics for each record type.

use std::collections::HashMap;

use lux_core::encoding::CanonicalEncode;
use lux_core::{CiphertextHash, NetworkKey, NodeId, ObjectId, Timestamp};

use crate::{DEFAULT_MAX_RECORDS, DEFAULT_RECORD_TTL_SECS};
use lux_proto::dht::{
    ChunkHolders, DhtError, DhtRecord, DhtRecordBody, ManifestAnnouncement, NodeAnnouncement,
};
use parking_lot::RwLock;
use tracing::{debug, warn};

/// Configuration for record storage.
#[derive(Debug, Clone)]
pub struct RecordStoreConfig {
    /// Maximum number of records to store
    pub max_records: usize,
    /// Enable record expiration
    pub expiration_enabled: bool,
    /// Record TTL in seconds
    pub record_ttl_secs: u64,
}

impl Default for RecordStoreConfig {
    fn default() -> Self {
        Self {
            max_records: DEFAULT_MAX_RECORDS,
            expiration_enabled: true,
            record_ttl_secs: DEFAULT_RECORD_TTL_SECS,
        }
    }
}

/// Key type for DHT records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKey {
    /// Node announcement (keyed by NodeId)
    Node(NodeId),
    /// Manifest announcement (keyed by ObjectId)
    Manifest(ObjectId),
    /// Chunk holders (keyed by CiphertextHash)
    ChunkHolders(CiphertextHash),
}

impl RecordKey {
    /// Returns the 32-byte key for DHT routing.
    pub fn as_bytes(&self) -> [u8; 32] {
        match self {
            RecordKey::Node(id) => id.0,
            RecordKey::Manifest(id) => id.0,
            RecordKey::ChunkHolders(hash) => hash.0,
        }
    }
}

/// Stored record with metadata.
struct StoredRecord {
    record: DhtRecord,
    stored_at: Timestamp,
}

/// DHT record storage with merge logic.
pub struct RecordStore {
    /// Network key for MAC verification
    network_key: NetworkKey,
    /// Node announcements
    nodes: RwLock<HashMap<NodeId, StoredRecord>>,
    /// Manifest announcements
    manifests: RwLock<HashMap<ObjectId, StoredRecord>>,
    /// Chunk holders
    chunk_holders: RwLock<HashMap<CiphertextHash, ChunkHolders>>,
    /// Configuration
    config: RecordStoreConfig,
}

impl RecordStore {
    /// Creates a new record store.
    pub fn new(network_key: NetworkKey, config: RecordStoreConfig) -> Self {
        Self {
            network_key,
            nodes: RwLock::new(HashMap::new()),
            manifests: RwLock::new(HashMap::new()),
            chunk_holders: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Stores a record after validation.
    ///
    /// Applies appropriate merge semantics based on record type.
    pub fn store(&self, record: DhtRecord) -> Result<(), DhtError> {
        // Validate MAC
        record.verify(&self.network_key)?;

        // Validate size
        record.validate_size()?;

        // Validate timestamp
        self.validate_timestamp(&record)?;

        // Store based on type
        match &record.body {
            DhtRecordBody::Node(node) => self.store_node(node.clone(), record)?,
            DhtRecordBody::Manifest(manifest) => self.store_manifest(manifest.clone(), record)?,
            DhtRecordBody::ChunkHolders(holders) => self.merge_chunk_holders(holders)?,
        }

        Ok(())
    }

    /// Gets a record by key.
    pub fn get(&self, key: &RecordKey) -> Option<DhtRecord> {
        match key {
            RecordKey::Node(id) => self.nodes.read().get(id).map(|r| r.record.clone()),
            RecordKey::Manifest(id) => self.manifests.read().get(id).map(|r| r.record.clone()),
            RecordKey::ChunkHolders(hash) => self.chunk_holders.read().get(hash).map(|holders| {
                DhtRecord::new(DhtRecordBody::ChunkHolders(holders.clone()), &self.network_key)
            }),
        }
    }

    /// Gets a node announcement.
    pub fn get_node(&self, node_id: &NodeId) -> Option<NodeAnnouncement> {
        self.nodes.read().get(node_id).and_then(|r| {
            if let DhtRecordBody::Node(node) = &r.record.body {
                Some(node.clone())
            } else {
                None
            }
        })
    }

    /// Gets a manifest announcement.
    pub fn get_manifest(&self, object_id: &ObjectId) -> Option<ManifestAnnouncement> {
        self.manifests.read().get(object_id).and_then(|r| {
            if let DhtRecordBody::Manifest(manifest) = &r.record.body {
                Some(manifest.clone())
            } else {
                None
            }
        })
    }

    /// Gets chunk holders.
    pub fn get_chunk_holders(&self, hash: &CiphertextHash) -> Option<ChunkHolders> {
        self.chunk_holders.read().get(hash).cloned()
    }

    /// Removes expired records.
    pub fn expire(&self) {
        if !self.config.expiration_enabled {
            return;
        }

        let now = Timestamp::now();
        let ttl_ms = self.config.record_ttl_secs as i64 * 1000;

        // Expire node announcements
        {
            let mut nodes = self.nodes.write();
            nodes.retain(|_, r| now.0 - r.stored_at.0 < ttl_ms);
        }

        // Expire manifests
        {
            let mut manifests = self.manifests.write();
            manifests.retain(|_, r| now.0 - r.stored_at.0 < ttl_ms);
        }

        // Remove expired chunk holders
        {
            let mut holders = self.chunk_holders.write();
            for (_, h) in holders.iter_mut() {
                h.remove_expired();
            }
            holders.retain(|_, h| !h.is_empty());
        }
    }

    /// Returns statistics about stored records.
    pub fn stats(&self) -> RecordStoreStats {
        RecordStoreStats {
            node_count: self.nodes.read().len(),
            manifest_count: self.manifests.read().len(),
            chunk_holder_count: self.chunk_holders.read().len(),
        }
    }

    fn store_node(&self, node: NodeAnnouncement, record: DhtRecord) -> Result<(), DhtError> {
        // Verify node announcement signature
        node.verify()?;

        let node_id = node.node_id;
        let mut nodes = self.nodes.write();

        // Check supersede logic: newer timestamp wins
        if let Some(existing) = nodes.get(&node_id) {
            if let DhtRecordBody::Node(existing_node) = &existing.record.body {
                if node.quality() <= existing_node.quality() {
                    debug!(node_id = %node_id, "Node announcement superseded by existing");
                    return Ok(());
                }
            }
        }

        nodes.insert(
            node_id,
            StoredRecord {
                record,
                stored_at: Timestamp::now(),
            },
        );

        debug!(node_id = %node_id, "Stored node announcement");
        Ok(())
    }

    fn store_manifest(
        &self,
        manifest: ManifestAnnouncement,
        record: DhtRecord,
    ) -> Result<(), DhtError> {
        let object_id = manifest.object_id;
        let mut manifests = self.manifests.write();

        // Check supersede logic: higher revision wins, then timestamp, then bytes
        if let Some(existing) = manifests.get(&object_id) {
            if let DhtRecordBody::Manifest(existing_manifest) = &existing.record.body {
                if manifest.quality() <= existing_manifest.quality() {
                    debug!(object_id = %object_id, "Manifest superseded by existing");
                    return Ok(());
                }
            }
        }

        // Verify manifest signature
        manifest
            .manifest
            .verify()
            .map_err(|_| DhtError::InvalidSignature)?;

        manifests.insert(
            object_id,
            StoredRecord {
                record,
                stored_at: Timestamp::now(),
            },
        );

        debug!(
            object_id = %object_id,
            revision = manifest.manifest.body.revision.value(),
            "Stored manifest announcement"
        );
        Ok(())
    }

    fn merge_chunk_holders(&self, incoming: &ChunkHolders) -> Result<(), DhtError> {
        // Get the ciphertext hash from one of the announcements
        let hash = incoming
            .holders
            .values()
            .next()
            .map(|ann| ann.lease.body.locator.ciphertext_hash);

        let hash = match hash {
            Some(h) => h,
            None => return Ok(()), // Empty holders, nothing to merge
        };

        let mut holders = self.chunk_holders.write();
        let existing = holders.entry(hash).or_insert_with(ChunkHolders::new);

        // CRDT merge
        existing.merge(incoming);

        debug!(
            ciphertext_hash = %hash,
            holder_count = existing.len(),
            "Merged chunk holders"
        );
        Ok(())
    }

    fn validate_timestamp(&self, record: &DhtRecord) -> Result<(), DhtError> {
        let timestamp = match &record.body {
            DhtRecordBody::Node(node) => Some(node.timestamp),
            DhtRecordBody::Manifest(manifest) => Some(manifest.manifest.body.modified_at),
            DhtRecordBody::ChunkHolders(_) => None, // Chunk holders use lease expiration
        };

        if let Some(ts) = timestamp {
            if !ts.is_valid() {
                warn!(timestamp = ts.0, "Record timestamp outside clock skew");
                return Err(DhtError::ClockSkew);
            }
        }

        Ok(())
    }
}

/// Statistics about record storage.
#[derive(Debug, Clone, Default)]
pub struct RecordStoreStats {
    /// Number of stored node announcements
    pub node_count: usize,
    /// Number of stored manifest announcements
    pub manifest_count: usize,
    /// Number of stored chunk holder records
    pub chunk_holder_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lux_core::SigningKey;
    use lux_proto::manifest::{IdentityBinding, ManifestBody};
    use lux_proto::Manifest;
    use lux_core::{DagRef, RevisionId};

    fn create_node_record(network_key: &NetworkKey) -> (DhtRecord, SigningKey) {
        let signing_key = SigningKey::random();
        let node_id = NodeId::from_public_key(&signing_key.public_key());
        let node = NodeAnnouncement::new(
            node_id,
            vec!["127.0.0.1:8080".to_string()],
            0,
            &signing_key,
        ).unwrap();
        (DhtRecord::new(DhtRecordBody::Node(node), network_key), signing_key)
    }

    fn create_node_record_with_key(network_key: &NetworkKey, signing_key: &SigningKey) -> DhtRecord {
        let node_id = NodeId::from_public_key(&signing_key.public_key());
        let node = NodeAnnouncement::new(
            node_id,
            vec!["127.0.0.1:8080".to_string()],
            0,
            signing_key,
        ).unwrap();
        DhtRecord::new(DhtRecordBody::Node(node), network_key)
    }

    fn create_manifest_record(network_key: &NetworkKey) -> DhtRecord {
        let signing_key = SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);
        let object_id = ObjectId::random();

        let body = ManifestBody::new(object_id, RevisionId::initial(), DagRef::empty(), origin);
        let manifest = Manifest::new(body, &signing_key).unwrap();
        let announcement = ManifestAnnouncement { object_id, manifest };

        DhtRecord::new(DhtRecordBody::Manifest(announcement), network_key)
    }

    #[test]
    fn test_store_node() {
        let network_key = NetworkKey::random();
        let store = RecordStore::new(network_key.clone(), RecordStoreConfig::default());

        let (record, _) = create_node_record(&network_key);
        store.store(record).unwrap();

        assert_eq!(store.stats().node_count, 1);
    }

    #[test]
    fn test_store_manifest() {
        let network_key = NetworkKey::random();
        let store = RecordStore::new(network_key.clone(), RecordStoreConfig::default());

        let record = create_manifest_record(&network_key);
        store.store(record).unwrap();

        assert_eq!(store.stats().manifest_count, 1);
    }

    #[test]
    fn test_invalid_mac() {
        let network_key1 = NetworkKey::random();
        let network_key2 = NetworkKey::random();
        let store = RecordStore::new(network_key1, RecordStoreConfig::default());

        // Create record with different network key
        let (record, _) = create_node_record(&network_key2);
        let result = store.store(record);

        assert!(matches!(result, Err(DhtError::InvalidMac)));
    }

    #[test]
    fn test_clock_skew_rejection() {
        let network_key = NetworkKey::random();
        let store = RecordStore::new(network_key.clone(), RecordStoreConfig::default());

        // Create a node announcement with a timestamp far in the future
        let signing_key = SigningKey::random();
        let node_id = NodeId::from_public_key(&signing_key.public_key());
        let far_future = Timestamp::new(Timestamp::now().0 + lux_core::MAX_CLOCK_SKEW_MS + 10000);

        // Create announcement body with future timestamp for signing
        let body = lux_proto::dht::NodeAnnouncementBody {
            node_id,
            timestamp: far_future,
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
        };
        let signature = signing_key.sign(&body.to_vec()).unwrap();

        let node = NodeAnnouncement {
            node_id,
            timestamp: far_future,
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
            signature,
        };
        let record = DhtRecord::new(DhtRecordBody::Node(node), &network_key);

        // Should be rejected due to clock skew
        let result = store.store(record);
        assert!(matches!(result, Err(DhtError::ClockSkew)));
    }

    #[test]
    fn test_clock_skew_past_rejection() {
        let network_key = NetworkKey::random();
        let store = RecordStore::new(network_key.clone(), RecordStoreConfig::default());

        // Create a node announcement with a timestamp far in the past
        let signing_key = SigningKey::random();
        let node_id = NodeId::from_public_key(&signing_key.public_key());
        let far_past = Timestamp::new(Timestamp::now().0 - lux_core::MAX_CLOCK_SKEW_MS - 10000);

        // Create announcement body with past timestamp for signing
        let body = lux_proto::dht::NodeAnnouncementBody {
            node_id,
            timestamp: far_past,
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
        };
        let signature = signing_key.sign(&body.to_vec()).unwrap();

        let node = NodeAnnouncement {
            node_id,
            timestamp: far_past,
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
            signature,
        };
        let record = DhtRecord::new(DhtRecordBody::Node(node), &network_key);

        // Should be rejected due to clock skew
        let result = store.store(record);
        assert!(matches!(result, Err(DhtError::ClockSkew)));
    }

    #[test]
    fn test_node_supersede() {
        let network_key = NetworkKey::random();
        let store = RecordStore::new(network_key.clone(), RecordStoreConfig::default());

        let signing_key = SigningKey::random();
        let node_id = NodeId::from_public_key(&signing_key.public_key());
        let now = Timestamp::now();

        // Store first announcement (1 second ago)
        let body1 = lux_proto::dht::NodeAnnouncementBody {
            node_id,
            timestamp: Timestamp::new(now.0 - 1000),
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
        };
        let signature1 = signing_key.sign(&body1.to_vec()).unwrap();
        let node1 = NodeAnnouncement {
            node_id,
            timestamp: Timestamp::new(now.0 - 1000),
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
            signature: signature1,
        };
        let record1 = DhtRecord::new(DhtRecordBody::Node(node1), &network_key);
        store.store(record1).unwrap();

        // Store newer announcement (now)
        let body2 = lux_proto::dht::NodeAnnouncementBody {
            node_id,
            timestamp: now,
            addresses: vec!["127.0.0.1:9090".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
        };
        let signature2 = signing_key.sign(&body2.to_vec()).unwrap();
        let node2 = NodeAnnouncement {
            node_id,
            timestamp: now,
            addresses: vec!["127.0.0.1:9090".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
            signature: signature2,
        };
        let record2 = DhtRecord::new(DhtRecordBody::Node(node2), &network_key);
        store.store(record2).unwrap();

        // Should have updated
        let stored = store.get_node(&node_id).unwrap();
        assert_eq!(stored.addresses[0], "127.0.0.1:9090");
    }

    #[test]
    fn test_invalid_node_signature() {
        let network_key = NetworkKey::random();
        let store = RecordStore::new(network_key.clone(), RecordStoreConfig::default());

        let signing_key = SigningKey::random();
        let wrong_key = SigningKey::random();
        let node_id = NodeId::from_public_key(&signing_key.public_key());

        // Create announcement signed with wrong key
        let body = lux_proto::dht::NodeAnnouncementBody {
            node_id,
            timestamp: Timestamp::now(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
        };
        let wrong_signature = wrong_key.sign(&body.to_vec()).unwrap();

        let node = NodeAnnouncement {
            node_id,
            timestamp: Timestamp::now(),
            addresses: vec!["127.0.0.1:8080".to_string()],
            services: 0,
            public_key: signing_key.public_key(),
            signature: wrong_signature,
        };
        let record = DhtRecord::new(DhtRecordBody::Node(node), &network_key);

        // Should be rejected due to invalid signature
        let result = store.store(record);
        assert!(matches!(result, Err(DhtError::InvalidSignature)));
    }
}
