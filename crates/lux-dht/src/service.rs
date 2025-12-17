//! DHT service actor.
//!
//! Provides the main DHT interface for node discovery, record storage,
//! and lookups.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use lux_core::{CiphertextHash, NetworkKey, NodeId, ObjectId};
use lux_proto::dht::{ChunkHolders, DhtRecord, ManifestAnnouncement, NodeAnnouncement};
use lux_proto::messages::{Message, MessagePayload, NodeInfo};
use tokio::sync::mpsc;
use tracing::debug;

use crate::record::{RecordStore, RecordStoreConfig};
use crate::routing::{NodeEntry, RoutingTable, RoutingTableConfig};
use crate::{DEFAULT_ALPHA, DEFAULT_COMMAND_CHANNEL_SIZE, DEFAULT_K, DEFAULT_REFRESH_INTERVAL_SECS};

/// DHT service configuration.
#[derive(Debug, Clone)]
pub struct DhtConfig {
    /// Local node ID
    pub local_id: NodeId,
    /// Network key for authentication
    pub network_key: NetworkKey,
    /// Routing table configuration
    pub routing: RoutingTableConfig,
    /// Record store configuration
    pub records: RecordStoreConfig,
    /// Lookup parallelism (alpha)
    pub alpha: usize,
    /// Bucket size (k)
    pub k: usize,
    /// Refresh interval for routing table
    pub refresh_interval: Duration,
}

impl DhtConfig {
    /// Creates a new configuration with defaults.
    pub fn new(local_id: NodeId, network_key: NetworkKey) -> Self {
        Self {
            local_id,
            network_key,
            routing: RoutingTableConfig::default(),
            records: RecordStoreConfig::default(),
            alpha: DEFAULT_ALPHA,
            k: DEFAULT_K,
            refresh_interval: Duration::from_secs(DEFAULT_REFRESH_INTERVAL_SECS),
        }
    }
}

/// Commands for the DHT service.
#[derive(Debug)]
pub enum DhtCommand {
    /// Bootstrap from a known node
    Bootstrap(NodeInfo),
    /// Find nodes close to a target
    FindNode(NodeId, mpsc::Sender<Vec<NodeInfo>>),
    /// Store a record
    Store(DhtRecord),
    /// Find a value by key
    FindValue([u8; 32], mpsc::Sender<Option<DhtRecord>>),
    /// Announce node presence
    Announce(NodeAnnouncement),
    /// Shutdown
    Shutdown,
}

/// DHT service providing the main interface.
pub struct DhtService {
    /// Configuration
    config: DhtConfig,
    /// Routing table
    routing_table: Arc<RoutingTable>,
    /// Record storage
    record_store: Arc<RecordStore>,
    /// Command sender
    command_tx: mpsc::Sender<DhtCommand>,
}

impl DhtService {
    /// Creates a new DHT service.
    pub fn new(config: DhtConfig) -> (Self, mpsc::Receiver<DhtCommand>) {
        let routing_table = Arc::new(RoutingTable::new(config.local_id, config.routing.clone()));
        let record_store = Arc::new(RecordStore::new(
            config.network_key.clone(),
            config.records.clone(),
        ));

        let (command_tx, command_rx) = mpsc::channel(DEFAULT_COMMAND_CHANNEL_SIZE);

        let service = Self {
            config,
            routing_table,
            record_store,
            command_tx,
        };

        (service, command_rx)
    }

    /// Returns the local node ID.
    pub fn local_id(&self) -> &NodeId {
        &self.config.local_id
    }

    /// Returns the routing table.
    pub fn routing_table(&self) -> &RoutingTable {
        &self.routing_table
    }

    /// Returns the record store.
    pub fn record_store(&self) -> &RecordStore {
        &self.record_store
    }

    /// Adds a node to the routing table.
    pub fn add_node(&self, entry: NodeEntry) -> bool {
        self.routing_table.insert(entry)
    }

    /// Updates a node's last seen time.
    pub fn touch_node(&self, node_id: &NodeId) {
        self.routing_table.touch(node_id);
    }

    /// Records a failure for a node.
    pub fn record_failure(&self, node_id: &NodeId) {
        self.routing_table.record_failure(node_id);
    }

    /// Finds the k closest nodes to a target.
    pub fn closest_nodes(&self, target: &NodeId) -> Vec<NodeEntry> {
        self.routing_table.closest(target, self.config.k)
    }

    /// Stores a record.
    pub fn store_record(&self, record: DhtRecord) -> Result<(), lux_proto::dht::DhtError> {
        self.record_store.store(record)
    }

    /// Gets a node announcement.
    pub fn get_node(&self, node_id: &NodeId) -> Option<NodeAnnouncement> {
        self.record_store.get_node(node_id)
    }

    /// Gets a manifest announcement.
    pub fn get_manifest(&self, object_id: &ObjectId) -> Option<ManifestAnnouncement> {
        self.record_store.get_manifest(object_id)
    }

    /// Gets chunk holders.
    pub fn get_chunk_holders(&self, hash: &CiphertextHash) -> Option<ChunkHolders> {
        self.record_store.get_chunk_holders(hash)
    }

    /// Sends a command to the service.
    pub async fn send_command(&self, cmd: DhtCommand) -> Result<(), mpsc::error::SendError<DhtCommand>> {
        self.command_tx.send(cmd).await
    }

    /// Handles an incoming message.
    pub fn handle_message(&self, msg: Message) -> Option<Message> {
        // Update routing table with sender
        if msg.sender != self.config.local_id {
            // We don't have full node info from the message, just touch if exists
            self.touch_node(&msg.sender);
        }

        let response_payload = match msg.payload {
            MessagePayload::Ping => Some(MessagePayload::Pong),

            MessagePayload::FindNode { target } => {
                let nodes: Vec<NodeInfo> = self
                    .closest_nodes(&target)
                    .into_iter()
                    .map(|e| NodeInfo {
                        node_id: e.node_id,
                        addresses: e.addresses,
                        public_key: e.public_key,
                    })
                    .collect();
                Some(MessagePayload::FindNodeResponse { nodes })
            }

            MessagePayload::StoreRecord { record } => {
                let success = self.store_record(record).is_ok();
                Some(MessagePayload::StoreRecordResponse { success })
            }

            MessagePayload::FindValue { key } => {
                // Try to find in record store based on key type
                // For simplicity, try all record types
                let node_id = NodeId::new(key);
                let object_id = ObjectId::new(key);
                let ciphertext_hash = CiphertextHash::new(key);

                let result = if let Some(node) = self.get_node(&node_id) {
                    use lux_proto::dht::{DhtRecordBody, DhtRecord};
                    Some(DhtRecord::new(
                        DhtRecordBody::Node(node),
                        &self.config.network_key,
                    ))
                } else if let Some(manifest) = self.get_manifest(&object_id) {
                    use lux_proto::dht::{DhtRecordBody, DhtRecord};
                    Some(DhtRecord::new(
                        DhtRecordBody::Manifest(manifest),
                        &self.config.network_key,
                    ))
                } else if let Some(holders) = self.get_chunk_holders(&ciphertext_hash) {
                    use lux_proto::dht::{DhtRecordBody, DhtRecord};
                    Some(DhtRecord::new(
                        DhtRecordBody::ChunkHolders(holders),
                        &self.config.network_key,
                    ))
                } else {
                    None
                };

                let result = match result {
                    Some(record) => lux_proto::messages::FindValueResult::Found(record),
                    None => {
                        // Return closest nodes
                        let target = NodeId::new(key);
                        let nodes: Vec<NodeInfo> = self
                            .closest_nodes(&target)
                            .into_iter()
                            .map(|e| NodeInfo {
                                node_id: e.node_id,
                                addresses: e.addresses,
                                public_key: e.public_key,
                            })
                            .collect();
                        lux_proto::messages::FindValueResult::Nodes(nodes)
                    }
                };

                Some(MessagePayload::FindValueResponse { result })
            }

            MessagePayload::GetManifest {
                object_id,
                revision: _,
            } => {
                let manifest = self.get_manifest(&object_id);
                Some(MessagePayload::GetManifestResponse { manifest })
            }

            MessagePayload::PublishManifest { announcement } => {
                use lux_proto::dht::{DhtRecordBody, DhtRecord};
                let record = DhtRecord::new(
                    DhtRecordBody::Manifest(announcement),
                    &self.config.network_key,
                );
                let success = self.store_record(record).is_ok();
                Some(MessagePayload::PublishManifestResponse { success })
            }

            // Response messages don't need responses
            MessagePayload::Pong
            | MessagePayload::FindNodeResponse { .. }
            | MessagePayload::StoreRecordResponse { .. }
            | MessagePayload::FindValueResponse { .. }
            | MessagePayload::GetChunkResponse { .. }
            | MessagePayload::StoreChunkResponse { .. }
            | MessagePayload::GetManifestResponse { .. }
            | MessagePayload::PublishManifestResponse { .. }
            | MessagePayload::Error { .. } => None,

            // Chunk operations are handled by the storage layer
            MessagePayload::GetChunk { .. } | MessagePayload::StoreChunk { .. } => {
                Some(MessagePayload::Error {
                    code: lux_proto::messages::ErrorCode::InvalidRequest,
                    message: "Chunk operations not handled by DHT".to_string(),
                })
            }
        };

        response_payload.map(|payload| Message::new(msg.request_id, self.config.local_id, payload))
    }

    /// Runs periodic maintenance tasks.
    pub fn maintenance(&self) {
        // Evict stale nodes
        let evicted = self.routing_table.evict_stale();
        if !evicted.is_empty() {
            debug!(count = evicted.len(), "Evicted stale nodes");
        }

        // Expire old records
        self.record_store.expire();
    }
}

/// Iterative node lookup.
pub struct NodeLookup {
    /// Target node ID
    target: NodeId,
    /// Known closest nodes
    closest: Vec<NodeEntry>,
    /// Queried node IDs
    queried: HashSet<NodeId>,
    /// k value
    k: usize,
    /// alpha value
    alpha: usize,
}

impl NodeLookup {
    /// Creates a new lookup.
    pub fn new(target: NodeId, initial: Vec<NodeEntry>, k: usize, alpha: usize) -> Self {
        let mut closest = initial;
        closest.sort_by(|a, b| {
            let dist_a = target.xor_distance(&a.node_id);
            let dist_b = target.xor_distance(&b.node_id);
            dist_a.cmp(&dist_b)
        });
        closest.truncate(k);

        Self {
            target,
            closest,
            queried: HashSet::new(),
            k,
            alpha,
        }
    }

    /// Returns the next batch of nodes to query.
    pub fn next_batch(&mut self) -> Vec<NodeEntry> {
        let mut batch = Vec::new();

        for entry in &self.closest {
            if !self.queried.contains(&entry.node_id) {
                batch.push(entry.clone());
                if batch.len() >= self.alpha {
                    break;
                }
            }
        }

        for entry in &batch {
            self.queried.insert(entry.node_id);
        }

        batch
    }

    /// Updates with newly discovered nodes.
    pub fn update(&mut self, nodes: Vec<NodeEntry>) {
        for node in nodes {
            if !self.closest.iter().any(|n| n.node_id == node.node_id) {
                self.closest.push(node);
            }
        }

        // Re-sort by distance
        self.closest.sort_by(|a, b| {
            let dist_a = self.target.xor_distance(&a.node_id);
            let dist_b = self.target.xor_distance(&b.node_id);
            dist_a.cmp(&dist_b)
        });
        self.closest.truncate(self.k);
    }

    /// Returns true if the lookup is complete.
    pub fn is_complete(&self) -> bool {
        // Complete when all k closest have been queried
        self.closest
            .iter()
            .take(self.k)
            .all(|n| self.queried.contains(&n.node_id))
    }

    /// Returns the result of the lookup.
    pub fn result(self) -> Vec<NodeEntry> {
        self.closest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dht_service_creation() {
        let local_id = NodeId::random();
        let network_key = NetworkKey::random();
        let config = DhtConfig::new(local_id, network_key);

        let (service, _rx) = DhtService::new(config);
        assert_eq!(*service.local_id(), local_id);
    }

    #[test]
    fn test_handle_ping() {
        let local_id = NodeId::random();
        let network_key = NetworkKey::random();
        let config = DhtConfig::new(local_id, network_key);

        let (service, _rx) = DhtService::new(config);

        let msg = Message::new(1, NodeId::random(), MessagePayload::Ping);
        let response = service.handle_message(msg);

        assert!(response.is_some());
        assert!(matches!(response.unwrap().payload, MessagePayload::Pong));
    }

    #[test]
    fn test_node_lookup() {
        let target = NodeId::random();
        let initial: Vec<NodeEntry> = (0..5)
            .map(|_| NodeEntry::new(NodeId::random(), vec![], [0u8; 32]))
            .collect();

        let mut lookup = NodeLookup::new(target, initial, 5, 3);

        // Should get alpha nodes to query
        let batch = lookup.next_batch();
        assert_eq!(batch.len(), 3);

        // Simulate response with new nodes
        let new_nodes: Vec<NodeEntry> = (0..3)
            .map(|_| NodeEntry::new(NodeId::random(), vec![], [0u8; 32]))
            .collect();
        lookup.update(new_nodes);

        // Should eventually complete
        while !lookup.is_complete() {
            let batch = lookup.next_batch();
            if batch.is_empty() {
                break;
            }
        }
    }
}
