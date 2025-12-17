//! Kademlia routing table implementation.
//!
//! The routing table organizes known nodes by XOR distance from the local node,
//! enabling efficient lookups in O(log n) hops.

use std::collections::VecDeque;
use std::time::Instant;

use lux_core::NodeId;
use parking_lot::RwLock;

use crate::{DEFAULT_ALPHA, DEFAULT_K, DEFAULT_STALE_TIMEOUT_SECS};

/// Configuration for the routing table.
#[derive(Debug, Clone)]
pub struct RoutingTableConfig {
    /// Bucket size (k)
    pub bucket_size: usize,
    /// Query parallelism (alpha)
    pub alpha: usize,
    /// Time before a node is considered stale
    pub stale_timeout_secs: u64,
}

impl Default for RoutingTableConfig {
    fn default() -> Self {
        Self {
            bucket_size: DEFAULT_K,
            alpha: DEFAULT_ALPHA,
            stale_timeout_secs: DEFAULT_STALE_TIMEOUT_SECS,
        }
    }
}

/// Information about a node in the routing table.
#[derive(Debug, Clone)]
pub struct NodeEntry {
    /// Node identifier
    pub node_id: NodeId,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Public key for connection
    pub public_key: [u8; 32],
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Number of failed queries
    pub failures: u32,
}

impl NodeEntry {
    /// Creates a new node entry.
    pub fn new(node_id: NodeId, addresses: Vec<String>, public_key: [u8; 32]) -> Self {
        Self {
            node_id,
            addresses,
            public_key,
            last_seen: Instant::now(),
            failures: 0,
        }
    }

    /// Updates the last seen time.
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
        self.failures = 0;
    }

    /// Records a failure.
    pub fn record_failure(&mut self) {
        self.failures += 1;
    }

    /// Returns true if the node is considered stale.
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        self.last_seen.elapsed().as_secs() > timeout_secs
    }
}

/// A k-bucket holding up to k nodes at a specific distance range.
#[derive(Debug)]
pub struct KBucket {
    /// Nodes in this bucket (ordered by last seen, most recent last)
    nodes: VecDeque<NodeEntry>,
    /// Replacement cache for when bucket is full
    replacement_cache: VecDeque<NodeEntry>,
    /// Maximum bucket size
    bucket_size: usize,
    /// Maximum replacement cache size
    cache_size: usize,
}

impl KBucket {
    /// Creates a new k-bucket.
    pub fn new(bucket_size: usize) -> Self {
        Self {
            nodes: VecDeque::with_capacity(bucket_size),
            replacement_cache: VecDeque::with_capacity(bucket_size),
            bucket_size,
            cache_size: bucket_size,
        }
    }

    /// Returns the number of nodes in this bucket.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns true if this bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns true if this bucket is full.
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.bucket_size
    }

    /// Returns all nodes in this bucket.
    pub fn nodes(&self) -> impl Iterator<Item = &NodeEntry> {
        self.nodes.iter()
    }

    /// Gets a node by ID.
    pub fn get(&self, node_id: &NodeId) -> Option<&NodeEntry> {
        self.nodes.iter().find(|n| n.node_id == *node_id)
    }

    /// Gets a mutable reference to a node by ID.
    pub fn get_mut(&mut self, node_id: &NodeId) -> Option<&mut NodeEntry> {
        self.nodes.iter_mut().find(|n| n.node_id == *node_id)
    }

    /// Adds or updates a node in this bucket.
    ///
    /// Returns true if the node was added or updated.
    pub fn insert(&mut self, entry: NodeEntry) -> bool {
        // If node exists, move to end (most recently seen)
        if let Some(pos) = self.nodes.iter().position(|n| n.node_id == entry.node_id) {
            let mut existing = self.nodes.remove(pos).unwrap();
            existing.touch();
            existing.addresses = entry.addresses;
            self.nodes.push_back(existing);
            return true;
        }

        // If bucket is not full, add node
        if !self.is_full() {
            self.nodes.push_back(entry);
            return true;
        }

        // Bucket is full - add to replacement cache
        if let Some(pos) = self
            .replacement_cache
            .iter()
            .position(|n| n.node_id == entry.node_id)
        {
            self.replacement_cache.remove(pos);
        }
        if self.replacement_cache.len() >= self.cache_size {
            self.replacement_cache.pop_front();
        }
        self.replacement_cache.push_back(entry);
        false
    }

    /// Removes a node from this bucket.
    ///
    /// If there are nodes in the replacement cache, one will be promoted.
    pub fn remove(&mut self, node_id: &NodeId) -> Option<NodeEntry> {
        if let Some(pos) = self.nodes.iter().position(|n| n.node_id == *node_id) {
            let removed = self.nodes.remove(pos).unwrap();

            // Promote from replacement cache if available
            if let Some(replacement) = self.replacement_cache.pop_front() {
                self.nodes.push_back(replacement);
            }

            return Some(removed);
        }
        None
    }

    /// Returns the stalest node (candidate for eviction check).
    pub fn stalest(&self) -> Option<&NodeEntry> {
        self.nodes.front()
    }

    /// Removes stale nodes and promotes from replacement cache.
    pub fn evict_stale(&mut self, timeout_secs: u64) -> Vec<NodeEntry> {
        let mut evicted = Vec::new();

        self.nodes.retain(|n| {
            if n.is_stale(timeout_secs) {
                evicted.push(n.clone());
                false
            } else {
                true
            }
        });

        // Promote from replacement cache
        while self.nodes.len() < self.bucket_size {
            if let Some(replacement) = self.replacement_cache.pop_front() {
                if !replacement.is_stale(timeout_secs) {
                    self.nodes.push_back(replacement);
                }
            } else {
                break;
            }
        }

        evicted
    }
}

/// Kademlia routing table.
pub struct RoutingTable {
    /// Local node ID
    local_id: NodeId,
    /// K-buckets (index = common prefix length)
    buckets: Vec<RwLock<KBucket>>,
    /// Configuration
    config: RoutingTableConfig,
}

impl RoutingTable {
    /// Creates a new routing table.
    pub fn new(local_id: NodeId, config: RoutingTableConfig) -> Self {
        // 256 buckets for 256-bit node IDs
        let buckets = (0..256)
            .map(|_| RwLock::new(KBucket::new(config.bucket_size)))
            .collect();

        Self {
            local_id,
            buckets,
            config,
        }
    }

    /// Returns the local node ID.
    pub fn local_id(&self) -> &NodeId {
        &self.local_id
    }

    /// Computes the bucket index for a node ID.
    ///
    /// This is 255 - leading_zeros(distance) for non-self IDs.
    pub fn bucket_index(&self, node_id: &NodeId) -> Option<usize> {
        if *node_id == self.local_id {
            return None;
        }

        let distance = self.local_id.xor_distance(node_id);
        let leading_zeros = {
            let mut zeros = 0u32;
            for byte in &distance {
                if *byte == 0 {
                    zeros += 8;
                } else {
                    zeros += byte.leading_zeros();
                    break;
                }
            }
            zeros
        };

        Some(255 - leading_zeros as usize)
    }

    /// Adds or updates a node in the routing table.
    pub fn insert(&self, entry: NodeEntry) -> bool {
        if let Some(index) = self.bucket_index(&entry.node_id) {
            self.buckets[index].write().insert(entry)
        } else {
            false // Can't add self
        }
    }

    /// Removes a node from the routing table.
    pub fn remove(&self, node_id: &NodeId) -> Option<NodeEntry> {
        if let Some(index) = self.bucket_index(node_id) {
            self.buckets[index].write().remove(node_id)
        } else {
            None
        }
    }

    /// Gets a node by ID.
    pub fn get(&self, node_id: &NodeId) -> Option<NodeEntry> {
        if let Some(index) = self.bucket_index(node_id) {
            self.buckets[index].read().get(node_id).cloned()
        } else {
            None
        }
    }

    /// Updates a node's last seen time.
    pub fn touch(&self, node_id: &NodeId) {
        if let Some(index) = self.bucket_index(node_id) {
            if let Some(entry) = self.buckets[index].write().get_mut(node_id) {
                entry.touch();
            }
        }
    }

    /// Records a failure for a node.
    pub fn record_failure(&self, node_id: &NodeId) {
        if let Some(index) = self.bucket_index(node_id) {
            if let Some(entry) = self.buckets[index].write().get_mut(node_id) {
                entry.record_failure();
            }
        }
    }

    /// Finds the k closest nodes to a target.
    pub fn closest(&self, target: &NodeId, k: usize) -> Vec<NodeEntry> {
        let mut nodes: Vec<NodeEntry> = Vec::new();

        // Collect all nodes
        for bucket in &self.buckets {
            for entry in bucket.read().nodes() {
                nodes.push(entry.clone());
            }
        }

        // Sort by distance to target
        nodes.sort_by(|a, b| {
            let dist_a = target.xor_distance(&a.node_id);
            let dist_b = target.xor_distance(&b.node_id);
            dist_a.cmp(&dist_b)
        });

        nodes.truncate(k);
        nodes
    }

    /// Returns the total number of nodes in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.read().len()).sum()
    }

    /// Returns true if the routing table is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns all nodes in the routing table.
    pub fn all_nodes(&self) -> Vec<NodeEntry> {
        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            for entry in bucket.read().nodes() {
                nodes.push(entry.clone());
            }
        }
        nodes
    }

    /// Evicts stale nodes from all buckets.
    pub fn evict_stale(&self) -> Vec<NodeEntry> {
        let mut evicted = Vec::new();
        for bucket in &self.buckets {
            evicted.extend(bucket.write().evict_stale(self.config.stale_timeout_secs));
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_node_id() -> NodeId {
        NodeId::random()
    }

    fn create_entry(node_id: NodeId) -> NodeEntry {
        NodeEntry::new(node_id, vec!["127.0.0.1:8080".to_string()], [0u8; 32])
    }

    #[test]
    fn test_kbucket_insert() {
        let mut bucket = KBucket::new(3);

        for i in 0..3 {
            let mut id = [0u8; 32];
            id[0] = i;
            let entry = create_entry(NodeId::new(id));
            assert!(bucket.insert(entry));
        }

        assert_eq!(bucket.len(), 3);
        assert!(bucket.is_full());

        // Fourth insertion should go to replacement cache
        let mut id = [0u8; 32];
        id[0] = 100;
        let entry = create_entry(NodeId::new(id));
        assert!(!bucket.insert(entry));
    }

    #[test]
    fn test_kbucket_update() {
        let mut bucket = KBucket::new(3);

        let id = NodeId::new([0x42; 32]);
        let entry = create_entry(id);
        bucket.insert(entry);

        // Re-insert should update and move to end
        let entry2 = create_entry(id);
        bucket.insert(entry2);

        assert_eq!(bucket.len(), 1);
    }

    #[test]
    fn test_routing_table_insert() {
        let local_id = random_node_id();
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        for _ in 0..100 {
            let entry = create_entry(random_node_id());
            table.insert(entry);
        }

        assert!(table.len() > 0);
    }

    #[test]
    fn test_routing_table_closest() {
        let local_id = random_node_id();
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        // Insert nodes
        for _ in 0..50 {
            let entry = create_entry(random_node_id());
            table.insert(entry);
        }

        // Find closest to random target
        let target = random_node_id();
        let closest = table.closest(&target, 10);

        assert!(closest.len() <= 10);

        // Verify sorted by distance
        for i in 1..closest.len() {
            let dist_prev = target.xor_distance(&closest[i - 1].node_id);
            let dist_curr = target.xor_distance(&closest[i].node_id);
            assert!(dist_prev <= dist_curr);
        }
    }

    #[test]
    fn test_bucket_index() {
        let local_id = NodeId::new([0x00; 32]);
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        // Node with all 1s should be in bucket 255
        let far = NodeId::new([0xFF; 32]);
        assert_eq!(table.bucket_index(&far), Some(255));

        // Node with single bit difference should be in lower bucket
        let mut near = [0x00; 32];
        near[31] = 0x01;
        let near_id = NodeId::new(near);
        assert_eq!(table.bucket_index(&near_id), Some(0));

        // Self should return None
        assert_eq!(table.bucket_index(&local_id), None);
    }

    #[test]
    fn test_kbucket_replacement_cache() {
        let mut bucket = KBucket::new(2);

        // Fill the bucket
        let id1 = NodeId::new([0x01; 32]);
        let id2 = NodeId::new([0x02; 32]);
        bucket.insert(create_entry(id1));
        bucket.insert(create_entry(id2));
        assert!(bucket.is_full());

        // Next insertions go to replacement cache
        let id3 = NodeId::new([0x03; 32]);
        let result = bucket.insert(create_entry(id3));
        assert!(!result); // Returns false for cache insertion

        assert_eq!(bucket.len(), 2);
    }

    #[test]
    fn test_routing_table_remove() {
        let local_id = random_node_id();
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        let node_id = random_node_id();
        let entry = create_entry(node_id);
        table.insert(entry);

        assert!(table.get(&node_id).is_some());

        let removed = table.remove(&node_id);
        assert!(removed.is_some());
        assert!(table.get(&node_id).is_none());
    }

    #[test]
    fn test_routing_table_touch() {
        let local_id = random_node_id();
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        let node_id = random_node_id();
        let entry = create_entry(node_id);
        table.insert(entry);

        // Touch should update last_seen
        std::thread::sleep(std::time::Duration::from_millis(10));
        table.touch(&node_id);

        let updated = table.get(&node_id).unwrap();
        assert!(updated.last_seen.elapsed().as_millis() < 5);
    }

    #[test]
    fn test_routing_table_record_failure() {
        let local_id = random_node_id();
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        let node_id = random_node_id();
        let entry = create_entry(node_id);
        table.insert(entry);

        assert_eq!(table.get(&node_id).unwrap().failures, 0);

        table.record_failure(&node_id);
        assert_eq!(table.get(&node_id).unwrap().failures, 1);

        table.record_failure(&node_id);
        assert_eq!(table.get(&node_id).unwrap().failures, 2);
    }

    #[test]
    fn test_routing_table_all_nodes() {
        let local_id = random_node_id();
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        let mut inserted = Vec::new();
        for _ in 0..20 {
            let node_id = random_node_id();
            let entry = create_entry(node_id);
            table.insert(entry);
            inserted.push(node_id);
        }

        let all = table.all_nodes();
        assert_eq!(all.len(), 20);

        for node_id in inserted {
            assert!(all.iter().any(|e| e.node_id == node_id));
        }
    }

    #[test]
    fn test_routing_table_closest_k() {
        let local_id = random_node_id();
        let mut config = RoutingTableConfig::default();
        config.bucket_size = 5;
        let table = RoutingTable::new(local_id, config);

        // Insert many nodes
        for _ in 0..100 {
            let entry = create_entry(random_node_id());
            table.insert(entry);
        }

        let target = random_node_id();
        let closest = table.closest(&target, 5);

        // Should return at most k nodes (may be less due to bucket limits)
        assert!(closest.len() <= 20);

        // Should be sorted by distance
        for i in 1..closest.len() {
            let dist_prev = target.xor_distance(&closest[i - 1].node_id);
            let dist_curr = target.xor_distance(&closest[i].node_id);
            assert!(dist_prev <= dist_curr, "Nodes not sorted by distance");
        }
    }

    #[test]
    fn test_bucket_index_distribution() {
        // Verify nodes get distributed across buckets correctly
        let local_id = NodeId::new([0x00; 32]);
        let config = RoutingTableConfig::default();
        let table = RoutingTable::new(local_id, config);

        // Node with high bit set in first byte should be in bucket 255
        let mut id = [0x00; 32];
        id[0] = 0x80;
        assert_eq!(table.bucket_index(&NodeId::new(id)), Some(255));

        // Node with high bit set in second byte should be in bucket 247
        id = [0x00; 32];
        id[1] = 0x80;
        assert_eq!(table.bucket_index(&NodeId::new(id)), Some(247));

        // Node with lowest bit set in last byte should be in bucket 0
        id = [0x00; 32];
        id[31] = 0x01;
        assert_eq!(table.bucket_index(&NodeId::new(id)), Some(0));
    }
}
