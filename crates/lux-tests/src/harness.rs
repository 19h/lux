//! Test network harness for multi-node integration testing.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use lux_core::{NetworkKey, NodeId};
use tokio::time::sleep;
use tracing::info;

use crate::node::{TestNode, TestNodeConfig};

/// A test network containing multiple nodes.
pub struct TestNetwork {
    /// Network key shared by all nodes
    pub network_key: NetworkKey,
    /// Nodes in the network
    nodes: Vec<Arc<TestNode>>,
    /// Node lookup by ID
    node_map: HashMap<NodeId, Arc<TestNode>>,
}

impl TestNetwork {
    /// Creates a new empty test network.
    pub fn new() -> Self {
        Self {
            network_key: NetworkKey::random(),
            nodes: Vec::new(),
            node_map: HashMap::new(),
        }
    }

    /// Creates a test network with the specified number of nodes.
    pub async fn with_nodes(count: usize) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut network = Self::new();

        for _ in 0..count {
            network.add_node().await?;
        }

        Ok(network)
    }

    /// Adds a new node to the network.
    pub async fn add_node(&mut self) -> Result<Arc<TestNode>, Box<dyn std::error::Error + Send + Sync>> {
        let config = TestNodeConfig {
            network_key: self.network_key.clone(),
            ..Default::default()
        };

        let node = Arc::new(TestNode::new(config).await?);
        node.start().await?;

        let node_id = node.node_id;
        self.nodes.push(node.clone());
        self.node_map.insert(node_id, node.clone());

        info!(node_id = %node_id, total = self.nodes.len(), "Added node to test network");
        Ok(node)
    }

    /// Returns the number of nodes in the network.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns all nodes in the network.
    pub fn nodes(&self) -> &[Arc<TestNode>] {
        &self.nodes
    }

    /// Returns a node by index.
    pub fn node(&self, index: usize) -> Option<&Arc<TestNode>> {
        self.nodes.get(index)
    }

    /// Returns a node by ID.
    pub fn node_by_id(&self, id: &NodeId) -> Option<&Arc<TestNode>> {
        self.node_map.get(id)
    }

    /// Connects all nodes in a mesh topology.
    pub async fn connect_mesh(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for i in 0..self.nodes.len() {
            for j in (i + 1)..self.nodes.len() {
                self.nodes[i].connect_to(&self.nodes[j]).await?;
            }
        }

        // Give connections time to establish
        sleep(Duration::from_millis(100)).await;

        info!(nodes = self.nodes.len(), "Connected nodes in mesh topology");
        Ok(())
    }

    /// Connects nodes in a ring topology.
    pub async fn connect_ring(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.nodes.len() < 2 {
            return Ok(());
        }

        for i in 0..self.nodes.len() {
            let next = (i + 1) % self.nodes.len();
            self.nodes[i].connect_to(&self.nodes[next]).await?;
        }

        sleep(Duration::from_millis(100)).await;

        info!(nodes = self.nodes.len(), "Connected nodes in ring topology");
        Ok(())
    }

    /// Connects nodes in a star topology (first node is hub).
    pub async fn connect_star(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.nodes.len() < 2 {
            return Ok(());
        }

        let hub = &self.nodes[0];
        for spoke in &self.nodes[1..] {
            spoke.connect_to(hub).await?;
        }

        sleep(Duration::from_millis(100)).await;

        info!(nodes = self.nodes.len(), "Connected nodes in star topology");
        Ok(())
    }

    /// Waits for all nodes to have at least the specified number of connections.
    pub async fn wait_for_connections(&self, min_connections: usize, timeout: Duration) -> Result<(), &'static str> {
        let start = std::time::Instant::now();

        while start.elapsed() < timeout {
            let all_connected = self.nodes.iter()
                .all(|n| n.connection_count() >= min_connections);

            if all_connected {
                return Ok(());
            }

            sleep(Duration::from_millis(50)).await;
        }

        Err("Timeout waiting for connections")
    }

    /// Returns total connection count across all nodes.
    pub fn total_connections(&self) -> usize {
        self.nodes.iter()
            .map(|n| n.connection_count())
            .sum()
    }

    /// Prints network statistics.
    pub fn print_stats(&self) {
        println!("\n=== Test Network Stats ===");
        println!("Nodes: {}", self.nodes.len());
        println!("Network Key: {}", hex::encode(self.network_key.as_bytes()));

        for (i, node) in self.nodes.iter().enumerate() {
            println!(
                "  Node {}: {} (connections: {})",
                i,
                node.node_id,
                node.connection_count()
            );
        }
        println!("Total connections: {}", self.total_connections());
        println!("==========================\n");
    }
}

impl Default for TestNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_creation() {
        let network = TestNetwork::new();
        assert_eq!(network.node_count(), 0);
    }

    #[tokio::test]
    async fn test_network_with_nodes() {
        let network = TestNetwork::with_nodes(3).await.unwrap();
        assert_eq!(network.node_count(), 3);
    }

    #[tokio::test]
    async fn test_network_mesh_connection() {
        let network = TestNetwork::with_nodes(3).await.unwrap();
        network.connect_mesh().await.unwrap();

        // In a mesh of 3 nodes, each node should have 2 connections
        // Total connections = 3 * 2 = 6 (counted from each side)
        assert!(network.total_connections() >= 3);
    }

    #[tokio::test]
    async fn test_network_ring_connection() {
        let network = TestNetwork::with_nodes(4).await.unwrap();
        network.connect_ring().await.unwrap();

        // In a ring of 4 nodes, each node connects to the next
        // Total connections = 4
        assert!(network.total_connections() >= 4);
    }
}
