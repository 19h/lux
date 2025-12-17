//! Test node implementation for integration testing.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lux_core::{NetworkKey, NodeId, SigningKey};
use lux_net::noise::generate_keypair;
use lux_net::quic::QuicTransport;
use lux_net::transport::{Transport, TransportConfig, TransportError};
use lux_proto::messages::{Message, MessagePayload};
use lux_store::ChunkStore;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info};

/// Configuration for a test node.
#[derive(Debug, Clone)]
pub struct TestNodeConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Network key for DHT authentication
    pub network_key: NetworkKey,
    /// Enable chunk storage
    pub enable_storage: bool,
}

impl Default for TestNodeConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            network_key: NetworkKey::random(),
            enable_storage: true,
        }
    }
}

/// A test node for integration testing.
pub struct TestNode {
    /// Node ID
    pub node_id: NodeId,
    /// Signing key for the node
    pub signing_key: SigningKey,
    /// Static Noise keypair (private, public)
    pub noise_keypair: ([u8; 32], [u8; 32]),
    /// Transport layer
    pub transport: Arc<QuicTransport>,
    /// Chunk store (if enabled)
    pub store: Option<Arc<ChunkStore>>,
    /// Temporary directory for storage
    _temp_dir: TempDir,
    /// Actual bound address after start
    bound_addr: RwLock<Option<SocketAddr>>,
    /// Network key
    pub network_key: NetworkKey,
    /// Request ID counter for message sending
    request_id_counter: AtomicU64,
}

impl TestNode {
    /// Creates a new test node with the given configuration.
    pub async fn new(config: TestNodeConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Create temporary directory for storage
        let temp_dir = TempDir::new()?;

        // Generate node identity
        let signing_key = SigningKey::random();
        let public_key = signing_key.public_key();
        let node_id = NodeId::from_public_key(&public_key);

        // Generate Noise keypair
        let (noise_private, noise_public) = generate_keypair()?;

        // Create transport
        let transport_config = TransportConfig {
            listen_addr: config.listen_addr,
            ..Default::default()
        };

        let transport = Arc::new(QuicTransport::new(
            transport_config,
            node_id,
            noise_private,
            noise_public,
        ));

        // Create chunk store if enabled
        let store = if config.enable_storage {
            Some(Arc::new(ChunkStore::open(temp_dir.path())?))
        } else {
            None
        };

        info!(node_id = %node_id, "Created test node");

        Ok(Self {
            node_id,
            signing_key,
            noise_keypair: (noise_private, noise_public),
            transport,
            store,
            _temp_dir: temp_dir,
            bound_addr: RwLock::new(None),
            network_key: config.network_key,
            request_id_counter: AtomicU64::new(1),
        })
    }

    /// Starts the node.
    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Start transport
        self.transport.start().await?;

        // Store bound address
        let addr = self.transport.local_addr();
        *self.bound_addr.write().await = Some(addr);

        info!(node_id = %self.node_id, addr = %addr, "Test node started");
        Ok(())
    }

    /// Returns the bound address (after start).
    pub async fn addr(&self) -> Option<SocketAddr> {
        *self.bound_addr.read().await
    }

    /// Returns the static public key for Noise.
    pub fn static_key(&self) -> &[u8; 32] {
        &self.noise_keypair.1
    }

    /// Creates a PeerInfo for this node.
    pub async fn peer_info(&self) -> Option<lux_net::PeerInfo> {
        let addr = self.addr().await?;
        Some(lux_net::PeerInfo {
            node_id: self.node_id,
            addresses: vec![addr],
            static_key: self.noise_keypair.1,
        })
    }

    /// Connects to another node.
    pub async fn connect_to(&self, other: &TestNode) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let peer_info = other.peer_info().await
            .ok_or("Other node not started")?;

        self.transport.connect(&peer_info).await?;
        debug!(from = %self.node_id, to = %other.node_id, "Connected to peer");
        Ok(())
    }

    /// Disconnects from another node.
    pub async fn disconnect_from(&self, other: &TestNode) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.transport.disconnect(&other.node_id).await?;
        debug!(from = %self.node_id, to = %other.node_id, "Disconnected from peer");
        Ok(())
    }

    /// Returns the number of active connections.
    pub fn connection_count(&self) -> usize {
        self.transport.connection_count()
    }

    /// Stores a chunk in the local store.
    pub fn store_chunk(&self, chunk: &lux_proto::storage::StoredChunk) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let store = self.store.as_ref().ok_or("Storage not enabled")?;
        store.put(chunk)?;
        Ok(())
    }

    /// Retrieves a chunk from the local store.
    pub fn get_chunk(&self, hash: &lux_core::CiphertextHash) -> Result<Option<lux_proto::storage::StoredChunk>, Box<dyn std::error::Error + Send + Sync>> {
        let store = self.store.as_ref().ok_or("Storage not enabled")?;
        Ok(store.get(hash)?)
    }

    /// Checks if a chunk exists in the local store.
    pub fn has_chunk(&self, hash: &lux_core::CiphertextHash) -> bool {
        self.store
            .as_ref()
            .and_then(|s| s.contains(hash).ok())
            .unwrap_or(false)
    }

    // =========================================================================
    // Message send/receive helpers for data exchange testing
    // =========================================================================

    /// Generates a unique request ID.
    pub fn next_request_id(&self) -> u64 {
        self.request_id_counter.fetch_add(1, Ordering::SeqCst)
    }

    /// Sends a message to another node.
    pub async fn send_message(
        &self,
        to: &NodeId,
        payload: MessagePayload,
    ) -> Result<u64, TransportError> {
        let request_id = self.next_request_id();
        let message = Message::new(request_id, self.node_id, payload);
        self.transport.send(to, message).await?;
        debug!(from = %self.node_id, to = %to, request_id, "Sent message");
        Ok(request_id)
    }

    /// Sends a ping to another node.
    pub async fn send_ping(&self, to: &NodeId) -> Result<u64, TransportError> {
        self.send_message(to, MessagePayload::Ping).await
    }

    /// Sends a pong response.
    pub async fn send_pong(&self, to: &NodeId, request_id: u64) -> Result<(), TransportError> {
        let message = Message::new(request_id, self.node_id, MessagePayload::Pong);
        self.transport.send(to, message).await
    }

    /// Sends a chunk to another node.
    pub async fn send_chunk(
        &self,
        to: &NodeId,
        chunk: lux_proto::storage::StoredChunk,
    ) -> Result<u64, TransportError> {
        self.send_message(to, MessagePayload::StoreChunk { chunk }).await
    }

    /// Requests a chunk from another node.
    pub async fn request_chunk(
        &self,
        to: &NodeId,
        hash: lux_core::CiphertextHash,
    ) -> Result<u64, TransportError> {
        self.send_message(to, MessagePayload::GetChunk { ciphertext_hash: hash }).await
    }

    /// Receives a message with timeout.
    pub async fn recv_message(
        &self,
        timeout_duration: Duration,
    ) -> Result<(NodeId, Message), TransportError> {
        match timeout(timeout_duration, self.transport.recv()).await {
            Ok(result) => result,
            Err(_) => Err(TransportError::Timeout),
        }
    }

    /// Receives a message and expects a specific payload type.
    pub async fn recv_ping(&self, timeout_duration: Duration) -> Result<(NodeId, u64), TransportError> {
        let (from, msg) = self.recv_message(timeout_duration).await?;
        match msg.payload {
            MessagePayload::Ping => Ok((from, msg.request_id)),
            _ => Err(TransportError::Other("Expected Ping".to_string())),
        }
    }

    /// Receives and expects a pong.
    pub async fn recv_pong(&self, timeout_duration: Duration) -> Result<(NodeId, u64), TransportError> {
        let (from, msg) = self.recv_message(timeout_duration).await?;
        match msg.payload {
            MessagePayload::Pong => Ok((from, msg.request_id)),
            _ => Err(TransportError::Other("Expected Pong".to_string())),
        }
    }

    /// Receives a StoreChunk message.
    pub async fn recv_store_chunk(
        &self,
        timeout_duration: Duration,
    ) -> Result<(NodeId, u64, lux_proto::storage::StoredChunk), TransportError> {
        let (from, msg) = self.recv_message(timeout_duration).await?;
        match msg.payload {
            MessagePayload::StoreChunk { chunk } => Ok((from, msg.request_id, chunk)),
            _ => Err(TransportError::Other("Expected StoreChunk".to_string())),
        }
    }

    /// Receives a GetChunk request.
    pub async fn recv_get_chunk(
        &self,
        timeout_duration: Duration,
    ) -> Result<(NodeId, u64, lux_core::CiphertextHash), TransportError> {
        let (from, msg) = self.recv_message(timeout_duration).await?;
        match msg.payload {
            MessagePayload::GetChunk { ciphertext_hash } => Ok((from, msg.request_id, ciphertext_hash)),
            _ => Err(TransportError::Other("Expected GetChunk".to_string())),
        }
    }

    /// Sends a GetChunk response.
    pub async fn send_chunk_response(
        &self,
        to: &NodeId,
        request_id: u64,
        chunk: Option<lux_proto::storage::StoredChunk>,
    ) -> Result<(), TransportError> {
        let message = Message::new(
            request_id,
            self.node_id,
            MessagePayload::GetChunkResponse { chunk },
        );
        self.transport.send(to, message).await
    }

    /// Receives a GetChunk response.
    pub async fn recv_chunk_response(
        &self,
        timeout_duration: Duration,
    ) -> Result<(NodeId, u64, Option<lux_proto::storage::StoredChunk>), TransportError> {
        let (from, msg) = self.recv_message(timeout_duration).await?;
        match msg.payload {
            MessagePayload::GetChunkResponse { chunk } => Ok((from, msg.request_id, chunk)),
            _ => Err(TransportError::Other("Expected GetChunkResponse".to_string())),
        }
    }

    /// Sends a StoreChunk response.
    pub async fn send_store_chunk_response(
        &self,
        to: &NodeId,
        request_id: u64,
        success: bool,
    ) -> Result<(), TransportError> {
        let message = Message::new(
            request_id,
            self.node_id,
            MessagePayload::StoreChunkResponse { success },
        );
        self.transport.send(to, message).await
    }
}

impl Drop for TestNode {
    fn drop(&mut self) {
        debug!(node_id = %self.node_id, "Dropping test node");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_node_creation() {
        let config = TestNodeConfig::default();
        let node = TestNode::new(config).await.unwrap();

        assert!(node.store.is_some());
    }

    #[tokio::test]
    async fn test_node_start() {
        let config = TestNodeConfig::default();
        let node = TestNode::new(config).await.unwrap();

        node.start().await.unwrap();

        let addr = node.addr().await;
        assert!(addr.is_some());
        assert!(addr.unwrap().port() > 0);
    }

    #[tokio::test]
    async fn test_node_peer_info() {
        let config = TestNodeConfig::default();
        let node = TestNode::new(config).await.unwrap();
        node.start().await.unwrap();

        let peer_info = node.peer_info().await.unwrap();
        assert_eq!(peer_info.node_id, node.node_id);
        assert_eq!(peer_info.static_key, *node.static_key());
    }
}
