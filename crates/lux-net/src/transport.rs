//! Transport trait and configuration.

use async_trait::async_trait;
use lux_core::NodeId;
use lux_proto::messages::Message;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

use crate::PeerInfo;

/// Transport errors.
#[derive(Debug, Error)]
pub enum TransportError {
    /// Connection failed
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    /// Connection timeout
    #[error("Connection timeout")]
    Timeout,

    /// Send failed
    #[error("Send failed: {0}")]
    SendFailed(String),

    /// Receive failed
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Invalid peer
    #[error("Invalid peer: {0}")]
    InvalidPeer(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Already connected
    #[error("Already connected to peer")]
    AlreadyConnected,

    /// Not connected
    #[error("Not connected to peer")]
    NotConnected,

    /// Other error
    #[error("{0}")]
    Other(String),
}

/// Transport configuration.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Enable QUIC transport
    pub enable_quic: bool,
    /// Enable TCP fallback
    pub enable_tcp: bool,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            connect_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(300),
            max_connections: 1000,
            enable_quic: true,
            enable_tcp: true,
        }
    }
}

/// Abstract transport layer.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Returns the local address.
    fn local_addr(&self) -> SocketAddr;

    /// Returns the local node ID.
    fn local_node_id(&self) -> &NodeId;

    /// Connects to a peer.
    async fn connect(&self, peer: &PeerInfo) -> Result<(), TransportError>;

    /// Disconnects from a peer.
    async fn disconnect(&self, node_id: &NodeId) -> Result<(), TransportError>;

    /// Returns true if connected to a peer.
    fn is_connected(&self, node_id: &NodeId) -> bool;

    /// Sends a message to a peer.
    async fn send(&self, node_id: &NodeId, message: Message) -> Result<(), TransportError>;

    /// Receives the next message.
    async fn recv(&self) -> Result<(NodeId, Message), TransportError>;

    /// Returns the number of active connections.
    fn connection_count(&self) -> usize;
}
