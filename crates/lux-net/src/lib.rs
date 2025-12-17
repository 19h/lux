//! Lux Network - Network transport layer.
//!
//! Implements the network stack per specification §12:
//! - Noise NK encryption
//! - QUIC transport (primary)
//! - TCP transport (fallback)
//! - NAT traversal

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod connection;
pub mod noise;
pub mod quic;
pub mod transport;

pub use connection::{Connection, ConnectionId, ConnectionState};
pub use noise::NoiseSession;
pub use transport::{Transport, TransportConfig, TransportError};

use lux_core::NodeId;
use std::net::SocketAddr;

/// Peer information for connection establishment.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer node ID
    pub node_id: NodeId,
    /// Network addresses
    pub addresses: Vec<SocketAddr>,
    /// Static public key for Noise NK
    pub static_key: [u8; 32],
}
