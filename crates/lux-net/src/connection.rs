//! Connection management.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use lux_core::NodeId;

/// Unique connection identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    /// Generates a new unique connection ID.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connecting (handshake in progress)
    Connecting,
    /// Connected and ready
    Connected,
    /// Disconnecting
    Disconnecting,
    /// Disconnected
    Disconnected,
    /// Failed
    Failed,
}

/// Represents a connection to a peer.
#[derive(Debug)]
pub struct Connection {
    /// Connection ID
    pub id: ConnectionId,
    /// Remote node ID
    pub node_id: NodeId,
    /// Connection state
    pub state: ConnectionState,
    /// When the connection was established
    pub connected_at: Option<Instant>,
    /// Last activity time
    pub last_activity: Instant,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
}

impl Connection {
    /// Creates a new connection.
    pub fn new(node_id: NodeId) -> Self {
        Self {
            id: ConnectionId::new(),
            node_id,
            state: ConnectionState::Connecting,
            connected_at: None,
            last_activity: Instant::now(),
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
        }
    }

    /// Marks the connection as connected.
    pub fn set_connected(&mut self) {
        self.state = ConnectionState::Connected;
        self.connected_at = Some(Instant::now());
    }

    /// Marks the connection as disconnected.
    pub fn set_disconnected(&mut self) {
        self.state = ConnectionState::Disconnected;
    }

    /// Marks the connection as failed.
    pub fn set_failed(&mut self) {
        self.state = ConnectionState::Failed;
    }

    /// Returns true if the connection is active.
    pub fn is_active(&self) -> bool {
        self.state == ConnectionState::Connected
    }

    /// Records sent data.
    pub fn record_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.messages_sent += 1;
        self.last_activity = Instant::now();
    }

    /// Records received data.
    pub fn record_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.messages_received += 1;
        self.last_activity = Instant::now();
    }

    /// Returns the connection duration.
    pub fn duration(&self) -> Option<std::time::Duration> {
        self.connected_at.map(|t| t.elapsed())
    }

    /// Returns time since last activity.
    pub fn idle_time(&self) -> std::time::Duration {
        self.last_activity.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_lifecycle() {
        let node_id = NodeId::random();
        let mut conn = Connection::new(node_id);

        assert_eq!(conn.state, ConnectionState::Connecting);
        assert!(!conn.is_active());

        conn.set_connected();
        assert_eq!(conn.state, ConnectionState::Connected);
        assert!(conn.is_active());

        conn.record_sent(100);
        conn.record_received(200);
        assert_eq!(conn.bytes_sent, 100);
        assert_eq!(conn.bytes_received, 200);

        conn.set_disconnected();
        assert!(!conn.is_active());
    }

    #[test]
    fn test_connection_id_unique() {
        let id1 = ConnectionId::new();
        let id2 = ConnectionId::new();
        assert_ne!(id1, id2);
    }
}
