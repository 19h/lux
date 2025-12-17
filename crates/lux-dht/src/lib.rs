//! Lux DHT - Kademlia DHT implementation.
//!
//! Implements a Kademlia-derived distributed hash table for:
//! - Node discovery and routing
//! - Manifest announcement and lookup
//! - Chunk holder tracking
//! - Data resilience and repair

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod record;
pub mod resilience;
pub mod routing;
pub mod service;

pub use record::{RecordStore, RecordStoreConfig, RecordStoreStats};
pub use resilience::{
    ChunkHealth, HealthCheckResult, RepairTask, ResilienceManager, ResiliencePolicy,
    ResilienceStats, DEFAULT_LEASE_TTL_DAYS, DEFAULT_MIN_REPLICAS,
    DEFAULT_REPAIR_CHECK_INTERVAL_HOURS,
};
pub use routing::{KBucket, RoutingTable, RoutingTableConfig};
pub use service::{DhtConfig, DhtService};

/// Default k value (bucket size) per specification §16.1.
pub const DEFAULT_K: usize = 20;

/// Default alpha value (parallelism) per specification §16.1.
pub const DEFAULT_ALPHA: usize = 3;

/// Default node stale timeout in seconds (1 hour).
/// Nodes not seen for this duration are considered stale.
pub const DEFAULT_STALE_TIMEOUT_SECS: u64 = 3600;

/// Default bucket refresh interval in seconds (1 hour).
/// How often to refresh routing table buckets.
pub const DEFAULT_REFRESH_INTERVAL_SECS: u64 = 3600;

/// Default DHT record TTL in seconds (24 hours).
/// Records older than this are considered expired.
pub const DEFAULT_RECORD_TTL_SECS: u64 = 86400;

/// Default maximum number of records per store.
pub const DEFAULT_MAX_RECORDS: usize = 100_000;

/// Default command channel buffer size.
pub const DEFAULT_COMMAND_CHANNEL_SIZE: usize = 1024;
