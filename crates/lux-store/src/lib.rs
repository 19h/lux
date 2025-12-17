//! Lux Store - Local storage engine.
//!
//! Provides persistent storage for:
//! - Encrypted chunks (keyed by CiphertextHash)
//! - Manifests (keyed by ObjectId)
//! - DHT records
//! - Local cache management

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod blob;
pub mod cache;
pub mod chunk;
pub mod config;
pub mod manifest;

pub use blob::BlobStore;
pub use cache::{Cache, CacheConfig};
pub use chunk::ChunkStore;
pub use config::StoreConfig;
pub use manifest::ManifestStore;

use thiserror::Error;

/// Errors from storage operations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// RocksDB error
    #[error("Database error: {0}")]
    Database(String),

    /// Chunk not found
    #[error("Chunk not found: {0}")]
    ChunkNotFound(String),

    /// Manifest not found
    #[error("Manifest not found: {0}")]
    ManifestNotFound(String),

    /// Encoding error
    #[error("Encoding error: {0}")]
    Encoding(#[from] lux_core::encoding::DecodeError),

    /// Invalid data
    #[error("Invalid data: {0}")]
    InvalidData(String),
}
