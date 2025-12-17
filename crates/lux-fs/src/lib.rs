//! Lux Filesystem - FUSE bindings and virtual filesystem.
//!
//! Implements the filesystem interface per specification §4.1:
//! - Mount semantics for Lux URIs
//! - Demand paging at chunk granularity
//! - Write buffering with atomic commits

#![warn(missing_docs, rust_2018_idioms)]

pub mod inode;
pub mod mount;
pub mod ops;
pub mod vfs;

pub use inode::{Inode, InodeId, InodeTable};
pub use mount::{MountConfig, MountPoint};
pub use vfs::{LuxFilesystem, VfsError};

use thiserror::Error;

/// Filesystem errors.
#[derive(Debug, Error)]
pub enum FsError {
    /// Mount failed
    #[error("Mount failed: {0}")]
    Mount(String),

    /// Unmount failed
    #[error("Unmount failed: {0}")]
    Unmount(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Permission denied
    #[error("Permission denied")]
    PermissionDenied,

    /// Invalid operation
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] lux_store::StoreError),
}
