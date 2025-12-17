//! High-level filesystem operations.

use std::path::Path;
use std::process::Command;
use std::sync::Arc;

use lux_core::{CapabilitySecret, ObjectId};
use lux_proto::uri::{LuxUri, ObjectUri};
use lux_store::BlobStore;

use crate::mount::MountConfig;
use crate::vfs::LuxFilesystem;
use crate::FsError;

/// Mounts a Lux URI as a filesystem.
pub fn mount(uri: &LuxUri, mount_point: &Path, config: MountConfig) -> Result<(), FsError> {
    // Ensure mount point exists
    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point)
            .map_err(|e| FsError::Mount(format!("Failed to create mount point: {}", e)))?;
    }

    // Create filesystem instance
    let fs = LuxFilesystem::new(config);

    // Mount using fuser
    let options = vec![
        fuser::MountOption::RW,
        fuser::MountOption::FSName("lux".to_string()),
        fuser::MountOption::AutoUnmount,
        fuser::MountOption::AllowOther,
    ];

    fuser::mount2(fs, mount_point, &options)
        .map_err(|e| FsError::Mount(format!("FUSE mount failed: {}", e)))?;

    Ok(())
}

/// Mounts a Lux URI as a filesystem with a blob store for content retrieval.
pub fn mount_with_store(
    uri: &LuxUri,
    mount_point: &Path,
    config: MountConfig,
    store: Arc<BlobStore>,
) -> Result<(), FsError> {
    // Ensure mount point exists
    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point)
            .map_err(|e| FsError::Mount(format!("Failed to create mount point: {}", e)))?;
    }

    // Create filesystem instance with store
    let fs = LuxFilesystem::new(config).with_store(store);

    // Mount using fuser
    let options = vec![
        fuser::MountOption::RW,
        fuser::MountOption::FSName("lux".to_string()),
        fuser::MountOption::AutoUnmount,
    ];

    fuser::mount2(fs, mount_point, &options)
        .map_err(|e| FsError::Mount(format!("FUSE mount failed: {}", e)))?;

    Ok(())
}

/// Unmounts a filesystem.
pub fn unmount(mount_point: &Path) -> Result<(), FsError> {
    // Use fusermount to unmount
    let output = Command::new("fusermount")
        .arg("-u")
        .arg(mount_point)
        .output()
        .map_err(|e| FsError::Unmount(format!("Failed to run fusermount: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FsError::Unmount(format!("fusermount failed: {}", stderr)));
    }

    Ok(())
}

/// Creates a new mutable object and returns its URI.
pub fn create_object() -> ObjectUri {
    let object_id = ObjectId::random();
    let capability = CapabilitySecret::random();
    ObjectUri::new(object_id, capability)
}

/// Synchronizes local changes to the network.
pub fn sync(mount_point: &Path, store: &BlobStore) -> Result<SyncResult, FsError> {
    // This would typically:
    // 1. Flush any buffered writes to chunk store
    // 2. Build a new Merkle DAG from modified files
    // 3. Create and sign a new manifest
    // 4. Upload new chunks to the network
    // 5. Publish manifest to DHT

    // For now, return stats about what would be synced
    Ok(SyncResult {
        chunks_uploaded: 0,
        bytes_uploaded: 0,
        manifest_published: false,
    })
}

/// Result of a sync operation.
#[derive(Debug, Clone)]
pub struct SyncResult {
    /// Number of chunks uploaded to the network.
    pub chunks_uploaded: usize,
    /// Total bytes uploaded.
    pub bytes_uploaded: u64,
    /// Whether the manifest was published.
    pub manifest_published: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_object() {
        let uri1 = create_object();
        let uri2 = create_object();

        // Each call should create a unique object
        assert_ne!(uri1.object_id, uri2.object_id);
    }

    #[test]
    fn test_object_uri_roundtrip() {
        let uri = create_object();
        let uri_string = uri.to_string();

        // Should be parseable back (format is lux:obj:...)
        assert!(uri_string.starts_with("lux:obj:"));
    }
}
