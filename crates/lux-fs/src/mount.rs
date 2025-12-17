//! Mount point management.

use std::path::PathBuf;

use lux_proto::uri::LuxUri;

/// Mount configuration.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Mount point path
    pub mount_point: PathBuf,
    /// Allow other users to access
    pub allow_other: bool,
    /// Read-only mount
    pub read_only: bool,
    /// Enable write caching
    pub write_cache: bool,
    /// Cache timeout in seconds
    pub cache_timeout_secs: u64,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            mount_point: PathBuf::new(),
            allow_other: false,
            read_only: false,
            write_cache: true,
            cache_timeout_secs: 60,
        }
    }
}

/// A mounted Lux filesystem.
#[derive(Debug)]
pub struct MountPoint {
    /// Configuration
    pub config: MountConfig,
    /// The Lux URI being mounted
    pub uri: LuxUri,
    /// Mount status
    pub mounted: bool,
}

impl MountPoint {
    /// Creates a new mount point.
    pub fn new(uri: LuxUri, config: MountConfig) -> Self {
        Self {
            config,
            uri,
            mounted: false,
        }
    }

    /// Returns the mount path.
    pub fn path(&self) -> &PathBuf {
        &self.config.mount_point
    }

    /// Returns true if mounted.
    pub fn is_mounted(&self) -> bool {
        self.mounted
    }
}
