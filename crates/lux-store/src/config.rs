//! Storage configuration.

use std::path::PathBuf;

/// Storage configuration per specification §16.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Base path for all storage
    pub base_path: PathBuf,
    /// Maximum memory cache size in megabytes
    pub max_memory_mb: u64,
    /// Maximum disk cache size in gigabytes
    pub max_disk_gb: u64,
    /// Enable write-ahead logging
    pub wal_enabled: bool,
    /// Sync writes to disk
    pub sync_writes: bool,
    /// Compression enabled
    pub compression: bool,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from(".lux"),
            max_memory_mb: 256,
            max_disk_gb: 10,
            wal_enabled: true,
            sync_writes: false,
            compression: true,
        }
    }
}

impl StoreConfig {
    /// Creates a new configuration with the given base path.
    pub fn new(base_path: PathBuf) -> Self {
        Self {
            base_path,
            ..Default::default()
        }
    }

    /// Returns the path for chunk storage.
    pub fn chunks_path(&self) -> PathBuf {
        self.base_path.join("chunks")
    }

    /// Returns the path for blob storage.
    pub fn blobs_path(&self) -> PathBuf {
        self.base_path.join("blobs")
    }

    /// Returns the path for manifest storage.
    pub fn manifests_path(&self) -> PathBuf {
        self.base_path.join("manifests")
    }

    /// Returns the path for DHT records.
    pub fn dht_path(&self) -> PathBuf {
        self.base_path.join("dht")
    }

    /// Returns the maximum memory cache size in bytes.
    pub fn max_memory_bytes(&self) -> u64 {
        self.max_memory_mb * 1024 * 1024
    }

    /// Returns the maximum disk cache size in bytes.
    pub fn max_disk_bytes(&self) -> u64 {
        self.max_disk_gb * 1024 * 1024 * 1024
    }

    /// Creates all necessary directories.
    pub fn create_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.base_path)?;
        std::fs::create_dir_all(self.chunks_path())?;
        std::fs::create_dir_all(self.blobs_path())?;
        std::fs::create_dir_all(self.manifests_path())?;
        std::fs::create_dir_all(self.dht_path())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_paths() {
        let config = StoreConfig::new(PathBuf::from("/tmp/lux"));
        assert_eq!(config.chunks_path(), PathBuf::from("/tmp/lux/chunks"));
        assert_eq!(config.blobs_path(), PathBuf::from("/tmp/lux/blobs"));
    }

    #[test]
    fn test_config_sizes() {
        let config = StoreConfig {
            max_memory_mb: 512,
            max_disk_gb: 20,
            ..Default::default()
        };
        assert_eq!(config.max_memory_bytes(), 512 * 1024 * 1024);
        assert_eq!(config.max_disk_bytes(), 20 * 1024 * 1024 * 1024);
    }
}
