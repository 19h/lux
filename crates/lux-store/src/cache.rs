//! Cache implementation per specification §4.2.
//!
//! Provides a multi-tier caching system:
//! - Hot Cache: Memory (recently accessed decrypted chunks)
//! - Warm Cache: SSD (LRU eviction)
//! - Cold Store: Network

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use lux_core::CiphertextHash;
use parking_lot::{Mutex, RwLock};

/// Cache configuration.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum memory cache size in bytes
    pub max_memory_bytes: u64,
    /// Maximum disk cache size in bytes
    pub max_disk_bytes: u64,
    /// Enable prefetching for sequential access
    pub prefetch_enabled: bool,
    /// Number of chunks to prefetch
    pub prefetch_count: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MiB
            max_disk_bytes: 10 * 1024 * 1024 * 1024, // 10 GiB
            prefetch_enabled: true,
            prefetch_count: 4,
        }
    }
}

/// Cache entry with metadata.
struct CacheEntry {
    /// Decrypted chunk data
    data: Vec<u8>,
    /// Size in bytes
    size: usize,
    /// Last access time (monotonic counter)
    last_access: u64,
}

/// LRU memory cache for decrypted chunks.
pub struct Cache {
    config: CacheConfig,
    /// Cached entries
    entries: RwLock<HashMap<CiphertextHash, CacheEntry>>,
    /// Current cache size in bytes
    current_size: AtomicU64,
    /// Access counter for LRU
    access_counter: AtomicU64,
    /// Statistics
    stats: RwLock<CacheStats>,
}

/// Cache statistics.
#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Evictions
    pub evictions: u64,
    /// Total bytes cached
    pub bytes_cached: u64,
}

impl Cache {
    /// Creates a new cache with the given configuration.
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            entries: RwLock::new(HashMap::new()),
            current_size: AtomicU64::new(0),
            access_counter: AtomicU64::new(0),
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Creates a cache with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Gets a decrypted chunk from the cache.
    pub fn get(&self, hash: &CiphertextHash) -> Option<Vec<u8>> {
        let mut entries = self.entries.write();

        if let Some(entry) = entries.get_mut(hash) {
            // Update access time
            entry.last_access = self.access_counter.fetch_add(1, Ordering::Relaxed);
            self.stats.write().hits += 1;
            Some(entry.data.clone())
        } else {
            self.stats.write().misses += 1;
            None
        }
    }

    /// Puts a decrypted chunk into the cache.
    pub fn put(&self, hash: CiphertextHash, data: Vec<u8>) {
        let size = data.len();

        // Evict if necessary
        while self.current_size.load(Ordering::Relaxed) + size as u64 > self.config.max_memory_bytes
        {
            if !self.evict_one() {
                break;
            }
        }

        let entry = CacheEntry {
            data,
            size,
            last_access: self.access_counter.fetch_add(1, Ordering::Relaxed),
        };

        let mut entries = self.entries.write();
        if let Some(old) = entries.insert(hash, entry) {
            self.current_size
                .fetch_sub(old.size as u64, Ordering::Relaxed);
        }
        self.current_size.fetch_add(size as u64, Ordering::Relaxed);
        self.stats.write().bytes_cached += size as u64;
    }

    /// Removes an entry from the cache.
    pub fn remove(&self, hash: &CiphertextHash) -> Option<Vec<u8>> {
        let mut entries = self.entries.write();
        if let Some(entry) = entries.remove(hash) {
            self.current_size
                .fetch_sub(entry.size as u64, Ordering::Relaxed);
            Some(entry.data)
        } else {
            None
        }
    }

    /// Returns the current cache size in bytes.
    pub fn size(&self) -> u64 {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Clears the cache.
    pub fn clear(&self) {
        self.entries.write().clear();
        self.current_size.store(0, Ordering::Relaxed);
    }

    /// Returns cache statistics.
    pub fn stats(&self) -> CacheStats {
        self.stats.read().clone()
    }

    /// Evicts one entry (LRU).
    fn evict_one(&self) -> bool {
        let mut entries = self.entries.write();

        // Find the least recently used entry
        let lru_key = entries
            .iter()
            .min_by_key(|(_, e)| e.last_access)
            .map(|(k, _)| *k);

        if let Some(key) = lru_key {
            if let Some(entry) = entries.remove(&key) {
                self.current_size
                    .fetch_sub(entry.size as u64, Ordering::Relaxed);
                self.stats.write().evictions += 1;
                return true;
            }
        }

        false
    }
}

/// Prefetch hint for sequential access patterns.
pub struct PrefetchHint {
    /// Hashes to prefetch
    pub hashes: Vec<CiphertextHash>,
}

/// Detects sequential access patterns for prefetching.
pub struct AccessPatternDetector {
    /// Recent access history
    history: Mutex<Vec<CiphertextHash>>,
    /// Maximum history size
    max_history: usize,
}

impl AccessPatternDetector {
    /// Creates a new detector.
    pub fn new(max_history: usize) -> Self {
        Self {
            history: Mutex::new(Vec::with_capacity(max_history)),
            max_history,
        }
    }

    /// Records an access.
    pub fn record_access(&self, hash: CiphertextHash) {
        let mut history = self.history.lock();
        if history.len() >= self.max_history {
            history.remove(0);
        }
        history.push(hash);
    }

    /// Returns true if recent access pattern is sequential.
    pub fn is_sequential(&self) -> bool {
        let history = self.history.lock();
        // Simple heuristic: if we have multiple accesses, assume sequential
        history.len() >= 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic() {
        let cache = Cache::new(CacheConfig {
            max_memory_bytes: 1024,
            ..Default::default()
        });

        let hash = CiphertextHash::new([0x42; 32]);
        let data = vec![0xAA; 100];

        cache.put(hash, data.clone());
        assert_eq!(cache.get(&hash), Some(data));
    }

    #[test]
    fn test_cache_eviction() {
        let cache = Cache::new(CacheConfig {
            max_memory_bytes: 200,
            ..Default::default()
        });

        // Add entries that exceed capacity
        for i in 0..5 {
            let mut hash = [0u8; 32];
            hash[0] = i;
            cache.put(CiphertextHash::new(hash), vec![0xAA; 100]);
        }

        // Should have evicted some entries
        assert!(cache.size() <= 200);

        let stats = cache.stats();
        assert!(stats.evictions > 0);
    }

    #[test]
    fn test_cache_remove() {
        let cache = Cache::with_defaults();

        let hash = CiphertextHash::new([0x42; 32]);
        let data = vec![0xAA; 100];

        cache.put(hash, data.clone());
        assert!(cache.get(&hash).is_some());

        let removed = cache.remove(&hash);
        assert_eq!(removed, Some(data));
        assert!(cache.get(&hash).is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = Cache::with_defaults();

        let hash = CiphertextHash::new([0x42; 32]);
        cache.put(hash, vec![0xAA; 100]);

        // Hit
        cache.get(&hash);
        // Miss
        cache.get(&CiphertextHash::new([0xFF; 32]));

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }
}
