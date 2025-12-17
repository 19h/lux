//! Chunk storage implementation.
//!
//! Stores encrypted chunks keyed by their CiphertextHash.

use std::path::Path;
use std::sync::Arc;

use lux_core::CiphertextHash;
use lux_proto::StoredChunk;
use parking_lot::RwLock;
use rocksdb::{Options, DB};
use tracing::{debug, warn};

use crate::StoreError;

/// Column family name for chunks.
const CHUNKS_CF: &str = "chunks";

/// Local chunk storage backed by RocksDB.
pub struct ChunkStore {
    db: Arc<DB>,
    /// Statistics tracking
    stats: RwLock<ChunkStoreStats>,
}

/// Statistics for the chunk store.
#[derive(Debug, Default, Clone)]
pub struct ChunkStoreStats {
    /// Total chunks stored
    pub chunks_stored: u64,
    /// Total bytes stored
    pub bytes_stored: u64,
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
}

impl ChunkStore {
    /// Opens or creates a chunk store at the given path.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Optimize for random reads
        opts.set_allow_concurrent_memtable_write(true);
        opts.set_enable_write_thread_adaptive_yield(true);

        let db = DB::open_cf(&opts, path, [CHUNKS_CF])
            .map_err(|e| StoreError::Database(e.to_string()))?;

        Ok(Self {
            db: Arc::new(db),
            stats: RwLock::new(ChunkStoreStats::default()),
        })
    }

    /// Opens a chunk store with an existing DB instance.
    pub fn with_db(db: Arc<DB>) -> Self {
        Self {
            db,
            stats: RwLock::new(ChunkStoreStats::default()),
        }
    }

    /// Stores a chunk.
    ///
    /// Returns the CiphertextHash of the stored chunk.
    pub fn put(&self, chunk: &StoredChunk) -> Result<CiphertextHash, StoreError> {
        let hash = chunk.ciphertext_hash();
        let key = hash.as_bytes();
        let value = chunk.to_bytes();

        let cf = self
            .db
            .cf_handle(CHUNKS_CF)
            .ok_or_else(|| StoreError::Database("Missing chunks column family".to_string()))?;

        self.db
            .put_cf(&cf, key, &value)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.chunks_stored += 1;
            stats.bytes_stored += value.len() as u64;
        }

        debug!(hash = %hash, size = value.len(), "Stored chunk");
        Ok(hash)
    }

    /// Retrieves a chunk by its CiphertextHash.
    pub fn get(&self, hash: &CiphertextHash) -> Result<Option<StoredChunk>, StoreError> {
        let cf = self
            .db
            .cf_handle(CHUNKS_CF)
            .ok_or_else(|| StoreError::Database("Missing chunks column family".to_string()))?;

        match self
            .db
            .get_cf(&cf, hash.as_bytes())
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(bytes) => {
                let chunk = StoredChunk::from_bytes(&bytes)
                    .map_err(|e| StoreError::InvalidData(e.to_string()))?;

                // Verify hash matches
                let actual_hash = chunk.ciphertext_hash();
                if actual_hash != *hash {
                    warn!(
                        expected = %hash,
                        actual = %actual_hash,
                        "Chunk hash mismatch"
                    );
                    return Err(StoreError::InvalidData("Hash mismatch".to_string()));
                }

                self.stats.write().hits += 1;
                Ok(Some(chunk))
            }
            None => {
                self.stats.write().misses += 1;
                Ok(None)
            }
        }
    }

    /// Checks if a chunk exists.
    pub fn contains(&self, hash: &CiphertextHash) -> Result<bool, StoreError> {
        let cf = self
            .db
            .cf_handle(CHUNKS_CF)
            .ok_or_else(|| StoreError::Database("Missing chunks column family".to_string()))?;

        self.db
            .get_cf(&cf, hash.as_bytes())
            .map(|v| v.is_some())
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    /// Deletes a chunk.
    pub fn delete(&self, hash: &CiphertextHash) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(CHUNKS_CF)
            .ok_or_else(|| StoreError::Database("Missing chunks column family".to_string()))?;

        self.db
            .delete_cf(&cf, hash.as_bytes())
            .map_err(|e| StoreError::Database(e.to_string()))?;

        debug!(hash = %hash, "Deleted chunk");
        Ok(())
    }

    /// Returns store statistics.
    pub fn stats(&self) -> ChunkStoreStats {
        self.stats.read().clone()
    }

    /// Lists all chunk hashes in the store.
    ///
    /// Note: This can be expensive for large stores.
    pub fn list_chunks(&self) -> Result<Vec<CiphertextHash>, StoreError> {
        let cf = self
            .db
            .cf_handle(CHUNKS_CF)
            .ok_or_else(|| StoreError::Database("Missing chunks column family".to_string()))?;

        let mut hashes = Vec::new();
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, _) = item.map_err(|e| StoreError::Database(e.to_string()))?;
            if key.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&key);
                hashes.push(CiphertextHash::new(arr));
            }
        }

        Ok(hashes)
    }

    /// Returns the total size of all stored chunks.
    pub fn total_size(&self) -> Result<u64, StoreError> {
        let cf = self
            .db
            .cf_handle(CHUNKS_CF)
            .ok_or_else(|| StoreError::Database("Missing chunks column family".to_string()))?;

        let mut total = 0u64;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item.map_err(|e| StoreError::Database(e.to_string()))?;
            total += value.len() as u64;
        }

        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_chunk() -> StoredChunk {
        StoredChunk::new([0x42u8; 24], vec![0xAA; 100])
    }

    #[test]
    fn test_chunk_store_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let chunk = create_test_chunk();
        let hash = store.put(&chunk).unwrap();

        let retrieved = store.get(&hash).unwrap().unwrap();
        assert_eq!(chunk.nonce, retrieved.nonce);
        assert_eq!(chunk.ciphertext_with_tag, retrieved.ciphertext_with_tag);
    }

    #[test]
    fn test_chunk_store_contains() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let chunk = create_test_chunk();
        let hash = store.put(&chunk).unwrap();

        assert!(store.contains(&hash).unwrap());

        let nonexistent = CiphertextHash::new([0xFF; 32]);
        assert!(!store.contains(&nonexistent).unwrap());
    }

    #[test]
    fn test_chunk_store_delete() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let chunk = create_test_chunk();
        let hash = store.put(&chunk).unwrap();
        assert!(store.contains(&hash).unwrap());

        store.delete(&hash).unwrap();
        assert!(!store.contains(&hash).unwrap());
    }

    #[test]
    fn test_chunk_store_stats() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let chunk = create_test_chunk();
        let hash = store.put(&chunk).unwrap();

        // Hit
        store.get(&hash).unwrap();

        // Miss
        let nonexistent = CiphertextHash::new([0xFF; 32]);
        store.get(&nonexistent).unwrap();

        let stats = store.stats();
        assert_eq!(stats.chunks_stored, 1);
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_chunk_store_multiple_chunks() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let mut hashes = Vec::new();
        for i in 0..100 {
            let chunk = StoredChunk::new([i as u8; 24], vec![i as u8; 100 + i]);
            let hash = store.put(&chunk).unwrap();
            hashes.push(hash);
        }

        // Verify all chunks can be retrieved
        for (i, hash) in hashes.iter().enumerate() {
            let chunk = store.get(hash).unwrap().unwrap();
            assert_eq!(chunk.nonce, [i as u8; 24]);
            assert_eq!(chunk.ciphertext_with_tag.len(), 100 + i);
        }

        let stats = store.stats();
        assert_eq!(stats.chunks_stored, 100);
    }

    #[test]
    fn test_chunk_store_list_chunks() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let chunk1 = StoredChunk::new([0x01; 24], vec![0xAA; 50]);
        let chunk2 = StoredChunk::new([0x02; 24], vec![0xBB; 60]);
        let chunk3 = StoredChunk::new([0x03; 24], vec![0xCC; 70]);

        let hash1 = store.put(&chunk1).unwrap();
        let hash2 = store.put(&chunk2).unwrap();
        let hash3 = store.put(&chunk3).unwrap();

        let listed = store.list_chunks().unwrap();
        assert_eq!(listed.len(), 3);
        assert!(listed.contains(&hash1));
        assert!(listed.contains(&hash2));
        assert!(listed.contains(&hash3));
    }

    #[test]
    fn test_chunk_store_total_size() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        let chunk1 = StoredChunk::new([0x01; 24], vec![0xAA; 100]);
        let chunk2 = StoredChunk::new([0x02; 24], vec![0xBB; 200]);

        store.put(&chunk1).unwrap();
        store.put(&chunk2).unwrap();

        let total = store.total_size().unwrap();
        // Total should account for serialized size including nonce
        assert!(total > 300);
    }

    #[test]
    fn test_chunk_store_persistence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().to_path_buf();

        let hash;
        {
            let store = ChunkStore::open(&path).unwrap();
            let chunk = create_test_chunk();
            hash = store.put(&chunk).unwrap();
        }

        // Reopen store
        {
            let store = ChunkStore::open(&path).unwrap();
            let chunk = store.get(&hash).unwrap().unwrap();
            assert_eq!(chunk.nonce, [0x42u8; 24]);
        }
    }

    #[test]
    fn test_chunk_store_large_chunk() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        // Store a 1MB chunk
        let large_data = vec![0xAB; 1024 * 1024];
        let chunk = StoredChunk::new([0x42; 24], large_data.clone());
        let hash = store.put(&chunk).unwrap();

        let retrieved = store.get(&hash).unwrap().unwrap();
        assert_eq!(retrieved.ciphertext_with_tag, large_data);
    }

    #[test]
    fn test_chunk_store_minimum_chunk() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        // Minimum valid ciphertext: just the 16-byte tag (for empty plaintext)
        let chunk = StoredChunk::new([0x42; 24], vec![0xAA; 16]);
        let hash = store.put(&chunk).unwrap();

        let retrieved = store.get(&hash).unwrap().unwrap();
        assert_eq!(retrieved.ciphertext_with_tag.len(), 16);
    }

    #[test]
    fn test_chunk_hash_determinism() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        // Same content should produce same hash
        let chunk1 = StoredChunk::new([0x42; 24], vec![0xAA; 100]);
        let chunk2 = StoredChunk::new([0x42; 24], vec![0xAA; 100]);

        let hash1 = store.put(&chunk1).unwrap();
        let hash2 = store.put(&chunk2).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_chunk_different_nonces() {
        let dir = TempDir::new().unwrap();
        let store = ChunkStore::open(dir.path()).unwrap();

        // Same ciphertext but different nonces should produce different hashes
        let chunk1 = StoredChunk::new([0x01; 24], vec![0xAA; 100]);
        let chunk2 = StoredChunk::new([0x02; 24], vec![0xAA; 100]);

        let hash1 = store.put(&chunk1).unwrap();
        let hash2 = store.put(&chunk2).unwrap();

        assert_ne!(hash1, hash2);
    }
}
