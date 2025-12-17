//! Blob storage implementation.
//!
//! Manages complete blobs (files) and their DAG structure.

use std::path::Path;
use std::sync::Arc;

use lux_core::encoding::{CanonicalDecode, CanonicalEncode};
use lux_core::{BlobId, ChunkId, DagRef};
use lux_proto::{DagNode, StoredChunk};
use parking_lot::RwLock;
use rocksdb::{Options, DB};
use tracing::debug;

use crate::chunk::ChunkStore;
use crate::StoreError;

/// Column family for DAG nodes.
const DAG_CF: &str = "dag";
/// Column family for blob metadata.
const BLOB_META_CF: &str = "blob_meta";

/// Blob metadata stored alongside DAG.
#[derive(Debug, Clone)]
pub struct BlobMetadata {
    /// Root DAG reference
    pub root: DagRef,
    /// Total size of the blob
    pub size: u64,
    /// Number of chunks
    pub chunk_count: u32,
}

impl CanonicalEncode for BlobMetadata {
    fn encode(&self, buf: &mut bytes::BytesMut) {
        self.root.encode(buf);
        self.size.encode(buf);
        self.chunk_count.encode(buf);
    }
}

impl CanonicalDecode for BlobMetadata {
    fn decode(buf: &mut bytes::Bytes) -> Result<Self, lux_core::encoding::DecodeError> {
        Ok(Self {
            root: DagRef::decode(buf)?,
            size: u64::decode(buf)?,
            chunk_count: u32::decode(buf)?,
        })
    }
}

/// Blob store for managing complete files.
pub struct BlobStore {
    db: Arc<DB>,
    chunk_store: Arc<ChunkStore>,
}

impl BlobStore {
    /// Opens a blob store at the given path.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let db = DB::open_cf(&opts, path, [DAG_CF, BLOB_META_CF, "chunks"])
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let db = Arc::new(db);
        let chunk_store = Arc::new(ChunkStore::with_db(Arc::clone(&db)));

        Ok(Self { db, chunk_store })
    }

    /// Returns the underlying chunk store.
    pub fn chunk_store(&self) -> &ChunkStore {
        &self.chunk_store
    }

    /// Stores a DAG node.
    pub fn put_dag_node(&self, node: &DagNode) -> Result<DagRef, StoreError> {
        let dag_ref = node.dag_ref();
        let encoded = node.to_vec();

        let cf = self
            .db
            .cf_handle(DAG_CF)
            .ok_or_else(|| StoreError::Database("Missing dag column family".to_string()))?;

        self.db
            .put_cf(&cf, dag_ref.as_bytes(), &encoded)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        debug!(dag_ref = %dag_ref, "Stored DAG node");
        Ok(dag_ref)
    }

    /// Retrieves a DAG node by reference.
    pub fn get_dag_node(&self, dag_ref: &DagRef) -> Result<Option<DagNode>, StoreError> {
        if dag_ref.is_empty() {
            return Ok(None);
        }

        let cf = self
            .db
            .cf_handle(DAG_CF)
            .ok_or_else(|| StoreError::Database("Missing dag column family".to_string()))?;

        match self
            .db
            .get_cf(&cf, dag_ref.as_bytes())
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(bytes) => {
                let node = DagNode::from_bytes(&bytes)?;
                Ok(Some(node))
            }
            None => Ok(None),
        }
    }

    /// Stores blob metadata.
    pub fn put_blob_metadata(
        &self,
        blob_id: &BlobId,
        metadata: &BlobMetadata,
    ) -> Result<(), StoreError> {
        let encoded = metadata.to_vec();

        let cf = self
            .db
            .cf_handle(BLOB_META_CF)
            .ok_or_else(|| StoreError::Database("Missing blob_meta column family".to_string()))?;

        self.db
            .put_cf(&cf, blob_id.as_bytes(), &encoded)
            .map_err(|e| StoreError::Database(e.to_string()))?;

        debug!(blob_id = %blob_id, "Stored blob metadata");
        Ok(())
    }

    /// Retrieves blob metadata.
    pub fn get_blob_metadata(&self, blob_id: &BlobId) -> Result<Option<BlobMetadata>, StoreError> {
        let cf = self
            .db
            .cf_handle(BLOB_META_CF)
            .ok_or_else(|| StoreError::Database("Missing blob_meta column family".to_string()))?;

        match self
            .db
            .get_cf(&cf, blob_id.as_bytes())
            .map_err(|e| StoreError::Database(e.to_string()))?
        {
            Some(bytes) => {
                let metadata = BlobMetadata::from_bytes(&bytes)?;
                Ok(Some(metadata))
            }
            None => Ok(None),
        }
    }

    /// Stores a complete blob with all its chunks.
    ///
    /// This is a higher-level operation that:
    /// 1. Chunks the data using FastCDC
    /// 2. Encrypts each chunk
    /// 3. Stores the encrypted chunks
    /// 4. Builds the DAG structure
    /// 5. Stores blob metadata
    pub fn put_blob(&self, data: &[u8]) -> Result<BlobId, StoreError> {
        use lux_cdc::chunk;
        use lux_core::crypto::{encrypt_xchacha20poly1305, KeySchedule};

        let blob_id = BlobId::from_plaintext(data);
        let blob_key = KeySchedule::blob_key(blob_id.as_bytes());

        let boundaries = chunk(data);
        let mut chunk_refs = Vec::new();

        for i in 0..boundaries.len().saturating_sub(1) {
            let start = boundaries[i];
            let end = boundaries[i + 1];
            let chunk_data = &data[start..end];

            let chunk_id = ChunkId::from_plaintext(chunk_data);
            let chunk_key = KeySchedule::blob_chunk_key(&blob_key, chunk_id.as_bytes());
            let chunk_nonce = KeySchedule::blob_chunk_nonce(&blob_key, chunk_id.as_bytes());
            let aad = KeySchedule::blob_chunk_aad(blob_id.as_bytes(), chunk_id.as_bytes());

            let ciphertext =
                encrypt_xchacha20poly1305(&chunk_key, &chunk_nonce, chunk_data, &aad)
                    .map_err(|e| StoreError::InvalidData(e.to_string()))?;

            let stored_chunk = StoredChunk::new(chunk_nonce, ciphertext);
            let ciphertext_hash = self.chunk_store.put(&stored_chunk)?;

            let commitment =
                lux_proto::dag::CiphertextCommitment::for_chunk(&ciphertext_hash, stored_chunk.stored_size() as u64);

            let chunk_ref = lux_proto::ChunkRefHashed {
                chunk_id,
                ciphertext_hash,
                commitment,
                offset: start as u64,
                size: (end - start) as u32,
            };

            chunk_refs.push(chunk_ref);
        }

        // Build DAG
        let mut dag_refs: Vec<DagRef> = Vec::new();
        for chunk_ref in chunk_refs {
            let node = DagNode::Chunk(chunk_ref);
            let dag_ref = self.put_dag_node(&node)?;
            dag_refs.push(dag_ref);
        }

        // Create root node (internal node with all chunk refs)
        let root_ref = if dag_refs.is_empty() {
            DagRef::empty()
        } else if dag_refs.len() == 1 {
            dag_refs[0]
        } else {
            let internal = lux_proto::InternalNode::new(dag_refs);
            let node = DagNode::Internal(internal);
            self.put_dag_node(&node)?
        };

        // Store metadata
        let metadata = BlobMetadata {
            root: root_ref,
            size: data.len() as u64,
            chunk_count: boundaries.len().saturating_sub(1) as u32,
        };
        self.put_blob_metadata(&blob_id, &metadata)?;

        Ok(blob_id)
    }

    /// Retrieves a complete blob.
    pub fn get_blob(&self, blob_id: &BlobId) -> Result<Option<Vec<u8>>, StoreError> {
        use lux_core::crypto::{decrypt_xchacha20poly1305, KeySchedule};

        let metadata = match self.get_blob_metadata(blob_id)? {
            Some(m) => m,
            None => return Ok(None),
        };

        if metadata.root.is_empty() {
            return Ok(Some(Vec::new()));
        }

        let blob_key = KeySchedule::blob_key(blob_id.as_bytes());
        let mut data = vec![0u8; metadata.size as usize];

        // Collect all chunk refs from DAG
        let chunk_refs = self.collect_chunk_refs(&metadata.root)?;

        for chunk_ref in chunk_refs {
            let stored_chunk = self
                .chunk_store
                .get(&chunk_ref.ciphertext_hash)?
                .ok_or_else(|| {
                    StoreError::ChunkNotFound(chunk_ref.ciphertext_hash.to_hex())
                })?;

            let chunk_key = KeySchedule::blob_chunk_key(&blob_key, chunk_ref.chunk_id.as_bytes());
            let aad = KeySchedule::blob_chunk_aad(blob_id.as_bytes(), chunk_ref.chunk_id.as_bytes());

            let plaintext = decrypt_xchacha20poly1305(
                &chunk_key,
                &stored_chunk.nonce,
                &stored_chunk.ciphertext_with_tag,
                &aad,
            )
            .map_err(|e| StoreError::InvalidData(e.to_string()))?;

            let start = chunk_ref.offset as usize;
            let end = start + chunk_ref.size as usize;
            if end <= data.len() {
                data[start..end].copy_from_slice(&plaintext);
            }
        }

        Ok(Some(data))
    }

    /// Collects all chunk references from a DAG.
    fn collect_chunk_refs(
        &self,
        dag_ref: &DagRef,
    ) -> Result<Vec<lux_proto::ChunkRefHashed>, StoreError> {
        let mut refs = Vec::new();
        self.collect_chunk_refs_recursive(dag_ref, &mut refs)?;
        Ok(refs)
    }

    fn collect_chunk_refs_recursive(
        &self,
        dag_ref: &DagRef,
        refs: &mut Vec<lux_proto::ChunkRefHashed>,
    ) -> Result<(), StoreError> {
        if dag_ref.is_empty() {
            return Ok(());
        }

        let node = self
            .get_dag_node(dag_ref)?
            .ok_or_else(|| StoreError::InvalidData("Missing DAG node".to_string()))?;

        match node {
            DagNode::Chunk(chunk_ref) => {
                refs.push(chunk_ref);
            }
            DagNode::Internal(internal) => {
                for child in &internal.children {
                    self.collect_chunk_refs_recursive(child, refs)?;
                }
            }
            DagNode::Entry(entry) => {
                self.collect_chunk_refs_recursive(&entry.content, refs)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_blob_store_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();

        let data = b"Hello, Lux! This is a test blob.";
        let blob_id = store.put_blob(data).unwrap();

        let retrieved = store.get_blob(&blob_id).unwrap().unwrap();
        assert_eq!(data.as_slice(), retrieved.as_slice());
    }

    #[test]
    fn test_blob_store_empty() {
        let dir = TempDir::new().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();

        let data = b"";
        let blob_id = store.put_blob(data).unwrap();

        let retrieved = store.get_blob(&blob_id).unwrap().unwrap();
        assert!(retrieved.is_empty());
    }

    #[test]
    fn test_blob_store_large() {
        let dir = TempDir::new().unwrap();
        let store = BlobStore::open(dir.path()).unwrap();

        // Create data larger than min chunk size
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let blob_id = store.put_blob(&data).unwrap();

        let retrieved = store.get_blob(&blob_id).unwrap().unwrap();
        assert_eq!(data, retrieved);
    }
}
