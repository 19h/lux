//! Blob encryption and DAG construction per specification §13.
//!
//! Implements convergent encryption for content-addressed blobs:
//! - Content is split into chunks using FastCDC
//! - Each chunk is encrypted with a key derived from the BlobId
//! - BlobId = BLAKE3(full_plaintext) per specification §13.1
//! - This enables deduplication while maintaining encryption

use lux_core::crypto::{encrypt_xchacha20poly1305, decrypt_xchacha20poly1305, KeySchedule};
use lux_core::{BlobId, ChunkId, CiphertextHash, DagRef};
use thiserror::Error;

use crate::dag::{ChunkRefHashed, CiphertextCommitment, DagNode, InternalNode};
use crate::storage::StoredChunk;

/// Error during blob operations.
#[derive(Debug, Error)]
pub enum BlobError {
    /// Encryption failed
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    Decryption(String),

    /// Invalid chunk
    #[error("Invalid chunk: {0}")]
    InvalidChunk(String),

    /// DAG construction error
    #[error("DAG construction error: {0}")]
    DagError(String),
}

/// Result of encrypting a blob.
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    /// The blob identifier (hash of the DAG root)
    pub blob_id: BlobId,
    /// The DAG root reference
    pub dag_root: DagRef,
    /// All DAG nodes (leaves and internal nodes)
    pub dag_nodes: Vec<DagNode>,
    /// All encrypted chunks
    pub chunks: Vec<StoredChunk>,
    /// Chunk references with hashes
    pub chunk_refs: Vec<ChunkRefHashed>,
}

/// Result of encrypting a single chunk.
#[derive(Debug, Clone)]
pub struct EncryptedChunk {
    /// The plaintext ChunkId
    pub chunk_id: ChunkId,
    /// The encrypted stored chunk
    pub stored_chunk: StoredChunk,
    /// The ciphertext hash (storage address)
    pub ciphertext_hash: CiphertextHash,
}

/// Blob encryption using convergent encryption per specification §13.
pub struct BlobEncryptor;

impl BlobEncryptor {
    /// Encrypts a blob using convergent encryption.
    ///
    /// This is a two-pass algorithm per specification §13.1:
    /// 1. Compute BlobId = BLAKE3(full_plaintext) by hashing all chunks
    /// 2. Compute ChunkIds for all chunks to build the DAG
    /// 3. Encrypt chunks using keys derived from BlobId
    ///
    /// # Arguments
    /// * `chunks` - The plaintext chunks (from FastCDC or similar)
    ///
    /// # Returns
    /// The encrypted blob with DAG structure
    pub fn encrypt(chunks: &[&[u8]]) -> Result<EncryptedBlob, BlobError> {
        if chunks.is_empty() {
            return Self::encrypt_empty();
        }

        // First: compute BlobId = BLAKE3(full_plaintext) per specification §13.1
        // We use incremental hashing to avoid concatenating all chunks in memory
        let mut hasher = blake3::Hasher::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        let blob_id = BlobId::new(*hasher.finalize().as_bytes());

        // Encrypt chunks using blob-derived keys
        let blob_key = KeySchedule::blob_key(blob_id.as_bytes());
        let mut encrypted_chunks = Vec::with_capacity(chunks.len());
        let mut chunk_refs = Vec::with_capacity(chunks.len());

        let mut offset = 0u64;
        for chunk in chunks.iter() {
            let chunk_id = ChunkId::from_plaintext(chunk);

            // Derive per-chunk key and nonce
            let key = KeySchedule::blob_chunk_key(&blob_key, chunk_id.as_bytes());
            let nonce = KeySchedule::blob_chunk_nonce(&blob_key, chunk_id.as_bytes());

            // Construct AAD
            let aad = KeySchedule::blob_chunk_aad(blob_id.as_bytes(), chunk_id.as_bytes());

            // Encrypt
            let ciphertext_with_tag = encrypt_xchacha20poly1305(&key, &nonce, chunk, &aad)
                .map_err(|e| BlobError::Encryption(e.to_string()))?;

            let stored_chunk = StoredChunk::new(nonce, ciphertext_with_tag);
            let ciphertext_hash = stored_chunk.ciphertext_hash();

            // Create chunk reference
            let chunk_ref = ChunkRefHashed {
                chunk_id,
                ciphertext_hash,
                commitment: CiphertextCommitment::for_chunk(&ciphertext_hash, stored_chunk.stored_size() as u64),
                offset,
                size: chunk.len() as u32,
            };

            encrypted_chunks.push(stored_chunk);
            chunk_refs.push(chunk_ref);
            offset += chunk.len() as u64;
        }

        // Rebuild DAG with actual ciphertext hashes
        let (final_dag_root, final_dag_nodes) = Self::build_dag_with_refs(&chunk_refs)?;

        Ok(EncryptedBlob {
            blob_id,
            dag_root: final_dag_root,
            dag_nodes: final_dag_nodes,
            chunks: encrypted_chunks,
            chunk_refs,
        })
    }

    /// Encrypts an empty blob.
    ///
    /// Per specification §9.4: EMPTY_BLOB_ID = BLAKE3("") = af1349b9...
    fn encrypt_empty() -> Result<EncryptedBlob, BlobError> {
        let dag_root = DagRef::empty();
        // BlobId = BLAKE3("") per specification §13.1 and §9.4
        let blob_id = BlobId::empty();

        Ok(EncryptedBlob {
            blob_id,
            dag_root,
            dag_nodes: Vec::new(),
            chunks: Vec::new(),
            chunk_refs: Vec::new(),
        })
    }

    /// Builds the DAG with actual chunk references.
    fn build_dag_with_refs(chunk_refs: &[ChunkRefHashed]) -> Result<(DagRef, Vec<DagNode>), BlobError> {
        if chunk_refs.is_empty() {
            return Ok((DagRef::empty(), Vec::new()));
        }

        if chunk_refs.len() == 1 {
            let leaf = DagNode::Chunk(chunk_refs[0].clone());
            let dag_ref = leaf.dag_ref();
            return Ok((dag_ref, vec![leaf]));
        }

        // Create leaf nodes and collect their refs
        let mut nodes = Vec::new();
        let mut child_refs = Vec::new();

        for chunk_ref in chunk_refs {
            let leaf = DagNode::Chunk(chunk_ref.clone());
            let dag_ref = leaf.dag_ref();
            child_refs.push(dag_ref);
            nodes.push(leaf);
        }

        // Create root internal node
        let root_node = DagNode::Internal(InternalNode::new(child_refs));
        let dag_root = root_node.dag_ref();
        nodes.push(root_node);

        Ok((dag_root, nodes))
    }

    /// Encrypts a single chunk using convergent encryption.
    ///
    /// # Arguments
    /// * `blob_id` - The blob identifier (for key derivation)
    /// * `plaintext` - The plaintext chunk data
    ///
    /// # Returns
    /// The encrypted chunk with metadata
    pub fn encrypt_chunk(blob_id: &BlobId, plaintext: &[u8]) -> Result<EncryptedChunk, BlobError> {
        let chunk_id = ChunkId::from_plaintext(plaintext);
        let blob_key = KeySchedule::blob_key(blob_id.as_bytes());

        let key = KeySchedule::blob_chunk_key(&blob_key, chunk_id.as_bytes());
        let nonce = KeySchedule::blob_chunk_nonce(&blob_key, chunk_id.as_bytes());
        let aad = KeySchedule::blob_chunk_aad(blob_id.as_bytes(), chunk_id.as_bytes());

        let ciphertext_with_tag = encrypt_xchacha20poly1305(&key, &nonce, plaintext, &aad)
            .map_err(|e| BlobError::Encryption(e.to_string()))?;

        let stored_chunk = StoredChunk::new(nonce, ciphertext_with_tag);
        let ciphertext_hash = stored_chunk.ciphertext_hash();

        Ok(EncryptedChunk {
            chunk_id,
            stored_chunk,
            ciphertext_hash,
        })
    }

    /// Decrypts a single chunk.
    ///
    /// # Arguments
    /// * `blob_id` - The blob identifier (for key derivation)
    /// * `chunk_id` - The expected plaintext ChunkId
    /// * `stored_chunk` - The encrypted chunk
    ///
    /// # Returns
    /// The decrypted plaintext
    pub fn decrypt_chunk(
        blob_id: &BlobId,
        chunk_id: &ChunkId,
        stored_chunk: &StoredChunk,
    ) -> Result<Vec<u8>, BlobError> {
        let blob_key = KeySchedule::blob_key(blob_id.as_bytes());

        let key = KeySchedule::blob_chunk_key(&blob_key, chunk_id.as_bytes());
        let aad = KeySchedule::blob_chunk_aad(blob_id.as_bytes(), chunk_id.as_bytes());

        let plaintext = decrypt_xchacha20poly1305(
            &key,
            &stored_chunk.nonce,
            &stored_chunk.ciphertext_with_tag,
            &aad,
        )
        .map_err(|e| BlobError::Decryption(e.to_string()))?;

        // Verify ChunkId matches
        let computed_chunk_id = ChunkId::from_plaintext(&plaintext);
        if computed_chunk_id != *chunk_id {
            return Err(BlobError::InvalidChunk(format!(
                "ChunkId mismatch: expected {}, got {}",
                chunk_id, computed_chunk_id
            )));
        }

        Ok(plaintext)
    }
}

/// Verifies that a stored chunk matches its expected CiphertextHash.
pub fn verify_chunk_integrity(stored_chunk: &StoredChunk, expected_hash: &CiphertextHash) -> bool {
    stored_chunk.ciphertext_hash() == *expected_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_single_chunk() {
        let data = b"Hello, this is test data for blob encryption!";
        let chunks: Vec<&[u8]> = vec![data.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        assert_eq!(result.chunks.len(), 1);
        assert_eq!(result.chunk_refs.len(), 1);
        assert!(!result.dag_nodes.is_empty());
    }

    #[test]
    fn test_encrypt_multiple_chunks() {
        let chunk1 = b"First chunk of data";
        let chunk2 = b"Second chunk of data";
        let chunk3 = b"Third chunk of data";
        let chunks: Vec<&[u8]> = vec![chunk1.as_slice(), chunk2.as_slice(), chunk3.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        assert_eq!(result.chunks.len(), 3);
        assert_eq!(result.chunk_refs.len(), 3);
    }

    #[test]
    fn test_encrypt_empty_blob() {
        let chunks: Vec<&[u8]> = vec![];
        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        assert!(result.chunks.is_empty());
        assert!(result.dag_nodes.is_empty());
        assert_eq!(result.dag_root, DagRef::empty());
    }

    /// Verifies BlobId = BLAKE3("") per specification §9.4 for empty blobs.
    #[test]
    fn test_empty_blob_id_matches_spec() {
        let chunks: Vec<&[u8]> = vec![];
        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        // Per specification §9.4: EMPTY_BLOB_ID = BLAKE3("") = af1349b9...
        assert_eq!(result.blob_id, BlobId::empty());
        assert_eq!(
            result.blob_id.to_hex(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    /// Verifies BlobId = BLAKE3(full_plaintext) per specification §13.1.
    #[test]
    fn test_blob_id_is_hash_of_plaintext() {
        let chunk1 = b"Hello, ";
        let chunk2 = b"World!";
        let chunks: Vec<&[u8]> = vec![chunk1.as_slice(), chunk2.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        // BlobId should be BLAKE3 of the concatenated plaintext
        let full_plaintext = b"Hello, World!";
        let expected_blob_id = BlobId::from_plaintext(full_plaintext);

        assert_eq!(result.blob_id, expected_blob_id);
    }

    /// Verifies that different chunking of same plaintext produces same BlobId.
    #[test]
    fn test_different_chunking_same_blob_id() {
        let plaintext = b"The quick brown fox jumps over the lazy dog";

        // One chunk
        let chunks1: Vec<&[u8]> = vec![plaintext.as_slice()];
        let result1 = BlobEncryptor::encrypt(&chunks1).unwrap();

        // Split into multiple chunks
        let chunks2: Vec<&[u8]> = vec![
            &plaintext[..10],
            &plaintext[10..30],
            &plaintext[30..],
        ];
        let result2 = BlobEncryptor::encrypt(&chunks2).unwrap();

        // BlobId should be the same regardless of chunking
        assert_eq!(result1.blob_id, result2.blob_id);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Test data for roundtrip encryption test";
        let chunks: Vec<&[u8]> = vec![plaintext.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        // Decrypt
        let decrypted = BlobEncryptor::decrypt_chunk(
            &result.blob_id,
            &result.chunk_refs[0].chunk_id,
            &result.chunks[0],
        )
        .unwrap();

        assert_eq!(decrypted.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt_multiple_chunks_roundtrip() {
        let chunk1 = b"First chunk";
        let chunk2 = b"Second chunk";
        let chunks: Vec<&[u8]> = vec![chunk1.as_slice(), chunk2.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        // Decrypt each chunk
        let decrypted1 = BlobEncryptor::decrypt_chunk(
            &result.blob_id,
            &result.chunk_refs[0].chunk_id,
            &result.chunks[0],
        )
        .unwrap();

        let decrypted2 = BlobEncryptor::decrypt_chunk(
            &result.blob_id,
            &result.chunk_refs[1].chunk_id,
            &result.chunks[1],
        )
        .unwrap();

        assert_eq!(decrypted1.as_slice(), chunk1.as_slice());
        assert_eq!(decrypted2.as_slice(), chunk2.as_slice());
    }

    #[test]
    fn test_convergent_encryption_same_content() {
        let data = b"Identical content for deduplication test";

        // Encrypt same content twice
        let chunks1: Vec<&[u8]> = vec![data.as_slice()];
        let chunks2: Vec<&[u8]> = vec![data.as_slice()];

        let result1 = BlobEncryptor::encrypt(&chunks1).unwrap();
        let result2 = BlobEncryptor::encrypt(&chunks2).unwrap();

        // Same content should produce same BlobId
        assert_eq!(result1.blob_id, result2.blob_id);

        // Same content should produce same ciphertext (deterministic encryption)
        assert_eq!(result1.chunks[0].nonce, result2.chunks[0].nonce);
        assert_eq!(
            result1.chunks[0].ciphertext_with_tag,
            result2.chunks[0].ciphertext_with_tag
        );
    }

    #[test]
    fn test_different_content_different_ciphertext() {
        let data1 = b"Content A";
        let data2 = b"Content B";

        let chunks1: Vec<&[u8]> = vec![data1.as_slice()];
        let chunks2: Vec<&[u8]> = vec![data2.as_slice()];

        let result1 = BlobEncryptor::encrypt(&chunks1).unwrap();
        let result2 = BlobEncryptor::encrypt(&chunks2).unwrap();

        // Different content should produce different BlobIds
        assert_ne!(result1.blob_id, result2.blob_id);

        // Different content should produce different ciphertext
        assert_ne!(
            result1.chunks[0].ciphertext_with_tag,
            result2.chunks[0].ciphertext_with_tag
        );
    }

    #[test]
    fn test_chunk_integrity_verification() {
        let data = b"Test data";
        let chunks: Vec<&[u8]> = vec![data.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        // Verify correct hash
        assert!(verify_chunk_integrity(
            &result.chunks[0],
            &result.chunk_refs[0].ciphertext_hash
        ));

        // Verify wrong hash fails
        let wrong_hash = CiphertextHash::new([0xFF; 32]);
        assert!(!verify_chunk_integrity(&result.chunks[0], &wrong_hash));
    }

    #[test]
    fn test_decrypt_with_wrong_blob_id_fails() {
        let plaintext = b"Test data";
        let chunks: Vec<&[u8]> = vec![plaintext.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        // Try to decrypt with wrong BlobId
        let wrong_blob_id = BlobId::new([0xFF; 32]);
        let decrypt_result = BlobEncryptor::decrypt_chunk(
            &wrong_blob_id,
            &result.chunk_refs[0].chunk_id,
            &result.chunks[0],
        );

        assert!(decrypt_result.is_err());
    }

    #[test]
    fn test_chunk_offsets_computed_correctly() {
        let chunk1 = vec![0u8; 100];
        let chunk2 = vec![0u8; 200];
        let chunk3 = vec![0u8; 150];
        let chunks: Vec<&[u8]> = vec![chunk1.as_slice(), chunk2.as_slice(), chunk3.as_slice()];

        let result = BlobEncryptor::encrypt(&chunks).unwrap();

        assert_eq!(result.chunk_refs[0].offset, 0);
        assert_eq!(result.chunk_refs[0].size, 100);

        assert_eq!(result.chunk_refs[1].offset, 100);
        assert_eq!(result.chunk_refs[1].size, 200);

        assert_eq!(result.chunk_refs[2].offset, 300);
        assert_eq!(result.chunk_refs[2].size, 150);
    }
}
