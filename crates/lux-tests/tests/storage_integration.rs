//! Storage integration tests.
//!
//! Tests for the storage layer including:
//! - Chunk storage and retrieval
//! - Blob encryption/decryption workflows
//! - Storage persistence

use lux_core::{BlobId, ChunkId, CiphertextHash};
use lux_proto::blob::{BlobEncryptor, verify_chunk_integrity};
use lux_proto::storage::StoredChunk;
use lux_tests::node::TestNodeConfig;
use lux_tests::TestNode;

/// Initialize tracing for tests.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("lux_tests=debug,lux_store=debug")
        .with_test_writer()
        .try_init();
}

#[tokio::test]
async fn test_chunk_store_basic() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    // Create a test chunk
    let plaintext = b"Hello, this is test data for chunk storage!";
    let chunk_id = ChunkId::from_plaintext(plaintext);

    // Encrypt using convergent encryption
    let chunks: Vec<&[u8]> = vec![plaintext.as_slice()];
    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Store the chunk
    node.store_chunk(&encrypted.chunks[0]).unwrap();

    // Retrieve and verify
    let retrieved = node.get_chunk(&encrypted.chunk_refs[0].ciphertext_hash)
        .unwrap()
        .expect("Chunk should exist");

    assert!(verify_chunk_integrity(&retrieved, &encrypted.chunk_refs[0].ciphertext_hash));
}

#[tokio::test]
async fn test_chunk_store_multiple() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    // Create multiple chunks
    let data1 = b"First chunk of test data";
    let data2 = b"Second chunk with different content";
    let data3 = b"Third chunk completes the set";

    let chunks: Vec<&[u8]> = vec![
        data1.as_slice(),
        data2.as_slice(),
        data3.as_slice(),
    ];

    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Store all chunks
    for chunk in &encrypted.chunks {
        node.store_chunk(chunk).unwrap();
    }

    // Verify all chunks can be retrieved
    for (i, chunk_ref) in encrypted.chunk_refs.iter().enumerate() {
        let retrieved = node.get_chunk(&chunk_ref.ciphertext_hash)
            .unwrap()
            .expect(&format!("Chunk {} should exist", i));

        assert!(verify_chunk_integrity(&retrieved, &chunk_ref.ciphertext_hash));
    }
}

#[tokio::test]
async fn test_chunk_store_not_found() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    // Try to get a non-existent chunk
    let fake_hash = CiphertextHash::new([0xFF; 32]);
    let result = node.get_chunk(&fake_hash).unwrap();

    assert!(result.is_none(), "Non-existent chunk should return None");
}

#[tokio::test]
async fn test_chunk_store_overwrite() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    // Store same content twice (should work via dedup)
    let data = b"Content that will be stored twice";
    let chunks: Vec<&[u8]> = vec![data.as_slice()];
    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Store twice
    node.store_chunk(&encrypted.chunks[0]).unwrap();
    node.store_chunk(&encrypted.chunks[0]).unwrap();

    // Should still retrieve correctly
    let retrieved = node.get_chunk(&encrypted.chunk_refs[0].ciphertext_hash)
        .unwrap()
        .expect("Chunk should exist");

    assert!(verify_chunk_integrity(&retrieved, &encrypted.chunk_refs[0].ciphertext_hash));
}

#[tokio::test]
async fn test_blob_encryption_roundtrip() {
    init_tracing();

    let original_data = b"Complete blob data that will be chunked, encrypted, stored, retrieved, and decrypted";

    // Encrypt
    let chunks: Vec<&[u8]> = vec![original_data.as_slice()];
    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Decrypt each chunk and reassemble
    let mut decrypted = Vec::new();
    for (chunk, chunk_ref) in encrypted.chunks.iter().zip(&encrypted.chunk_refs) {
        let plaintext = BlobEncryptor::decrypt_chunk(
            &encrypted.blob_id,
            &chunk_ref.chunk_id,
            chunk,
        ).unwrap();
        decrypted.extend(plaintext);
    }

    assert_eq!(original_data.as_slice(), decrypted.as_slice());
}

#[tokio::test]
async fn test_blob_convergent_encryption() {
    init_tracing();

    let data = b"Same content encrypted twice";

    // Encrypt same content twice
    let chunks1: Vec<&[u8]> = vec![data.as_slice()];
    let chunks2: Vec<&[u8]> = vec![data.as_slice()];

    let encrypted1 = BlobEncryptor::encrypt(&chunks1).unwrap();
    let encrypted2 = BlobEncryptor::encrypt(&chunks2).unwrap();

    // BlobId should be identical (convergent)
    assert_eq!(encrypted1.blob_id, encrypted2.blob_id);

    // Ciphertext should be identical (deterministic)
    assert_eq!(
        encrypted1.chunks[0].ciphertext_with_tag,
        encrypted2.chunks[0].ciphertext_with_tag
    );
}

#[tokio::test]
async fn test_blob_different_content_different_encryption() {
    init_tracing();

    let data1 = b"First blob content";
    let data2 = b"Second blob content";

    let chunks1: Vec<&[u8]> = vec![data1.as_slice()];
    let chunks2: Vec<&[u8]> = vec![data2.as_slice()];

    let encrypted1 = BlobEncryptor::encrypt(&chunks1).unwrap();
    let encrypted2 = BlobEncryptor::encrypt(&chunks2).unwrap();

    // BlobIds should differ
    assert_ne!(encrypted1.blob_id, encrypted2.blob_id);

    // Ciphertext should differ
    assert_ne!(
        encrypted1.chunks[0].ciphertext_with_tag,
        encrypted2.chunks[0].ciphertext_with_tag
    );
}

#[tokio::test]
async fn test_empty_blob() {
    init_tracing();

    let chunks: Vec<&[u8]> = vec![];
    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Empty blob should have special values
    assert_eq!(encrypted.blob_id, BlobId::empty());
    assert!(encrypted.chunks.is_empty());
    assert!(encrypted.dag_nodes.is_empty());
}

#[tokio::test]
async fn test_large_blob_chunking() {
    init_tracing();

    // Create a larger dataset (3 MB to guarantee multiple chunks)
    // CHUNK_MAX_SIZE is 1MB, so this should produce at least 3 chunks
    let large_data: Vec<u8> = (0..3_000_000u64).map(|i| (i % 256) as u8).collect();

    // Use FastCDC to chunk
    let boundaries = lux_cdc::chunk(&large_data);

    // Create chunks from boundaries
    let mut chunks_data: Vec<&[u8]> = Vec::new();
    for i in 0..boundaries.len() - 1 {
        chunks_data.push(&large_data[boundaries[i]..boundaries[i + 1]]);
    }

    // Encrypt
    let encrypted = BlobEncryptor::encrypt(&chunks_data).unwrap();

    // Should produce multiple chunks
    assert!(encrypted.chunks.len() > 1, "Large data should produce multiple chunks");

    // Decrypt and verify
    let mut decrypted = Vec::new();
    for (chunk, chunk_ref) in encrypted.chunks.iter().zip(&encrypted.chunk_refs) {
        let plaintext = BlobEncryptor::decrypt_chunk(
            &encrypted.blob_id,
            &chunk_ref.chunk_id,
            chunk,
        ).unwrap();
        decrypted.extend(plaintext);
    }

    assert_eq!(large_data, decrypted);
}

#[tokio::test]
async fn test_chunk_offsets() {
    init_tracing();

    let chunk1 = vec![0u8; 1000];
    let chunk2 = vec![1u8; 2000];
    let chunk3 = vec![2u8; 500];

    let chunks: Vec<&[u8]> = vec![
        chunk1.as_slice(),
        chunk2.as_slice(),
        chunk3.as_slice(),
    ];

    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Verify offsets
    assert_eq!(encrypted.chunk_refs[0].offset, 0);
    assert_eq!(encrypted.chunk_refs[0].size, 1000);

    assert_eq!(encrypted.chunk_refs[1].offset, 1000);
    assert_eq!(encrypted.chunk_refs[1].size, 2000);

    assert_eq!(encrypted.chunk_refs[2].offset, 3000);
    assert_eq!(encrypted.chunk_refs[2].size, 500);
}

#[tokio::test]
async fn test_chunk_integrity_detection() {
    init_tracing();

    let data = b"Original data";
    let chunks: Vec<&[u8]> = vec![data.as_slice()];
    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Tamper with the chunk
    let mut tampered = encrypted.chunks[0].clone();
    tampered.ciphertext_with_tag[0] ^= 0xFF;

    // Verify original passes
    assert!(verify_chunk_integrity(&encrypted.chunks[0], &encrypted.chunk_refs[0].ciphertext_hash));

    // Verify tampered fails
    assert!(!verify_chunk_integrity(&tampered, &encrypted.chunk_refs[0].ciphertext_hash));
}

#[tokio::test]
async fn test_store_and_retrieve_workflow() {
    init_tracing();

    let config = TestNodeConfig::default();
    let node = TestNode::new(config).await.unwrap();
    node.start().await.unwrap();

    // Full workflow: create, encrypt, store, retrieve, decrypt, verify
    let original = b"This is a complete storage workflow test";

    // Encrypt
    let chunks: Vec<&[u8]> = vec![original.as_slice()];
    let encrypted = BlobEncryptor::encrypt(&chunks).unwrap();

    // Store all chunks
    for chunk in &encrypted.chunks {
        node.store_chunk(chunk).unwrap();
    }

    // Retrieve and decrypt
    let mut reconstructed = Vec::new();
    for chunk_ref in &encrypted.chunk_refs {
        let stored = node.get_chunk(&chunk_ref.ciphertext_hash)
            .unwrap()
            .expect("Stored chunk should exist");

        let plaintext = BlobEncryptor::decrypt_chunk(
            &encrypted.blob_id,
            &chunk_ref.chunk_id,
            &stored,
        ).unwrap();

        reconstructed.extend(plaintext);
    }

    assert_eq!(original.as_slice(), reconstructed.as_slice());
}
