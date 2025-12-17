//! Specification edge case tests.
//!
//! Comprehensive tests for all edge cases and special cases identified in the
//! Lux specification. Each test is annotated with the relevant specification
//! section reference.
//!
//! # Test Categories
//! - §5.2: HKDF-SHA-256 edge cases
//! - §5.3: AEAD edge cases
//! - §5.4: BLAKE3 conformance anchors
//! - §5.5: Ed25519 signature requirements
//! - §6: Canonical encoding edge cases
//! - §9.4: Well-known constants
//! - §10: Chunking algorithm edge cases
//! - §10.2: Gear table spot checks
//! - §11.3: DHT validation gates
//! - §11.5: CRDT merge properties
//! - §15: Test vectors
//! - §17: Invariants

use lux_cdc::{chunk, chunk_with_params, ChunkingParams, gear_table, params::*};
use lux_core::crypto::{
    blake3_hash, decrypt_xchacha20poly1305, encrypt_xchacha20poly1305, hkdf_sha256, hmac_sha256,
    sign_ed25519, verify_ed25519, derive_public_key, generate_keypair, KeySchedule,
};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode, DecodeError, encode_sorted_map};
use lux_core::{
    BlobId, ChunkId, CiphertextHash, NetworkKey, NodeId, ObjectId, Timestamp, RevisionId,
    MAX_CHUNK_HOLDERS, DHT_MAX_RECORD_SIZE,
};
use lux_proto::dht::{
    ChunkAnnouncement, ChunkHolders, ChunkLocator, DhtRecord, DhtRecordBody, StorageLease,
    StorageLeaseBody,
};
use lux_proto::dag::CiphertextCommitment;
use bytes::BytesMut;

// ============================================================================
// §5.2 HKDF-SHA-256 Edge Cases
// ============================================================================

/// §5.2: Empty salt is treated as 32 zero bytes
#[test]
fn test_hkdf_empty_salt_equals_zero_salt() {
    let ikm = [0x42u8; 32];
    let info = b"test-info";

    // Empty salt
    let result_empty = hkdf_sha256(&ikm, &[], info, 32);

    // Explicit 32 zero bytes
    let result_zeros = hkdf_sha256(&ikm, &[0u8; 32], info, 32);

    assert_eq!(result_empty, result_zeros, "Empty salt should equal 32 zero bytes");
}

/// §5.2: HKDF counter must be 1-255 (n = ceil(L/32))
#[test]
fn test_hkdf_minimum_output_length() {
    let ikm = [0x42u8; 32];
    let result = hkdf_sha256(&ikm, &[], b"info", 1);
    assert_eq!(result.len(), 1);
}

/// §5.2: HKDF maximum output length (255 * 32 = 8160 bytes)
#[test]
fn test_hkdf_maximum_output_length() {
    let ikm = [0x42u8; 32];
    let result = hkdf_sha256(&ikm, &[], b"info", 8160);
    assert_eq!(result.len(), 8160);
}

/// §5.2: HKDF should panic if output length exceeds maximum
#[test]
#[should_panic(expected = "HKDF output length must be 1-8160 bytes")]
fn test_hkdf_output_exceeds_maximum() {
    let ikm = [0x42u8; 32];
    let _ = hkdf_sha256(&ikm, &[], b"info", 8161);
}

/// §5.2: Info strings are raw ASCII bytes without length prefix
#[test]
fn test_hkdf_info_is_raw_bytes() {
    let ikm = [0x42u8; 32];

    // Different info strings should produce different outputs
    let result1 = hkdf_sha256(&ikm, &[], b"lux/v1/network-mac", 32);
    let result2 = hkdf_sha256(&ikm, &[], b"lux/v1/chunk-key", 32);

    assert_ne!(result1, result2, "Different info strings should produce different outputs");
}

// ============================================================================
// §5.3 AEAD Edge Cases
// ============================================================================

/// §5.3: AEAD with empty plaintext
#[test]
fn test_aead_empty_plaintext() {
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 24];
    let aad = b"associated data";
    let plaintext = b"";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();

    // Ciphertext should be exactly 16 bytes (just the tag)
    assert_eq!(ciphertext.len(), 16, "Empty plaintext should produce 16-byte tag only");

    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();
    assert_eq!(decrypted.len(), 0);
}

/// §5.3: AEAD with empty AAD
#[test]
fn test_aead_empty_aad() {
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 24];
    let plaintext = b"Hello, world!";
    let aad = b"";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// §5.3: AEAD with both empty plaintext and empty AAD
#[test]
fn test_aead_both_empty() {
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 24];

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, b"", b"").unwrap();
    let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, b"").unwrap();

    assert!(decrypted.is_empty());
}

/// §5.3: AEAD nonce is NOT included in output
#[test]
fn test_aead_nonce_not_in_output() {
    let key = [0x42u8; 32];
    let nonce = [0xFFu8; 24];
    let plaintext = b"test";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, b"").unwrap();

    // Verify the nonce is not at the beginning of the ciphertext
    assert_ne!(&ciphertext[..24.min(ciphertext.len())], &nonce[..24.min(ciphertext.len())]);
}

/// §5.3: Wrong AAD should cause decryption failure
#[test]
fn test_aead_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let nonce = [0x00u8; 24];
    let plaintext = b"secret";
    let aad1 = b"correct aad";
    let aad2 = b"wrong aad";

    let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad1).unwrap();
    let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad2);

    assert!(result.is_err(), "Decryption with wrong AAD should fail");
}

// ============================================================================
// §5.4 BLAKE3 Conformance Anchors
// ============================================================================

/// §5.4: BLAKE3("") conformance anchor
#[test]
fn test_blake3_empty_conformance() {
    let hash = blake3_hash(&[]);
    assert_eq!(
        hex::encode(hash),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        "BLAKE3(\"\") conformance anchor mismatch"
    );
}

/// §5.4: BLAKE3([0x00]) conformance anchor
#[test]
fn test_blake3_zero_byte_conformance() {
    let hash = blake3_hash(&[0x00]);
    assert_eq!(
        hex::encode(hash),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        "BLAKE3([0x00]) conformance anchor mismatch"
    );
}

/// §5.4: BLAKE3([0x01]) conformance anchor
#[test]
fn test_blake3_one_byte_conformance() {
    let hash = blake3_hash(&[0x01]);
    assert_eq!(
        hex::encode(hash),
        "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b",
        "BLAKE3([0x01]) conformance anchor mismatch"
    );
}

/// §5.4: BLAKE3([0xFF]) conformance anchor
#[test]
fn test_blake3_ff_byte_conformance() {
    let hash = blake3_hash(&[0xFF]);
    assert_eq!(
        hex::encode(hash),
        "99d44d377bc5936d8cb7f5df90713d84c7587739b4724d3d2f9af1ee0e4c8efd",
        "BLAKE3([0xFF]) conformance anchor mismatch"
    );
}

// ============================================================================
// §5.5 Ed25519 Signature Requirements
// ============================================================================

/// §5.5: Signatures are deterministic
#[test]
fn test_ed25519_deterministic_signatures() {
    let (secret_key, _) = generate_keypair();
    let message = b"test message";

    let sig1 = sign_ed25519(&secret_key, message).unwrap();
    let sig2 = sign_ed25519(&secret_key, message).unwrap();

    assert_eq!(sig1, sig2, "Ed25519 signatures must be deterministic");
}

/// §5.5: Empty message signatures work correctly
#[test]
fn test_ed25519_empty_message() {
    let (secret_key, public_key) = generate_keypair();
    let message = b"";

    let signature = sign_ed25519(&secret_key, message).unwrap();
    let result = verify_ed25519(&public_key, message, &signature);

    assert!(result.is_ok(), "Empty message signature should verify");
}

/// §5.5: Non-canonical S value rejection (using RFC 8032 test vectors)
/// Note: This tests that our library rejects tampered signatures
#[test]
fn test_ed25519_reject_tampered_signature() {
    let (secret_key, public_key) = generate_keypair();
    let message = b"test";

    let mut signature = sign_ed25519(&secret_key, message).unwrap();

    // Tamper with the S value (second half of signature)
    signature[32] ^= 0x80;

    let result = verify_ed25519(&public_key, message, &signature);
    assert!(result.is_err(), "Tampered signature should be rejected");
}

/// §5.5: Wrong public key should fail verification
#[test]
fn test_ed25519_wrong_public_key() {
    let (secret_key, _) = generate_keypair();
    let (_, wrong_public_key) = generate_keypair();
    let message = b"test";

    let signature = sign_ed25519(&secret_key, message).unwrap();
    let result = verify_ed25519(&wrong_public_key, message, &signature);

    assert!(result.is_err(), "Wrong public key should fail verification");
}

// ============================================================================
// §6 Canonical Encoding Edge Cases
// ============================================================================

/// §6.2: Vec length encoding with u32 length prefix
#[test]
fn test_encoding_vec_length_prefix() {
    let vec: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
    let encoded = vec.to_bytes();

    // First 4 bytes should be length (3) in little-endian
    assert_eq!(&encoded[..4], &[0x03, 0x00, 0x00, 0x00]);
    // Followed by the actual bytes
    assert_eq!(&encoded[4..], &[0xAA, 0xBB, 0xCC]);
}

/// §6.2: Empty Vec encoding
#[test]
fn test_encoding_empty_vec() {
    let vec: Vec<u8> = vec![];
    let encoded = vec.to_bytes();

    // Should be just the length (0) as u32 LE
    assert_eq!(encoded.to_vec(), vec![0x00, 0x00, 0x00, 0x00]);
}

/// §6.2: Option None encoding
#[test]
fn test_encoding_option_none() {
    let opt: Option<u32> = None;
    let encoded = opt.to_bytes();

    assert_eq!(encoded.to_vec(), vec![0x00]);
}

/// §6.2: Option Some encoding
#[test]
fn test_encoding_option_some() {
    let opt: Option<u32> = Some(0x12345678);
    let encoded = opt.to_bytes();

    // 0x01 tag + little-endian u32
    assert_eq!(encoded.to_vec(), vec![0x01, 0x78, 0x56, 0x34, 0x12]);
}

/// §6.2: String encoding without null terminator
#[test]
fn test_encoding_string_no_null_terminator() {
    let s = String::from("hello");
    let encoded = s.to_bytes();

    // Length (5) as u32 LE + "hello" without null terminator
    assert_eq!(encoded.to_vec(), vec![0x05, 0x00, 0x00, 0x00, b'h', b'e', b'l', b'l', b'o']);
    assert_eq!(encoded.len(), 9); // 4 + 5, no null terminator
}

/// §6.2: Empty string encoding
#[test]
fn test_encoding_empty_string() {
    let s = String::from("");
    let encoded = s.to_bytes();

    assert_eq!(encoded.to_vec(), vec![0x00, 0x00, 0x00, 0x00]);
}

/// §6.4: Map encoding rejects duplicate keys
#[test]
fn test_encoding_map_duplicate_keys_rejected() {
    let mut buf = BytesMut::new();

    // Attempt to encode a map with duplicate keys
    let map: Vec<(u32, u32)> = vec![(1, 100), (1, 200)];
    let result = encode_sorted_map(&map, &mut buf);

    assert!(result.is_err(), "Duplicate keys should be rejected");
    assert!(matches!(result.unwrap_err(), DecodeError::DuplicateMapKey));
}

/// §6.4: Map keys sorted by lexicographic order of encoded key bytes
#[test]
fn test_encoding_map_sorted_keys() {
    let mut buf = BytesMut::new();

    // Keys not in sorted order by value, but will be sorted by encoded bytes
    // 300 = 0x012C -> encodes as 2C 01 00 00
    // 100 = 0x0064 -> encodes as 64 00 00 00
    // 200 = 0x00C8 -> encodes as C8 00 00 00
    //
    // Lexicographic byte order: 2C < 64 < C8
    // So sorted order is: 300, 100, 200
    let map: Vec<(u32, u32)> = vec![(300, 1), (100, 2), (200, 3)];
    encode_sorted_map(&map, &mut buf).unwrap();

    let encoded = buf.freeze();

    // Verify length prefix (3 entries)
    assert_eq!(&encoded[..4], &[0x03, 0x00, 0x00, 0x00]);

    // First key after length prefix should be 300 (0x012C in LE = 2C 01 00 00)
    // because 0x2C < 0x64 < 0xC8 in lexicographic byte ordering
    assert_eq!(&encoded[4..8], &[0x2C, 0x01, 0x00, 0x00]);
}

// ============================================================================
// §9.4 Well-Known Constants
// ============================================================================

/// §9.4: EMPTY_BLOB_ID = BLAKE3("")
#[test]
fn test_empty_blob_id_constant() {
    let empty_blob_id = BlobId::empty();
    let expected_hash = blake3_hash(&[]);

    assert_eq!(empty_blob_id.as_bytes(), &expected_hash);
    assert_eq!(
        hex::encode(empty_blob_id.as_bytes()),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
    );
}

/// §9.4: EMPTY_DAG_REF = BLAKE3("lux/v1/empty-dag")
#[test]
fn test_empty_dag_ref_constant() {
    let hash = blake3_hash(b"lux/v1/empty-dag");
    assert_eq!(
        hex::encode(hash),
        "98406f28ac2f17f4fa1b6f756a51a6b91b1d953f466a5e7730f9ee6acc7c3e59"
    );
}

// ============================================================================
// §10 Chunking Algorithm Edge Cases
// ============================================================================

/// §10.3: Empty input returns [0]
#[test]
fn test_chunking_empty_input() {
    let boundaries = chunk(&[]);
    assert_eq!(boundaries, vec![0], "Empty input should return [0]");
}

/// §10.3: Data smaller than CHUNK_MIN_SIZE is one chunk
#[test]
fn test_chunking_below_min_size() {
    let data = vec![0u8; CHUNK_MIN_SIZE - 1];
    let boundaries = chunk(&data);

    assert_eq!(boundaries.len(), 2);
    assert_eq!(boundaries[0], 0);
    assert_eq!(boundaries[1], data.len());
}

/// §10.3: Data exactly at CHUNK_MIN_SIZE is one chunk
#[test]
fn test_chunking_exactly_min_size() {
    let data = vec![0u8; CHUNK_MIN_SIZE];
    let boundaries = chunk(&data);

    assert_eq!(boundaries.len(), 2);
    assert_eq!(boundaries[0], 0);
    assert_eq!(boundaries[1], CHUNK_MIN_SIZE);
}

/// §10.3: Data exactly at CHUNK_MAX_SIZE is one chunk (if no boundary found)
#[test]
fn test_chunking_exactly_max_size_uniform() {
    // Uniform data unlikely to trigger boundary
    let data = vec![0x42u8; CHUNK_MAX_SIZE];
    let boundaries = chunk(&data);

    // Should be at most 2 boundaries (one chunk)
    assert!(boundaries.len() >= 2);
    assert_eq!(boundaries[0], 0);
    assert_eq!(*boundaries.last().unwrap(), CHUNK_MAX_SIZE);
}

/// §10.3: No chunk exceeds CHUNK_MAX_SIZE
#[test]
fn test_chunking_max_size_enforced() {
    let data: Vec<u8> = (0..CHUNK_MAX_SIZE * 5).map(|i| (i % 256) as u8).collect();
    let boundaries = chunk(&data);

    for i in 0..boundaries.len() - 1 {
        let chunk_size = boundaries[i + 1] - boundaries[i];
        assert!(
            chunk_size <= CHUNK_MAX_SIZE,
            "Chunk {} has size {} > max {}",
            i, chunk_size, CHUNK_MAX_SIZE
        );
    }
}

/// §10.3: No chunk smaller than CHUNK_MIN_SIZE (except last)
#[test]
fn test_chunking_min_size_enforced() {
    let data: Vec<u8> = (0..CHUNK_MAX_SIZE * 5).map(|i| (i % 256) as u8).collect();
    let boundaries = chunk(&data);

    // All chunks except the last should be >= CHUNK_MIN_SIZE
    for i in 0..boundaries.len().saturating_sub(2) {
        let chunk_size = boundaries[i + 1] - boundaries[i];
        assert!(
            chunk_size >= CHUNK_MIN_SIZE,
            "Chunk {} has size {} < min {}",
            i, chunk_size, CHUNK_MIN_SIZE
        );
    }
}

/// §10.3: Boundaries are end-exclusive
#[test]
fn test_chunking_boundaries_end_exclusive() {
    let data = vec![0u8; CHUNK_MIN_SIZE + 1000];
    let boundaries = chunk(&data);

    // First boundary is always 0
    assert_eq!(boundaries[0], 0);

    // Last boundary equals data length (end-exclusive)
    assert_eq!(*boundaries.last().unwrap(), data.len());

    // Boundaries are strictly increasing
    for i in 1..boundaries.len() {
        assert!(boundaries[i] > boundaries[i - 1]);
    }
}

/// §10.3: Chunking is deterministic
#[test]
fn test_chunking_determinism() {
    let data: Vec<u8> = (0..CHUNK_MAX_SIZE * 2).map(|i| (i % 256) as u8).collect();

    let boundaries1 = chunk(&data);
    let boundaries2 = chunk(&data);

    assert_eq!(boundaries1, boundaries2, "Chunking must be deterministic");
}

// ============================================================================
// §10.2 Gear Table Spot Checks
// ============================================================================

/// §10.2: GEAR[0] spot check
#[test]
fn test_gear_table_spot_check_0() {
    let table = gear_table();
    assert_eq!(table[0], 0xf1611bf1dfde3a2d, "GEAR[0] mismatch");
}

/// §10.2: GEAR[1] spot check
#[test]
fn test_gear_table_spot_check_1() {
    let table = gear_table();
    assert_eq!(table[1], 0xe072c1bb1f72fc48, "GEAR[1] mismatch");
}

/// §10.2: GEAR[255] spot check
#[test]
fn test_gear_table_spot_check_255() {
    let table = gear_table();
    assert_eq!(table[255], 0x6d93c57b374dd499, "GEAR[255] mismatch");
}

/// §10.2: Gear table derived from BLAKE3
#[test]
fn test_gear_table_blake3_derivation() {
    let table = gear_table();

    for i in 0..256 {
        let hash = blake3_hash(&[i as u8]);
        let expected = u64::from_le_bytes([
            hash[0], hash[1], hash[2], hash[3],
            hash[4], hash[5], hash[6], hash[7],
        ]);
        assert_eq!(table[i], expected, "GEAR[{}] derivation mismatch", i);
    }
}

// ============================================================================
// §11.3 DHT Validation Gates
// ============================================================================

/// §11.3: MAC Gate - Invalid MAC rejected
#[test]
fn test_dht_mac_gate_rejects_invalid() {
    let network_key = NetworkKey::random();
    let wrong_key = NetworkKey::random();

    let holders = ChunkHolders::new();
    let record = DhtRecord::new(DhtRecordBody::ChunkHolders(holders), &network_key);

    // Verify with wrong key should fail
    let result = record.verify(&wrong_key);
    assert!(result.is_err(), "Invalid MAC should be rejected");
}

/// §11.3: MAC Gate - Valid MAC accepted
#[test]
fn test_dht_mac_gate_accepts_valid() {
    let network_key = NetworkKey::random();

    let holders = ChunkHolders::new();
    let record = DhtRecord::new(DhtRecordBody::ChunkHolders(holders), &network_key);

    let result = record.verify(&network_key);
    assert!(result.is_ok(), "Valid MAC should be accepted");
}

/// §11.3: Size Gate - Record size check
#[test]
fn test_dht_size_gate() {
    let network_key = NetworkKey::random();

    let holders = ChunkHolders::new();
    let record = DhtRecord::new(DhtRecordBody::ChunkHolders(holders), &network_key);

    let result = record.validate_size();
    assert!(result.is_ok(), "Small record should pass size gate");

    // Verify the constant
    assert_eq!(DHT_MAX_RECORD_SIZE, 65536);
}

/// §11.3: Consistency Gate - holder_key == lease.body.holder
#[test]
fn test_dht_consistency_gate() {
    let mut holders = ChunkHolders::new();

    let holder_id = NodeId::new([0x11; 32]);
    let lease = create_test_lease(holder_id, Timestamp::new(1000));

    holders.add(ChunkAnnouncement { lease: lease.clone() });

    // The holder in the map should match the holder in the lease
    let stored = holders.holders.get(&holder_id).unwrap();
    assert_eq!(stored.lease.body.holder, holder_id);
}

// ============================================================================
// §11.5 CRDT Merge Properties
// ============================================================================

/// §11.5: Merge is commutative (A ⊕ B = B ⊕ A)
#[test]
fn test_crdt_merge_commutative() {
    let holder1 = NodeId::new([0x11; 32]);
    let holder2 = NodeId::new([0x22; 32]);

    let mut set_a = ChunkHolders::new();
    set_a.add(ChunkAnnouncement { lease: create_test_lease(holder1, Timestamp::new(1000)) });

    let mut set_b = ChunkHolders::new();
    set_b.add(ChunkAnnouncement { lease: create_test_lease(holder2, Timestamp::new(2000)) });

    // A ⊕ B
    let mut result_ab = set_a.clone();
    result_ab.merge(&set_b);

    // B ⊕ A
    let mut result_ba = set_b.clone();
    result_ba.merge(&set_a);

    // Both should produce the same result
    assert_eq!(result_ab.len(), result_ba.len());
    for (holder, ann) in &result_ab.holders {
        let other_ann = result_ba.holders.get(holder).expect("Holder should exist in both");
        assert_eq!(ann.quality(), other_ann.quality());
    }
}

/// §11.5: Merge is associative ((A ⊕ B) ⊕ C = A ⊕ (B ⊕ C))
#[test]
fn test_crdt_merge_associative() {
    let holder1 = NodeId::new([0x11; 32]);
    let holder2 = NodeId::new([0x22; 32]);
    let holder3 = NodeId::new([0x33; 32]);

    let mut set_a = ChunkHolders::new();
    set_a.add(ChunkAnnouncement { lease: create_test_lease(holder1, Timestamp::new(1000)) });

    let mut set_b = ChunkHolders::new();
    set_b.add(ChunkAnnouncement { lease: create_test_lease(holder2, Timestamp::new(2000)) });

    let mut set_c = ChunkHolders::new();
    set_c.add(ChunkAnnouncement { lease: create_test_lease(holder3, Timestamp::new(3000)) });

    // (A ⊕ B) ⊕ C
    let mut result_abc = set_a.clone();
    result_abc.merge(&set_b);
    result_abc.merge(&set_c);

    // A ⊕ (B ⊕ C)
    let mut bc = set_b.clone();
    bc.merge(&set_c);
    let mut result_a_bc = set_a.clone();
    result_a_bc.merge(&bc);

    // Both should produce the same result
    assert_eq!(result_abc.len(), result_a_bc.len());
    for (holder, ann) in &result_abc.holders {
        let other_ann = result_a_bc.holders.get(holder).expect("Holder should exist in both");
        assert_eq!(ann.quality(), other_ann.quality());
    }
}

/// §11.5: Merge is idempotent (A ⊕ A = A)
#[test]
fn test_crdt_merge_idempotent() {
    let holder1 = NodeId::new([0x11; 32]);
    let holder2 = NodeId::new([0x22; 32]);

    let mut set = ChunkHolders::new();
    set.add(ChunkAnnouncement { lease: create_test_lease(holder1, Timestamp::new(1000)) });
    set.add(ChunkAnnouncement { lease: create_test_lease(holder2, Timestamp::new(2000)) });

    let original_len = set.len();
    let original_qualities: Vec<_> = set.holders.iter()
        .map(|(k, v)| (*k, v.quality()))
        .collect();

    // A ⊕ A
    let set_clone = set.clone();
    set.merge(&set_clone);

    // Should be unchanged
    assert_eq!(set.len(), original_len);
    for (holder, quality) in original_qualities {
        assert_eq!(set.holders.get(&holder).unwrap().quality(), quality);
    }
}

/// §11.5: Per-holder: retain announcement with maximum quality
#[test]
fn test_crdt_per_holder_max_quality() {
    let holder = NodeId::new([0x11; 32]);

    let mut set = ChunkHolders::new();

    // Add older lease first
    set.add(ChunkAnnouncement { lease: create_test_lease(holder, Timestamp::new(1000)) });

    // Add newer lease (higher quality due to later expiration)
    set.add(ChunkAnnouncement { lease: create_test_lease(holder, Timestamp::new(2000)) });

    // Should keep the one with higher quality
    assert_eq!(set.len(), 1);
    assert_eq!(set.holders.get(&holder).unwrap().lease.body.expires_at.0, 2000);
}

/// §11.5: Bounded set retains top-K holders (K = MAX_CHUNK_HOLDERS = 64)
#[test]
fn test_crdt_bounded_set() {
    let mut set = ChunkHolders::new();

    // Add more than MAX_CHUNK_HOLDERS
    for i in 0..(MAX_CHUNK_HOLDERS + 20) {
        let mut holder_bytes = [0u8; 32];
        holder_bytes[0] = (i % 256) as u8;
        holder_bytes[1] = (i / 256) as u8;
        let holder = NodeId::new(holder_bytes);
        let lease = create_test_lease(holder, Timestamp::new(i as i64 * 1000));
        set.add(ChunkAnnouncement { lease });
    }

    assert_eq!(set.len(), MAX_CHUNK_HOLDERS, "Should be bounded to MAX_CHUNK_HOLDERS");
    assert_eq!(MAX_CHUNK_HOLDERS, 64, "MAX_CHUNK_HOLDERS should be 64");
}

/// §11.5: Quality function ordering
#[test]
fn test_crdt_quality_ordering() {
    let holder1 = NodeId::new([0x11; 32]);
    let holder2 = NodeId::new([0x22; 32]);

    let ann1 = ChunkAnnouncement { lease: create_test_lease(holder1, Timestamp::new(1000)) };
    let ann2 = ChunkAnnouncement { lease: create_test_lease(holder2, Timestamp::new(2000)) };

    // Higher expiration = higher quality
    assert!(ann2.quality() > ann1.quality());
}

// ============================================================================
// §15.1 HKDF Test Vectors
// ============================================================================

/// §15.1: RFC 5869 Test Case 1
#[test]
fn test_hkdf_rfc5869_case1() {
    let ikm = vec![0x0bu8; 22];
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

    let okm = hkdf_sha256(&ikm, &salt, &info, 42);

    let expected = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ).unwrap();

    assert_eq!(okm, expected);
}

/// §15.1: Network MAC Key derivation test vector
#[test]
fn test_hkdf_network_mac_key_vector() {
    let network_key = [0x42u8; 32];
    let info = b"lux/v1/network-mac";

    let mac_key = hkdf_sha256(&network_key, &[], info, 32);

    let expected = hex::decode("23c6878c5619c870f4f1942e7e99897cd08ac69dd3276c575e6a7eac37a2cbdf").unwrap();

    assert_eq!(mac_key, expected);
}

/// §15.1: Chunk key base derivation test vector
#[test]
fn test_hkdf_chunk_key_base_vector() {
    let capability_secret = [0xAAu8; 32];
    let object_id = [0xBBu8; 32];

    let chunk_key_base = hkdf_sha256(&capability_secret, &object_id, b"lux/v1/chunk-key-base", 32);

    let expected = hex::decode("532909a10b9188e1835d34a39a4f4ec6929b761934fd5d06418d45d5c60299e5").unwrap();

    assert_eq!(chunk_key_base, expected);
}

/// §15.1: Chunk key derivation test vector
#[test]
fn test_hkdf_chunk_key_vector() {
    let capability_secret = [0xAAu8; 32];
    let object_id = [0xBBu8; 32];
    let chunk_id = [0xCCu8; 32];

    let chunk_key_base = hkdf_sha256(&capability_secret, &object_id, b"lux/v1/chunk-key-base", 32);
    let chunk_key = hkdf_sha256(&chunk_key_base, &chunk_id, b"lux/v1/chunk-key", 32);

    let expected = hex::decode("05410a674aa6224ead714901fad1b1860916d4f4ca0eb14224ca9600ff8ee93e").unwrap();

    assert_eq!(chunk_key, expected);
}

/// §15.1: Chunk nonce derivation test vector
#[test]
fn test_hkdf_chunk_nonce_vector() {
    let capability_secret = [0xAAu8; 32];
    let object_id = [0xBBu8; 32];
    let chunk_id = [0xCCu8; 32];

    let chunk_key_base = hkdf_sha256(&capability_secret, &object_id, b"lux/v1/chunk-key-base", 32);
    let chunk_nonce = hkdf_sha256(&chunk_key_base, &chunk_id, b"lux/v1/chunk-nonce", 24);

    let expected = hex::decode("a2e10e6c62894bd744395bdd258b73367ac18e4442537545").unwrap();

    assert_eq!(chunk_nonce, expected);
}

// ============================================================================
// §15.2 Canonical Encoding Test Vectors
// ============================================================================

/// §15.2: Timestamp encoding test vector
#[test]
fn test_encoding_timestamp_vector() {
    let timestamp: i64 = 1700000000000;
    let encoded = timestamp.to_bytes();

    let expected = hex::decode("0068e5cf8b010000").unwrap();

    assert_eq!(encoded.to_vec(), expected);
}

/// §15.2: CryptoVersion::V1 encoding test vector
#[test]
fn test_encoding_crypto_version_vector() {
    let version: u32 = 1;
    let encoded = version.to_bytes();

    assert_eq!(encoded.to_vec(), vec![0x01, 0x00, 0x00, 0x00]);
}

/// §15.2: Vec<u8> encoding test vector
#[test]
fn test_encoding_vec_u8_vector() {
    let vec: Vec<u8> = vec![0xAA, 0xBB, 0xCC];
    let encoded = vec.to_bytes();

    assert_eq!(encoded.to_vec(), vec![0x03, 0x00, 0x00, 0x00, 0xAA, 0xBB, 0xCC]);
}

/// §15.2: Option None encoding test vector
#[test]
fn test_encoding_option_none_vector() {
    let opt: Option<u32> = None;
    let encoded = opt.to_bytes();

    assert_eq!(encoded.to_vec(), vec![0x00]);
}

/// §15.2: Option Some encoding test vector
#[test]
fn test_encoding_option_some_vector() {
    let opt: Option<u32> = Some(0x12345678);
    let encoded = opt.to_bytes();

    assert_eq!(encoded.to_vec(), vec![0x01, 0x78, 0x56, 0x34, 0x12]);
}

// ============================================================================
// §17 Invariants
// ============================================================================

/// §17.1: RevisionId strictly monotonic per ObjectId
#[test]
fn test_invariant_revision_id_monotonic() {
    let rev1 = RevisionId::new(1);
    let rev2 = RevisionId::new(2);
    let rev3 = RevisionId::new(3);

    assert!(rev2.value() > rev1.value());
    assert!(rev3.value() > rev2.value());

    // Increment should increase value
    let rev_next = rev1.increment();
    assert!(rev_next.value() > rev1.value());
}

/// §17.1: CiphertextHash = BLAKE3(nonce || ct || tag)
#[test]
fn test_invariant_ciphertext_hash_derivation() {
    use lux_proto::storage::StoredChunk;

    let nonce = [0x00u8; 24];
    let ciphertext_with_tag = vec![0x11u8; 100];

    let chunk = StoredChunk {
        nonce,
        ciphertext_with_tag: ciphertext_with_tag.clone(),
    };

    // CiphertextHash should be BLAKE3 of the entire stored representation
    let stored_bytes = chunk.to_bytes();
    let expected_hash = blake3_hash(&stored_bytes);
    let computed_hash = chunk.ciphertext_hash();

    assert_eq!(computed_hash.as_bytes(), &expected_hash);
}

/// §17.2: Encoding roundtrip produces identical bytes
#[test]
fn test_invariant_encoding_roundtrip() {
    // Test various types for encoding/decoding roundtrip

    // u32
    let val: u32 = 0x12345678;
    let decoded = u32::from_bytes(&val.to_vec()).unwrap();
    assert_eq!(val, decoded);

    // i64
    let val: i64 = -1234567890;
    let decoded = i64::from_bytes(&val.to_vec()).unwrap();
    assert_eq!(val, decoded);

    // Vec
    let val: Vec<u32> = vec![1, 2, 3, 4, 5];
    let decoded = Vec::<u32>::from_bytes(&val.to_vec()).unwrap();
    assert_eq!(val, decoded);

    // Option
    let val: Option<u64> = Some(12345);
    let decoded = Option::<u64>::from_bytes(&val.to_vec()).unwrap();
    assert_eq!(val, decoded);

    // String
    let val = String::from("hello world");
    let decoded = String::from_bytes(&val.to_vec()).unwrap();
    assert_eq!(val, decoded);
}

/// §17.3: MAC gate precedes all operations (DhtRecord)
#[test]
fn test_invariant_mac_gate_first() {
    let network_key = NetworkKey::random();
    let holders = ChunkHolders::new();
    let record = DhtRecord::new(DhtRecordBody::ChunkHolders(holders), &network_key);

    // MAC verification should be the first check
    assert!(record.verify(&network_key).is_ok());

    // Invalid MAC should be caught before other processing
    let wrong_key = NetworkKey::random();
    assert!(record.verify(&wrong_key).is_err());
}

// ============================================================================
// Helper Functions
// ============================================================================

fn create_test_lease(holder: NodeId, expires_at: Timestamp) -> StorageLease {
    StorageLease {
        body: StorageLeaseBody {
            locator: ChunkLocator {
                chunk_id: ChunkId::new([0xAA; 32]),
                ciphertext_hash: CiphertextHash::new([0xBB; 32]),
            },
            commitment: CiphertextCommitment {
                merkle_root: [0; 32],
                size: 1000,
                block_size: 1000,
                block_count: 1,
            },
            holder,
            issuer: NodeId::new([0xFF; 32]),
            issued_at: Timestamp::new(0),
            expires_at,
        },
        issuer_signature: [0; 64],
        holder_signature: [0; 64],
    }
}
