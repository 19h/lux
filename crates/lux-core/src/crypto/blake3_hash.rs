//! BLAKE3 hash implementation per specification §5.4.
//!
//! BLAKE3 is used in default hash mode with 256-bit output for:
//! - Content addressing (ChunkId, BlobId, DagRef)
//! - Ciphertext hashing (CiphertextHash)
//! - Node identity derivation

/// Computes BLAKE3 hash in default mode with 256-bit output.
///
/// # Arguments
/// * `data` - Data to hash
///
/// # Returns
/// 32-byte hash output
///
/// # Example
/// ```
/// use lux_core::crypto::blake3_hash;
///
/// // BLAKE3("") conformance anchor
/// let hash = blake3_hash(&[]);
/// let expected = hex::decode("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262").unwrap();
/// assert_eq!(hash.as_slice(), expected.as_slice());
/// ```
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Computes BLAKE3 hash incrementally using a hasher.
///
/// Useful for hashing large data that cannot fit in memory.
pub struct Blake3Hasher {
    inner: blake3::Hasher,
}

impl Blake3Hasher {
    /// Creates a new BLAKE3 hasher.
    pub fn new() -> Self {
        Self {
            inner: blake3::Hasher::new(),
        }
    }

    /// Updates the hasher with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalizes the hash and returns the 32-byte output.
    pub fn finalize(self) -> [u8; 32] {
        *self.inner.finalize().as_bytes()
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Conformance anchors from §5.4
    #[test]
    fn test_blake3_conformance_anchors() {
        // BLAKE3("")
        let hash_empty = blake3_hash(&[]);
        assert_eq!(
            hex::encode(hash_empty),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );

        // BLAKE3([0x00])
        let hash_00 = blake3_hash(&[0x00]);
        assert_eq!(
            hex::encode(hash_00),
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213"
        );

        // BLAKE3([0x01])
        let hash_01 = blake3_hash(&[0x01]);
        assert_eq!(
            hex::encode(hash_01),
            "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"
        );

        // BLAKE3([0xFF])
        let hash_ff = blake3_hash(&[0xFF]);
        assert_eq!(
            hex::encode(hash_ff),
            "99d44d377bc5936d8cb7f5df90713d84c7587739b4724d3d2f9af1ee0e4c8efd"
        );
    }

    /// Well-known constant from §9.4: EMPTY_BLOB_ID
    #[test]
    fn test_empty_blob_id() {
        let hash = blake3_hash(&[]);
        assert_eq!(
            hex::encode(hash),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    /// Well-known constant from §9.4: EMPTY_DAG_REF
    #[test]
    fn test_empty_dag_ref() {
        let hash = blake3_hash(b"lux/v1/empty-dag");
        assert_eq!(
            hex::encode(hash),
            "98406f28ac2f17f4fa1b6f756a51a6b91b1d953f466a5e7730f9ee6acc7c3e59"
        );
    }

    #[test]
    fn test_incremental_hasher() {
        let data = b"Hello, World!";

        // Single-shot
        let hash1 = blake3_hash(data);

        // Incremental
        let mut hasher = Blake3Hasher::new();
        hasher.update(b"Hello, ");
        hasher.update(b"World!");
        let hash2 = hasher.finalize();

        assert_eq!(hash1, hash2);
    }
}
