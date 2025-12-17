//! Key schedule implementation per specification §8.
//!
//! Provides key derivation for all encryption contexts:
//! - Network MAC keys
//! - Manifest encryption keys and nonces
//! - Chunk encryption keys and nonces
//! - Blob encryption keys and nonces

use super::hkdf::hkdf_sha256;

/// Derivation info constants per specification §8.1
pub mod info {
    /// Info string for network MAC key derivation
    pub const NETWORK_MAC: &[u8] = b"lux/v1/network-mac";
    /// Info string for manifest encryption key
    pub const MANIFEST_KEY: &[u8] = b"lux/v1/manifest-key";
    /// Info string for manifest encryption nonce
    pub const MANIFEST_NONCE: &[u8] = b"lux/v1/manifest-nonce";
    /// Info string for chunk key base derivation
    pub const CHUNK_KEY_BASE: &[u8] = b"lux/v1/chunk-key-base";
    /// Info string for chunk encryption key
    pub const CHUNK_KEY: &[u8] = b"lux/v1/chunk-key";
    /// Info string for chunk encryption nonce
    pub const CHUNK_NONCE: &[u8] = b"lux/v1/chunk-nonce";
    /// Info string for blob encryption key
    pub const BLOB_KEY: &[u8] = b"lux/v1/blob-key";
    /// Info string for blob encryption nonce
    pub const BLOB_NONCE: &[u8] = b"lux/v1/blob-nonce";
}

/// Key schedule for deriving all cryptographic keys in Lux.
///
/// Implements the key derivation table from specification §8.2.
pub struct KeySchedule;

impl KeySchedule {
    /// Derives the network MAC key from a NetworkKey.
    ///
    /// Used to authenticate DHT records per specification §11.1.
    ///
    /// ```text
    /// network_mac_key = HKDF(NetworkKey, salt=∅, info="lux/v1/network-mac", L=32)
    /// ```
    pub fn network_mac_key(network_key: &[u8; 32]) -> [u8; 32] {
        let result = hkdf_sha256(network_key, &[], info::NETWORK_MAC, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derives the manifest encryption key from a CapabilitySecret and ObjectId.
    ///
    /// ```text
    /// manifest_key = HKDF(CapabilitySecret, salt=ObjectId, info="lux/v1/manifest-key", L=32)
    /// ```
    pub fn manifest_key(capability_secret: &[u8; 32], object_id: &[u8; 32]) -> [u8; 32] {
        let result = hkdf_sha256(capability_secret, object_id, info::MANIFEST_KEY, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derives the manifest encryption nonce from CapabilitySecret, ObjectId, and RevisionId.
    ///
    /// The RevisionId ensures unique nonces across revisions.
    ///
    /// ```text
    /// manifest_nonce = HKDF(CapabilitySecret, salt=ObjectId‖RevisionId, info="lux/v1/manifest-nonce", L=24)
    /// ```
    pub fn manifest_nonce(
        capability_secret: &[u8; 32],
        object_id: &[u8; 32],
        revision_id: u64,
    ) -> [u8; 24] {
        let mut salt = [0u8; 40];
        salt[..32].copy_from_slice(object_id);
        salt[32..].copy_from_slice(&revision_id.to_le_bytes());

        let result = hkdf_sha256(capability_secret, &salt, info::MANIFEST_NONCE, 24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&result);
        nonce
    }

    /// Derives the chunk key base from CapabilitySecret and ObjectId.
    ///
    /// This intermediate key is used to derive per-chunk keys.
    ///
    /// ```text
    /// chunk_key_base = HKDF(CapabilitySecret, salt=ObjectId, info="lux/v1/chunk-key-base", L=32)
    /// ```
    pub fn chunk_key_base(capability_secret: &[u8; 32], object_id: &[u8; 32]) -> [u8; 32] {
        let result = hkdf_sha256(capability_secret, object_id, info::CHUNK_KEY_BASE, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derives a chunk encryption key from the chunk key base and ChunkId.
    ///
    /// ```text
    /// chunk_key = HKDF(chunk_key_base, salt=ChunkId, info="lux/v1/chunk-key", L=32)
    /// ```
    pub fn chunk_key(chunk_key_base: &[u8; 32], chunk_id: &[u8; 32]) -> [u8; 32] {
        let result = hkdf_sha256(chunk_key_base, chunk_id, info::CHUNK_KEY, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derives a chunk encryption nonce from the chunk key base and ChunkId.
    ///
    /// ```text
    /// chunk_nonce = HKDF(chunk_key_base, salt=ChunkId, info="lux/v1/chunk-nonce", L=24)
    /// ```
    pub fn chunk_nonce(chunk_key_base: &[u8; 32], chunk_id: &[u8; 32]) -> [u8; 24] {
        let result = hkdf_sha256(chunk_key_base, chunk_id, info::CHUNK_NONCE, 24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&result);
        nonce
    }

    /// Derives the blob encryption key from a BlobId (convergent encryption).
    ///
    /// ```text
    /// blob_key = HKDF(BlobId, salt=∅, info="lux/v1/blob-key", L=32)
    /// ```
    pub fn blob_key(blob_id: &[u8; 32]) -> [u8; 32] {
        let result = hkdf_sha256(blob_id, &[], info::BLOB_KEY, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derives a blob chunk encryption key from blob_key and ChunkId.
    ///
    /// ```text
    /// blob_chunk_key = HKDF(blob_key, salt=ChunkId, info="lux/v1/chunk-key", L=32)
    /// ```
    pub fn blob_chunk_key(blob_key: &[u8; 32], chunk_id: &[u8; 32]) -> [u8; 32] {
        let result = hkdf_sha256(blob_key, chunk_id, info::CHUNK_KEY, 32);
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    /// Derives a blob chunk encryption nonce from blob_key and ChunkId.
    ///
    /// ```text
    /// blob_chunk_nonce = HKDF(blob_key, salt=ChunkId, info="lux/v1/chunk-nonce", L=24)
    /// ```
    pub fn blob_chunk_nonce(blob_key: &[u8; 32], chunk_id: &[u8; 32]) -> [u8; 24] {
        let result = hkdf_sha256(blob_key, chunk_id, info::CHUNK_NONCE, 24);
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&result);
        nonce
    }

    /// Constructs AAD for manifest encryption per specification §8.3.
    ///
    /// AAD = ObjectId (32 bytes)
    pub fn manifest_aad(object_id: &[u8; 32]) -> [u8; 32] {
        *object_id
    }

    /// Constructs AAD for object chunk encryption per specification §8.3.
    ///
    /// AAD = ObjectId ‖ ChunkId (64 bytes)
    pub fn object_chunk_aad(object_id: &[u8; 32], chunk_id: &[u8; 32]) -> [u8; 64] {
        let mut aad = [0u8; 64];
        aad[..32].copy_from_slice(object_id);
        aad[32..].copy_from_slice(chunk_id);
        aad
    }

    /// Constructs AAD for blob chunk encryption per specification §8.3.
    ///
    /// AAD = BlobId ‖ ChunkId (64 bytes)
    pub fn blob_chunk_aad(blob_id: &[u8; 32], chunk_id: &[u8; 32]) -> [u8; 64] {
        let mut aad = [0u8; 64];
        aad[..32].copy_from_slice(blob_id);
        aad[32..].copy_from_slice(chunk_id);
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_mac_key() {
        let network_key = [0x42u8; 32];
        let mac_key = KeySchedule::network_mac_key(&network_key);
        let expected =
            hex::decode("23c6878c5619c870f4f1942e7e99897cd08ac69dd3276c575e6a7eac37a2cbdf")
                .unwrap();
        assert_eq!(mac_key.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_chunk_key_derivation() {
        let capability_secret = [0xAAu8; 32];
        let object_id = [0xBBu8; 32];
        let chunk_id = [0xCCu8; 32];

        let chunk_key_base = KeySchedule::chunk_key_base(&capability_secret, &object_id);
        let expected_base =
            hex::decode("532909a10b9188e1835d34a39a4f4ec6929b761934fd5d06418d45d5c60299e5")
                .unwrap();
        assert_eq!(chunk_key_base.as_slice(), expected_base.as_slice());

        let chunk_key = KeySchedule::chunk_key(&chunk_key_base, &chunk_id);
        let expected_key =
            hex::decode("05410a674aa6224ead714901fad1b1860916d4f4ca0eb14224ca9600ff8ee93e")
                .unwrap();
        assert_eq!(chunk_key.as_slice(), expected_key.as_slice());

        let chunk_nonce = KeySchedule::chunk_nonce(&chunk_key_base, &chunk_id);
        let expected_nonce =
            hex::decode("a2e10e6c62894bd744395bdd258b73367ac18e4442537545").unwrap();
        assert_eq!(chunk_nonce.as_slice(), expected_nonce.as_slice());
    }

    #[test]
    fn test_aad_sizes() {
        let object_id = [0u8; 32];
        let chunk_id = [0u8; 32];
        let blob_id = [0u8; 32];

        assert_eq!(KeySchedule::manifest_aad(&object_id).len(), 32);
        assert_eq!(
            KeySchedule::object_chunk_aad(&object_id, &chunk_id).len(),
            64
        );
        assert_eq!(KeySchedule::blob_chunk_aad(&blob_id, &chunk_id).len(), 64);
    }
}
