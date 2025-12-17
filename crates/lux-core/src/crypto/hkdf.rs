//! HKDF-SHA-256 implementation per RFC 5869 and specification §5.2.
//!
//! Key derivation function used throughout Lux for deriving:
//! - Network MAC keys
//! - Manifest encryption keys and nonces
//! - Chunk encryption keys and nonces
//! - Blob encryption keys and nonces

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA-256 of a message using the given key.
///
/// # Arguments
/// * `key` - The HMAC key
/// * `message` - The message to authenticate
///
/// # Returns
/// 32-byte MAC output
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// HKDF-SHA-256 key derivation as specified in RFC 5869 and §5.2.
///
/// # Arguments
/// * `ikm` - Input keying material
/// * `salt` - Optional salt value (empty salt treated as 32 zero bytes per spec)
/// * `info` - Context and application specific information (raw ASCII bytes)
/// * `length` - Length of output keying material (1-8160 bytes)
///
/// # Returns
/// Derived key material of the requested length
///
/// # Panics
/// Panics if length is 0 or exceeds 8160 bytes (255 * 32)
///
/// # Example
/// ```
/// use lux_core::crypto::hkdf_sha256;
///
/// let ikm = [0x0bu8; 22];
/// let salt = hex::decode("000102030405060708090a0b0c").unwrap();
/// let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
/// let okm = hkdf_sha256(&ikm, &salt, &info, 42);
///
/// let expected = hex::decode(
///     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
/// ).unwrap();
/// assert_eq!(okm, expected);
/// ```
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let n = (length + 31) / 32;
    assert!(n >= 1 && n <= 255, "HKDF output length must be 1-8160 bytes");

    // Extract: PRK = HMAC(salt, IKM)
    // Empty salt treated as 32 zero bytes per specification
    let prk = if salt.is_empty() {
        hmac_sha256(&[0u8; 32], ikm)
    } else {
        hmac_sha256(salt, ikm)
    };

    // Expand: T(i) = HMAC(PRK, T(i-1) || info || i)
    let mut output = Vec::with_capacity(length);
    let mut t = Vec::new();

    for i in 1..=n {
        let mut message = t.clone();
        message.extend_from_slice(info);
        message.push(i as u8);
        t = hmac_sha256(&prk, &message).to_vec();
        output.extend_from_slice(&t);
    }

    output.truncate(length);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5869 Test Case 1 from §15.1
    #[test]
    fn test_rfc5869_case1() {
        let ikm = vec![0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let okm = hkdf_sha256(&ikm, &salt, &info, 42);

        let expected = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        assert_eq!(okm, expected);
    }

    /// Network MAC key derivation from §15.1
    #[test]
    fn test_network_mac_key() {
        let network_key = [0x42u8; 32];
        let info = b"lux/v1/network-mac";

        let mac_key = hkdf_sha256(&network_key, &[], info, 32);

        let expected =
            hex::decode("23c6878c5619c870f4f1942e7e99897cd08ac69dd3276c575e6a7eac37a2cbdf")
                .unwrap();

        assert_eq!(mac_key, expected);
    }

    /// Chunk key derivation from §15.1
    #[test]
    fn test_chunk_key_derivation() {
        let capability_secret = [0xAAu8; 32];
        let object_id = [0xBBu8; 32];
        let chunk_id = [0xCCu8; 32];

        // Derive chunk_key_base
        let chunk_key_base = hkdf_sha256(&capability_secret, &object_id, b"lux/v1/chunk-key-base", 32);
        let expected_base =
            hex::decode("532909a10b9188e1835d34a39a4f4ec6929b761934fd5d06418d45d5c60299e5")
                .unwrap();
        assert_eq!(chunk_key_base, expected_base);

        // Derive chunk_key
        let chunk_key = hkdf_sha256(&chunk_key_base, &chunk_id, b"lux/v1/chunk-key", 32);
        let expected_key =
            hex::decode("05410a674aa6224ead714901fad1b1860916d4f4ca0eb14224ca9600ff8ee93e")
                .unwrap();
        assert_eq!(chunk_key, expected_key);

        // Derive chunk_nonce
        let chunk_nonce = hkdf_sha256(&chunk_key_base, &chunk_id, b"lux/v1/chunk-nonce", 24);
        let expected_nonce =
            hex::decode("a2e10e6c62894bd744395bdd258b73367ac18e4442537545").unwrap();
        assert_eq!(chunk_nonce, expected_nonce);
    }
}
