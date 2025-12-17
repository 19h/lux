//! XChaCha20-Poly1305 AEAD implementation per specification §5.3.
//!
//! Provides authenticated encryption with associated data for:
//! - Chunk encryption
//! - Manifest encryption
//! - Blob chunk encryption

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use thiserror::Error;

use super::{KEY_SIZE, NONCE_SIZE, TAG_SIZE};

/// Errors that can occur during AEAD operations.
#[derive(Debug, Error)]
pub enum AeadError {
    /// Invalid key length (must be 32 bytes)
    #[error("Invalid key length: expected {KEY_SIZE} bytes, got {0}")]
    InvalidKeyLength(usize),

    /// Invalid nonce length (must be 24 bytes)
    #[error("Invalid nonce length: expected {NONCE_SIZE} bytes, got {0}")]
    InvalidNonceLength(usize),

    /// Encryption failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Decryption failed (authentication tag mismatch)
    #[error("Decryption failed: authentication tag mismatch")]
    DecryptionFailed,

    /// Ciphertext too short (must contain at least the tag)
    #[error("Ciphertext too short: expected at least {TAG_SIZE} bytes, got {0}")]
    CiphertextTooShort(usize),
}

/// Encrypts plaintext using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce (must be unique per key)
/// * `plaintext` - Data to encrypt
/// * `aad` - Additional authenticated data (not encrypted, but authenticated)
///
/// # Returns
/// Ciphertext concatenated with 16-byte authentication tag
///
/// # Note
/// The nonce is NOT included in the output per specification §5.3.
/// Callers must manage nonce storage separately.
pub fn encrypt_xchacha20poly1305(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if key.len() != KEY_SIZE {
        return Err(AeadError::InvalidKeyLength(key.len()));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(AeadError::InvalidNonceLength(nonce.len()));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength(key.len()))?;

    let nonce = XNonce::from_slice(nonce);
    let payload = Payload { msg: plaintext, aad };

    cipher
        .encrypt(nonce, payload)
        .map_err(|_| AeadError::EncryptionFailed)
}

/// Decrypts ciphertext using XChaCha20-Poly1305.
///
/// # Arguments
/// * `key` - 32-byte encryption key
/// * `nonce` - 24-byte nonce used during encryption
/// * `ciphertext_with_tag` - Ciphertext concatenated with 16-byte authentication tag
/// * `aad` - Additional authenticated data (must match encryption)
///
/// # Returns
/// Decrypted plaintext on success, or error if authentication fails
pub fn decrypt_xchacha20poly1305(
    key: &[u8],
    nonce: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if key.len() != KEY_SIZE {
        return Err(AeadError::InvalidKeyLength(key.len()));
    }
    if nonce.len() != NONCE_SIZE {
        return Err(AeadError::InvalidNonceLength(nonce.len()));
    }
    if ciphertext_with_tag.len() < TAG_SIZE {
        return Err(AeadError::CiphertextTooShort(ciphertext_with_tag.len()));
    }

    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength(key.len()))?;

    let nonce = XNonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| AeadError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"Hello, Lux!";
        let aad = b"additional data";

        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key() {
        let key1 = [0x42u8; KEY_SIZE];
        let key2 = [0x43u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"Hello, Lux!";
        let aad = b"additional data";

        let ciphertext = encrypt_xchacha20poly1305(&key1, &nonce, plaintext, aad).unwrap();
        let result = decrypt_xchacha20poly1305(&key2, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(AeadError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_wrong_aad() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"Hello, Lux!";
        let aad1 = b"additional data 1";
        let aad2 = b"additional data 2";

        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad1).unwrap();
        let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad2);
        assert!(matches!(result, Err(AeadError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"Hello, Lux!";
        let aad = b"additional data";

        let mut ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
        ciphertext[0] ^= 0xFF; // Tamper with ciphertext

        let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad);
        assert!(matches!(result, Err(AeadError::DecryptionFailed)));
    }

    #[test]
    fn test_decrypt_truncated_tag() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"Hello, Lux!";
        let aad = b"additional data";

        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
        // Truncate to less than TAG_SIZE
        let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext[..10], aad);
        assert!(matches!(result, Err(AeadError::CiphertextTooShort(_))));
    }

    #[test]
    fn test_large_plaintext() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = vec![0xAB; 1024 * 1024]; // 1MB
        let aad = b"large data test";

        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, &plaintext, aad).unwrap();
        let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let key = [0x42u8; KEY_SIZE];
        let nonce1 = [0x01u8; NONCE_SIZE];
        let nonce2 = [0x02u8; NONCE_SIZE];
        let plaintext = b"Same plaintext";
        let aad = b"";

        let ciphertext1 = encrypt_xchacha20poly1305(&key, &nonce1, plaintext, aad).unwrap();
        let ciphertext2 = encrypt_xchacha20poly1305(&key, &nonce2, plaintext, aad).unwrap();
        assert_ne!(ciphertext1, ciphertext2);
    }

    #[test]
    fn test_aad_is_authenticated() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"Secret message";
        let aad = b"authenticated but not encrypted";

        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();

        // AAD is not encrypted, but modifying it should fail decryption
        let modified_aad = b"modified authenticated data";
        let result = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, modified_aad);
        assert!(matches!(result, Err(AeadError::DecryptionFailed)));
    }

    #[test]
    fn test_empty_plaintext() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; NONCE_SIZE];
        let plaintext = b"";
        let aad = b"";

        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, plaintext, aad).unwrap();
        assert_eq!(ciphertext.len(), TAG_SIZE);

        let decrypted = decrypt_xchacha20poly1305(&key, &nonce, &ciphertext, aad).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_invalid_key_length() {
        let key = [0x42u8; 16]; // Wrong size
        let nonce = [0x01u8; NONCE_SIZE];

        let result = encrypt_xchacha20poly1305(&key, &nonce, b"test", b"");
        assert!(matches!(result, Err(AeadError::InvalidKeyLength(16))));
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x01u8; 12]; // Wrong size

        let result = encrypt_xchacha20poly1305(&key, &nonce, b"test", b"");
        assert!(matches!(result, Err(AeadError::InvalidNonceLength(12))));
    }
}
