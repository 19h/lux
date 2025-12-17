//! Manifest structure per specification §9.3.
//!
//! The manifest is a signed, encrypted document that represents the current
//! state of a mutable object.

use bytes::{Bytes, BytesMut};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
use lux_core::{CryptoVersion, DagRef, NodeId, ObjectId, RevisionId, Timestamp};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

/// Error during manifest operations.
#[derive(Debug, Error)]
pub enum ManifestError {
    /// Invalid signature
    #[error("Invalid manifest signature")]
    InvalidSignature,

    /// Revision ID not monotonic
    #[error("Revision ID {new} must be greater than {current}")]
    NonMonotonicRevision { current: u64, new: u64 },

    /// Encoding error
    #[error("Encoding error: {0}")]
    Encode(#[from] DecodeError),

    /// Signature error
    #[error("Signature error: {0}")]
    Signature(#[from] lux_core::crypto::SignatureError),
}

/// Identity binding for manifest authorship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBinding {
    /// Public key of the signer
    pub public_key: [u8; 32],
    /// NodeId derived from the public key
    pub node_id: NodeId,
}

impl IdentityBinding {
    /// Creates a new identity binding from a public key.
    pub fn from_public_key(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            node_id: NodeId::from_public_key(&public_key),
        }
    }

    /// Verifies that the node_id matches the public key.
    pub fn verify(&self) -> bool {
        NodeId::from_public_key(&self.public_key) == self.node_id
    }
}

impl CanonicalEncode for IdentityBinding {
    fn encode(&self, buf: &mut BytesMut) {
        self.public_key.encode(buf);
        self.node_id.encode(buf);
    }
}

impl CanonicalDecode for IdentityBinding {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            public_key: <[u8; 32]>::decode(buf)?,
            node_id: NodeId::decode(buf)?,
        })
    }
}

/// The body of a manifest (signed portion).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBody {
    /// Crypto version for offline decryption compatibility
    pub crypto_version: CryptoVersion,
    /// Object identifier
    pub object_id: ObjectId,
    /// Strictly monotonic revision number
    pub revision: RevisionId,
    /// Root of the content DAG
    pub content_root: DagRef,
    /// Creation timestamp
    pub created_at: Timestamp,
    /// Last modification timestamp
    pub modified_at: Timestamp,
    /// Identity of the manifest creator
    pub origin: IdentityBinding,
}

impl ManifestBody {
    /// Creates a new manifest body.
    pub fn new(
        object_id: ObjectId,
        revision: RevisionId,
        content_root: DagRef,
        origin: IdentityBinding,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            crypto_version: CryptoVersion::V1,
            object_id,
            revision,
            content_root,
            created_at: now,
            modified_at: now,
            origin,
        }
    }

    /// Creates a new revision of this manifest.
    pub fn new_revision(&self, content_root: DagRef) -> Self {
        Self {
            crypto_version: self.crypto_version,
            object_id: self.object_id,
            revision: self.revision.increment(),
            content_root,
            created_at: self.created_at,
            modified_at: Timestamp::now(),
            origin: self.origin.clone(),
        }
    }
}

impl CanonicalEncode for ManifestBody {
    fn encode(&self, buf: &mut BytesMut) {
        self.crypto_version.encode(buf);
        self.object_id.encode(buf);
        self.revision.encode(buf);
        self.content_root.encode(buf);
        self.created_at.encode(buf);
        self.modified_at.encode(buf);
        self.origin.encode(buf);
    }
}

impl CanonicalDecode for ManifestBody {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            crypto_version: CryptoVersion::decode(buf)?,
            object_id: ObjectId::decode(buf)?,
            revision: RevisionId::decode(buf)?,
            content_root: DagRef::decode(buf)?,
            created_at: Timestamp::decode(buf)?,
            modified_at: Timestamp::decode(buf)?,
            origin: IdentityBinding::decode(buf)?,
        })
    }
}

/// Complete manifest with signature.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The signed body
    pub body: ManifestBody,
    /// Ed25519 signature over canonical_encode(body)
    #[serde_as(as = "[_; 64]")]
    pub signature: [u8; 64],
}

impl Manifest {
    /// Creates a new signed manifest.
    pub fn new(body: ManifestBody, signing_key: &lux_core::SigningKey) -> Result<Self, ManifestError> {
        let body_bytes = body.to_vec();
        let signature = signing_key.sign(&body_bytes)?;
        Ok(Self { body, signature })
    }

    /// Verifies the manifest signature.
    pub fn verify(&self) -> Result<(), ManifestError> {
        let body_bytes = self.body.to_vec();
        lux_core::crypto::verify_ed25519(&self.body.origin.public_key, &body_bytes, &self.signature)
            .map_err(|_| ManifestError::InvalidSignature)
    }

    /// Returns true if the signature is valid.
    pub fn is_valid(&self) -> bool {
        self.verify().is_ok()
    }

    /// Validates that a new revision is valid given a previous manifest.
    pub fn validate_revision(&self, previous: &Manifest) -> Result<(), ManifestError> {
        // Verify signature
        self.verify()?;

        // Check object ID matches
        if self.body.object_id != previous.body.object_id {
            return Err(ManifestError::NonMonotonicRevision {
                current: previous.body.revision.value(),
                new: self.body.revision.value(),
            });
        }

        // Check revision is strictly greater
        if self.body.revision.value() <= previous.body.revision.value() {
            return Err(ManifestError::NonMonotonicRevision {
                current: previous.body.revision.value(),
                new: self.body.revision.value(),
            });
        }

        // Check same origin (same public key)
        if self.body.origin.public_key != previous.body.origin.public_key {
            return Err(ManifestError::InvalidSignature);
        }

        Ok(())
    }
}

impl CanonicalEncode for Manifest {
    fn encode(&self, buf: &mut BytesMut) {
        self.body.encode(buf);
        self.signature.encode(buf);
    }
}

impl CanonicalDecode for Manifest {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            body: ManifestBody::decode(buf)?,
            signature: <[u8; 64]>::decode(buf)?,
        })
    }
}

/// Encrypted manifest per specification §9.3.
///
/// The manifest is encrypted using XChaCha20-Poly1305 with:
/// - key = manifest_key(CapabilitySecret, ObjectId)
/// - nonce = manifest_nonce(CapabilitySecret, ObjectId, RevisionId)
/// - aad = ObjectId
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedManifest {
    /// 24-byte nonce used for encryption
    pub nonce: [u8; 24],
    /// Encrypted manifest with authentication tag
    pub ciphertext: Vec<u8>,
    /// Object ID (for AAD verification)
    pub object_id: ObjectId,
    /// Revision ID (needed to derive nonce for decryption)
    pub revision_id: RevisionId,
}

impl EncryptedManifest {
    /// Encrypts a manifest for storage/transmission.
    pub fn encrypt(
        manifest: &Manifest,
        capability_secret: &[u8; 32],
    ) -> Result<Self, ManifestError> {
        use lux_core::crypto::{encrypt_xchacha20poly1305, KeySchedule};

        let key = KeySchedule::manifest_key(capability_secret, manifest.body.object_id.as_bytes());
        let nonce = KeySchedule::manifest_nonce(
            capability_secret,
            manifest.body.object_id.as_bytes(),
            manifest.body.revision.value(),
        );
        let aad = KeySchedule::manifest_aad(manifest.body.object_id.as_bytes());

        let plaintext = manifest.to_vec();
        let ciphertext = encrypt_xchacha20poly1305(&key, &nonce, &plaintext, &aad)
            .map_err(|e| ManifestError::Encode(DecodeError::Custom(e.to_string())))?;

        Ok(Self {
            nonce,
            ciphertext,
            object_id: manifest.body.object_id,
            revision_id: manifest.body.revision,
        })
    }

    /// Decrypts a manifest.
    pub fn decrypt(&self, capability_secret: &[u8; 32]) -> Result<Manifest, ManifestError> {
        use lux_core::crypto::{decrypt_xchacha20poly1305, KeySchedule};

        let key = KeySchedule::manifest_key(capability_secret, self.object_id.as_bytes());
        let aad = KeySchedule::manifest_aad(self.object_id.as_bytes());

        let plaintext = decrypt_xchacha20poly1305(&key, &self.nonce, &self.ciphertext, &aad)
            .map_err(|e| ManifestError::Encode(DecodeError::Custom(e.to_string())))?;

        Manifest::from_bytes(&plaintext).map_err(ManifestError::Encode)
    }

    /// Returns the size of the encrypted manifest in bytes.
    pub fn size(&self) -> usize {
        24 + self.ciphertext.len() + 32 + 8
    }
}

impl CanonicalEncode for EncryptedManifest {
    fn encode(&self, buf: &mut BytesMut) {
        self.nonce.encode(buf);
        self.ciphertext.encode(buf);
        self.object_id.encode(buf);
        self.revision_id.encode(buf);
    }
}

impl CanonicalDecode for EncryptedManifest {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            nonce: <[u8; 24]>::decode(buf)?,
            ciphertext: Vec::<u8>::decode(buf)?,
            object_id: ObjectId::decode(buf)?,
            revision_id: RevisionId::decode(buf)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_sign_verify() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);

        let body = ManifestBody::new(
            ObjectId::random(),
            RevisionId::initial(),
            DagRef::empty(),
            origin,
        );

        let manifest = Manifest::new(body, &signing_key).unwrap();
        assert!(manifest.verify().is_ok());
    }

    #[test]
    fn test_manifest_invalid_signature() {
        let signing_key1 = lux_core::SigningKey::random();
        let signing_key2 = lux_core::SigningKey::random();
        let public_key1 = signing_key1.public_key();
        let origin = IdentityBinding::from_public_key(public_key1);

        let body = ManifestBody::new(
            ObjectId::random(),
            RevisionId::initial(),
            DagRef::empty(),
            origin,
        );

        // Sign with wrong key
        let manifest = Manifest::new(body, &signing_key2).unwrap();
        assert!(manifest.verify().is_err());
    }

    #[test]
    fn test_manifest_revision() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);

        let body1 = ManifestBody::new(
            ObjectId::random(),
            RevisionId::initial(),
            DagRef::empty(),
            origin,
        );
        let manifest1 = Manifest::new(body1.clone(), &signing_key).unwrap();

        let body2 = body1.new_revision(DagRef::new([0xFF; 32]));
        let manifest2 = Manifest::new(body2, &signing_key).unwrap();

        assert!(manifest2.validate_revision(&manifest1).is_ok());
        assert_eq!(manifest2.body.revision.value(), 1);
    }

    #[test]
    fn test_manifest_encoding_roundtrip() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);

        let body = ManifestBody::new(
            ObjectId::random(),
            RevisionId::new(42),
            DagRef::new([0xAA; 32]),
            origin,
        );
        let manifest = Manifest::new(body, &signing_key).unwrap();

        let encoded = manifest.to_vec();
        let decoded = Manifest::from_bytes(&encoded).unwrap();

        assert_eq!(manifest.body, decoded.body);
        assert_eq!(manifest.signature, decoded.signature);
        assert!(decoded.verify().is_ok());
    }

    #[test]
    fn test_identity_binding() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();

        let binding = IdentityBinding::from_public_key(public_key);
        assert!(binding.verify());

        // Tampered binding should fail
        let mut bad_binding = binding.clone();
        bad_binding.public_key[0] ^= 0xFF;
        assert!(!bad_binding.verify());
    }

    #[test]
    fn test_encrypted_manifest_roundtrip() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);
        let capability_secret = [0xAAu8; 32];

        let body = ManifestBody::new(
            ObjectId::random(),
            RevisionId::initial(),
            DagRef::empty(),
            origin,
        );
        let manifest = Manifest::new(body, &signing_key).unwrap();

        // Encrypt
        let encrypted = EncryptedManifest::encrypt(&manifest, &capability_secret).unwrap();

        // Decrypt
        let decrypted = encrypted.decrypt(&capability_secret).unwrap();

        assert_eq!(manifest.body, decrypted.body);
        assert_eq!(manifest.signature, decrypted.signature);
        assert!(decrypted.verify().is_ok());
    }

    #[test]
    fn test_encrypted_manifest_wrong_key() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);
        let capability_secret = [0xAAu8; 32];
        let wrong_secret = [0xBBu8; 32];

        let body = ManifestBody::new(
            ObjectId::random(),
            RevisionId::initial(),
            DagRef::empty(),
            origin,
        );
        let manifest = Manifest::new(body, &signing_key).unwrap();

        let encrypted = EncryptedManifest::encrypt(&manifest, &capability_secret).unwrap();

        // Decrypting with wrong key should fail
        assert!(encrypted.decrypt(&wrong_secret).is_err());
    }

    #[test]
    fn test_encrypted_manifest_encoding_roundtrip() {
        let signing_key = lux_core::SigningKey::random();
        let public_key = signing_key.public_key();
        let origin = IdentityBinding::from_public_key(public_key);
        let capability_secret = [0xAAu8; 32];

        let body = ManifestBody::new(
            ObjectId::random(),
            RevisionId::new(42),
            DagRef::new([0xBB; 32]),
            origin,
        );
        let manifest = Manifest::new(body, &signing_key).unwrap();

        let encrypted = EncryptedManifest::encrypt(&manifest, &capability_secret).unwrap();
        let encoded = encrypted.to_vec();
        let decoded = EncryptedManifest::from_bytes(&encoded).unwrap();

        assert_eq!(encrypted.nonce, decoded.nonce);
        assert_eq!(encrypted.ciphertext, decoded.ciphertext);
        assert_eq!(encrypted.object_id, decoded.object_id);
        assert_eq!(encrypted.revision_id, decoded.revision_id);

        // Should still decrypt correctly
        let decrypted = decoded.decrypt(&capability_secret).unwrap();
        assert!(decrypted.verify().is_ok());
    }
}
