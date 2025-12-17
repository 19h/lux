//! Lux URI schemes per specification §2.3.
//!
//! Defines the URI formats for addressing content:
//! - `lux:blob:<base64url(BlobId)>` - Immutable blob URIs
//! - `lux:obj:<base64url(ObjectId)>:<base64url(CapabilitySecret)>[:<RevisionId>]` - Mutable object URIs

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use lux_core::{BlobId, CapabilitySecret, ObjectId, RevisionId};
use thiserror::Error;

/// Error parsing Lux URIs.
#[derive(Debug, Error)]
pub enum UriParseError {
    /// Missing scheme prefix
    #[error("Missing 'lux:' scheme prefix")]
    MissingScheme,

    /// Invalid URI type
    #[error("Invalid URI type: expected 'blob' or 'obj', got '{0}'")]
    InvalidType(String),

    /// Missing required component
    #[error("Missing required component: {0}")]
    MissingComponent(&'static str),

    /// Invalid base64 encoding
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(#[from] base64::DecodeError),

    /// Invalid length for component
    #[error("Invalid {component} length: expected {expected} bytes, got {actual}")]
    InvalidLength {
        component: &'static str,
        expected: usize,
        actual: usize,
    },

    /// Invalid revision ID
    #[error("Invalid revision ID: {0}")]
    InvalidRevision(#[from] std::num::ParseIntError),
}

/// A Lux URI (either blob or object).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuxUri {
    /// Immutable blob URI
    Blob(BlobUri),
    /// Mutable object URI
    Object(ObjectUri),
}

impl LuxUri {
    /// Parses a Lux URI string.
    pub fn parse(s: &str) -> Result<Self, UriParseError> {
        if !s.starts_with("lux:") {
            return Err(UriParseError::MissingScheme);
        }

        let rest = &s[4..];

        if rest.starts_with("blob:") {
            Ok(LuxUri::Blob(BlobUri::parse(s)?))
        } else if rest.starts_with("obj:") {
            Ok(LuxUri::Object(ObjectUri::parse(s)?))
        } else {
            let type_end = rest.find(':').unwrap_or(rest.len());
            Err(UriParseError::InvalidType(rest[..type_end].to_string()))
        }
    }

    /// Returns the URI as a string.
    pub fn to_string(&self) -> String {
        match self {
            LuxUri::Blob(blob) => blob.to_string(),
            LuxUri::Object(obj) => obj.to_string(),
        }
    }
}

impl std::fmt::Display for LuxUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl std::str::FromStr for LuxUri {
    type Err = UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Immutable blob URI: `lux:blob:<base64url(BlobId)>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobUri {
    /// The blob identifier
    pub blob_id: BlobId,
}

impl BlobUri {
    /// Creates a new blob URI.
    pub fn new(blob_id: BlobId) -> Self {
        Self { blob_id }
    }

    /// Parses a blob URI string.
    pub fn parse(s: &str) -> Result<Self, UriParseError> {
        if !s.starts_with("lux:blob:") {
            return Err(UriParseError::MissingScheme);
        }

        let encoded = &s[9..];
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;

        if bytes.len() != 32 {
            return Err(UriParseError::InvalidLength {
                component: "BlobId",
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self {
            blob_id: BlobId::new(arr),
        })
    }

    /// Returns the URI as a string.
    pub fn to_string(&self) -> String {
        format!("lux:blob:{}", URL_SAFE_NO_PAD.encode(self.blob_id.0))
    }
}

impl std::fmt::Display for BlobUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Mutable object URI: `lux:obj:<ObjectId>:<CapabilitySecret>[:<RevisionId>]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectUri {
    /// The object identifier
    pub object_id: ObjectId,
    /// The decryption capability
    pub capability_secret: CapabilitySecret,
    /// Optional specific revision
    pub revision: Option<RevisionId>,
}

impl ObjectUri {
    /// Creates a new object URI without a revision.
    pub fn new(object_id: ObjectId, capability_secret: CapabilitySecret) -> Self {
        Self {
            object_id,
            capability_secret,
            revision: None,
        }
    }

    /// Creates a new object URI with a specific revision.
    pub fn with_revision(
        object_id: ObjectId,
        capability_secret: CapabilitySecret,
        revision: RevisionId,
    ) -> Self {
        Self {
            object_id,
            capability_secret,
            revision: Some(revision),
        }
    }

    /// Parses an object URI string.
    pub fn parse(s: &str) -> Result<Self, UriParseError> {
        if !s.starts_with("lux:obj:") {
            return Err(UriParseError::MissingScheme);
        }

        let rest = &s[8..];
        let parts: Vec<&str> = rest.split(':').collect();

        if parts.len() < 2 {
            return Err(UriParseError::MissingComponent("CapabilitySecret"));
        }

        // Parse ObjectId
        let object_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
        if object_bytes.len() != 32 {
            return Err(UriParseError::InvalidLength {
                component: "ObjectId",
                expected: 32,
                actual: object_bytes.len(),
            });
        }
        let mut object_arr = [0u8; 32];
        object_arr.copy_from_slice(&object_bytes);
        let object_id = ObjectId::new(object_arr);

        // Parse CapabilitySecret
        let secret_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
        if secret_bytes.len() != 32 {
            return Err(UriParseError::InvalidLength {
                component: "CapabilitySecret",
                expected: 32,
                actual: secret_bytes.len(),
            });
        }
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&secret_bytes);
        let capability_secret = CapabilitySecret::new(secret_arr);

        // Parse optional RevisionId
        let revision = if parts.len() > 2 {
            Some(RevisionId::new(parts[2].parse()?))
        } else {
            None
        };

        Ok(Self {
            object_id,
            capability_secret,
            revision,
        })
    }

    /// Returns the URI as a string.
    pub fn to_string(&self) -> String {
        let base = format!(
            "lux:obj:{}:{}",
            URL_SAFE_NO_PAD.encode(self.object_id.0),
            URL_SAFE_NO_PAD.encode(self.capability_secret.0)
        );

        match self.revision {
            Some(rev) => format!("{}:{}", base, rev.value()),
            None => base,
        }
    }

    /// Returns a URI for a specific revision.
    pub fn at_revision(&self, revision: RevisionId) -> Self {
        Self {
            object_id: self.object_id,
            capability_secret: self.capability_secret.clone(),
            revision: Some(revision),
        }
    }

    /// Returns a URI without a revision.
    pub fn without_revision(&self) -> Self {
        Self {
            object_id: self.object_id,
            capability_secret: self.capability_secret.clone(),
            revision: None,
        }
    }
}

impl std::fmt::Display for ObjectUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blob_uri_roundtrip() {
        let blob_id = BlobId::new([0x42; 32]);
        let uri = BlobUri::new(blob_id);
        let string = uri.to_string();
        let parsed = BlobUri::parse(&string).unwrap();
        assert_eq!(uri, parsed);
    }

    #[test]
    fn test_object_uri_roundtrip() {
        let object_id = ObjectId::new([0x11; 32]);
        let capability = CapabilitySecret::new([0x22; 32]);
        let uri = ObjectUri::new(object_id, capability);
        let string = uri.to_string();
        let parsed = ObjectUri::parse(&string).unwrap();
        assert_eq!(uri.object_id, parsed.object_id);
        assert_eq!(uri.capability_secret.0, parsed.capability_secret.0);
        assert_eq!(uri.revision, parsed.revision);
    }

    #[test]
    fn test_object_uri_with_revision() {
        let object_id = ObjectId::new([0x11; 32]);
        let capability = CapabilitySecret::new([0x22; 32]);
        let revision = RevisionId::new(42);
        let uri = ObjectUri::with_revision(object_id, capability, revision);
        let string = uri.to_string();
        assert!(string.ends_with(":42"));

        let parsed = ObjectUri::parse(&string).unwrap();
        assert_eq!(parsed.revision, Some(RevisionId::new(42)));
    }

    #[test]
    fn test_lux_uri_dispatch() {
        let blob_id = BlobId::new([0x42; 32]);
        let blob_uri = BlobUri::new(blob_id);
        let string = blob_uri.to_string();

        let parsed = LuxUri::parse(&string).unwrap();
        assert!(matches!(parsed, LuxUri::Blob(_)));

        let object_id = ObjectId::new([0x11; 32]);
        let capability = CapabilitySecret::new([0x22; 32]);
        let object_uri = ObjectUri::new(object_id, capability);
        let string = object_uri.to_string();

        let parsed = LuxUri::parse(&string).unwrap();
        assert!(matches!(parsed, LuxUri::Object(_)));
    }

    #[test]
    fn test_invalid_scheme() {
        let result = LuxUri::parse("http://example.com");
        assert!(matches!(result, Err(UriParseError::MissingScheme)));
    }

    #[test]
    fn test_invalid_type() {
        let result = LuxUri::parse("lux:unknown:data");
        assert!(matches!(result, Err(UriParseError::InvalidType(_))));
    }

    #[test]
    fn test_invalid_base64() {
        let result = BlobUri::parse("lux:blob:not-valid-base64!!!");
        assert!(matches!(result, Err(UriParseError::InvalidBase64(_))));
    }

    #[test]
    fn test_invalid_length() {
        // Too short
        let result = BlobUri::parse("lux:blob:AQID"); // Only 3 bytes
        assert!(matches!(result, Err(UriParseError::InvalidLength { .. })));
    }
}
