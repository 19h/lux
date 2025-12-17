//! Lux Protocol - Wire protocol and message definitions.
//!
//! This crate defines:
//! - Storage formats (StoredChunk, DAG nodes, Manifest)
//! - Blob encryption (convergent encryption per §13)
//! - DHT record types (NodeAnnouncement, ManifestAnnouncement, ChunkHolders)
//! - Storage leases
//! - Message framing for network transport

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

pub mod blob;
pub mod dag;
pub mod dht;
pub mod manifest;
pub mod messages;
pub mod storage;
pub mod uri;

pub use blob::{BlobEncryptor, BlobError, EncryptedBlob, EncryptedChunk};
pub use dag::{ChunkRefHashed, CiphertextCommitment, DagNode, EntryMetadata, EntryNode, InternalNode};
pub use dht::{
    ChunkAnnouncement, ChunkHolders, ChunkLocator, DhtRecord, DhtRecordBody,
    ManifestAnnouncement, NodeAnnouncement, StorageLease, StorageLeaseBody,
};
pub use manifest::{IdentityBinding, Manifest, ManifestBody};
pub use messages::{Message, MessageType};
pub use storage::StoredChunk;
pub use uri::{BlobUri, LuxUri, ObjectUri, UriParseError};
