//! Merkle DAG node types per specification §9.2.
//!
//! Defines the structure of the Merkle DAG used to represent files and directories.

use bytes::{Bytes, BytesMut};
use lux_core::encoding::{CanonicalDecode, CanonicalEncode, DecodeError};
use lux_core::{ChunkId, CiphertextHash, DagRef, Timestamp};
use serde::{Deserialize, Serialize};

/// Ciphertext commitment for storage verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiphertextCommitment {
    /// Merkle root of the ciphertext blocks
    pub merkle_root: [u8; 32],
    /// Total size of the ciphertext
    pub size: u64,
    /// Block size used for Merkle tree
    pub block_size: u32,
    /// Number of blocks
    pub block_count: u32,
}

impl CiphertextCommitment {
    /// Creates a simple commitment for a chunk.
    pub fn for_chunk(ciphertext_hash: &CiphertextHash, size: u64) -> Self {
        Self {
            merkle_root: ciphertext_hash.0,
            size,
            block_size: size as u32, // Single block
            block_count: 1,
        }
    }
}

impl CanonicalEncode for CiphertextCommitment {
    fn encode(&self, buf: &mut BytesMut) {
        self.merkle_root.encode(buf);
        self.size.encode(buf);
        self.block_size.encode(buf);
        self.block_count.encode(buf);
    }
}

impl CanonicalDecode for CiphertextCommitment {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            merkle_root: <[u8; 32]>::decode(buf)?,
            size: u64::decode(buf)?,
            block_size: u32::decode(buf)?,
            block_count: u32::decode(buf)?,
        })
    }
}

/// Reference to an encrypted chunk with all addressing information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkRefHashed {
    /// Plaintext identity: BLAKE3(plaintext_chunk)
    pub chunk_id: ChunkId,
    /// Storage address: BLAKE3(stored_bytes)
    pub ciphertext_hash: CiphertextHash,
    /// Integrity commitment
    pub commitment: CiphertextCommitment,
    /// Byte offset within the file
    pub offset: u64,
    /// Size of the plaintext chunk
    pub size: u32,
}

impl CanonicalEncode for ChunkRefHashed {
    fn encode(&self, buf: &mut BytesMut) {
        self.chunk_id.encode(buf);
        self.ciphertext_hash.encode(buf);
        self.commitment.encode(buf);
        self.offset.encode(buf);
        self.size.encode(buf);
    }
}

impl CanonicalDecode for ChunkRefHashed {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            chunk_id: ChunkId::decode(buf)?,
            ciphertext_hash: CiphertextHash::decode(buf)?,
            commitment: CiphertextCommitment::decode(buf)?,
            offset: u64::decode(buf)?,
            size: u32::decode(buf)?,
        })
    }
}

/// Internal node that aggregates child references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InternalNode {
    /// References to child nodes (leaves or other internals)
    pub children: Vec<DagRef>,
}

impl InternalNode {
    /// Creates a new internal node with the given children.
    pub fn new(children: Vec<DagRef>) -> Self {
        Self { children }
    }

    /// Returns the number of children.
    pub fn len(&self) -> usize {
        self.children.len()
    }

    /// Returns true if there are no children.
    pub fn is_empty(&self) -> bool {
        self.children.is_empty()
    }
}

impl CanonicalEncode for InternalNode {
    fn encode(&self, buf: &mut BytesMut) {
        self.children.encode(buf);
    }
}

impl CanonicalDecode for InternalNode {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            children: Vec::<DagRef>::decode(buf)?,
        })
    }
}

/// Metadata for a filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryMetadata {
    /// Unix file mode (permissions and type)
    pub mode: u32,
    /// Modification time
    pub mtime: Timestamp,
}

impl Default for EntryMetadata {
    fn default() -> Self {
        Self {
            mode: 0o644, // Regular file, rw-r--r--
            mtime: Timestamp::now(),
        }
    }
}

impl EntryMetadata {
    /// Creates metadata for a regular file.
    pub fn file(mode: u32, mtime: Timestamp) -> Self {
        Self { mode, mtime }
    }

    /// Creates metadata for a directory.
    pub fn directory(mtime: Timestamp) -> Self {
        Self {
            mode: 0o755 | 0o040000, // Directory with rwxr-xr-x
            mtime,
        }
    }

    /// Returns true if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.mode & 0o040000 != 0
    }

    /// Returns true if this is a regular file.
    pub fn is_file(&self) -> bool {
        self.mode & 0o100000 != 0
    }

    /// Returns true if this is a symlink.
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o120000 != 0
    }

    /// Returns the permission bits.
    pub fn permissions(&self) -> u32 {
        self.mode & 0o777
    }
}

impl CanonicalEncode for EntryMetadata {
    fn encode(&self, buf: &mut BytesMut) {
        self.mode.encode(buf);
        self.mtime.encode(buf);
    }
}

impl CanonicalDecode for EntryMetadata {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            mode: u32::decode(buf)?,
            mtime: Timestamp::decode(buf)?,
        })
    }
}

/// Entry node representing a named filesystem entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryNode {
    /// Entry name (filename or directory name)
    pub name: String,
    /// Entry metadata
    pub metadata: EntryMetadata,
    /// Reference to content (file data or directory listing)
    pub content: DagRef,
}

impl EntryNode {
    /// Creates a new entry node.
    pub fn new(name: String, metadata: EntryMetadata, content: DagRef) -> Self {
        Self {
            name,
            metadata,
            content,
        }
    }

    /// Creates an entry for an empty file.
    pub fn empty_file(name: String) -> Self {
        Self {
            name,
            metadata: EntryMetadata::default(),
            content: DagRef::empty(),
        }
    }

    /// Creates an entry for an empty directory.
    pub fn empty_directory(name: String) -> Self {
        Self {
            name,
            metadata: EntryMetadata::directory(Timestamp::now()),
            content: DagRef::empty(),
        }
    }
}

impl CanonicalEncode for EntryNode {
    fn encode(&self, buf: &mut BytesMut) {
        self.name.encode(buf);
        self.metadata.encode(buf);
        self.content.encode(buf);
    }
}

impl CanonicalDecode for EntryNode {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        Ok(Self {
            name: String::decode(buf)?,
            metadata: EntryMetadata::decode(buf)?,
            content: DagRef::decode(buf)?,
        })
    }
}

/// DAG node types per specification §9.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DagNode {
    /// Leaf node containing a chunk reference (tag = 0)
    Chunk(ChunkRefHashed),
    /// Internal node aggregating children (tag = 1)
    Internal(InternalNode),
    /// Entry node for filesystem entries (tag = 2)
    Entry(EntryNode),
}

impl DagNode {
    /// Returns the tag value for encoding.
    pub fn tag(&self) -> u32 {
        match self {
            DagNode::Chunk(_) => 0,
            DagNode::Internal(_) => 1,
            DagNode::Entry(_) => 2,
        }
    }

    /// Computes the DagRef for this node.
    pub fn dag_ref(&self) -> DagRef {
        DagRef::from_encoded(&self.to_vec())
    }
}

impl CanonicalEncode for DagNode {
    fn encode(&self, buf: &mut BytesMut) {
        self.tag().encode(buf);
        match self {
            DagNode::Chunk(chunk) => chunk.encode(buf),
            DagNode::Internal(internal) => internal.encode(buf),
            DagNode::Entry(entry) => entry.encode(buf),
        }
    }
}

impl CanonicalDecode for DagNode {
    fn decode(buf: &mut Bytes) -> Result<Self, DecodeError> {
        let tag = u32::decode(buf)?;
        match tag {
            0 => Ok(DagNode::Chunk(ChunkRefHashed::decode(buf)?)),
            1 => Ok(DagNode::Internal(InternalNode::decode(buf)?)),
            2 => Ok(DagNode::Entry(EntryNode::decode(buf)?)),
            _ => Err(DecodeError::InvalidEnumTag(tag)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dag_node_encoding() {
        let chunk_ref = ChunkRefHashed {
            chunk_id: ChunkId::new([0xAA; 32]),
            ciphertext_hash: CiphertextHash::new([0xBB; 32]),
            commitment: CiphertextCommitment::for_chunk(&CiphertextHash::new([0xBB; 32]), 1000),
            offset: 0,
            size: 1000,
        };

        let node = DagNode::Chunk(chunk_ref);
        let encoded = node.to_vec();
        let decoded = DagNode::from_bytes(&encoded).unwrap();

        assert_eq!(node, decoded);
    }

    #[test]
    fn test_internal_node() {
        let children = vec![
            DagRef::new([0x11; 32]),
            DagRef::new([0x22; 32]),
            DagRef::new([0x33; 32]),
        ];

        let internal = InternalNode::new(children.clone());
        let node = DagNode::Internal(internal);

        let encoded = node.to_vec();
        let decoded = DagNode::from_bytes(&encoded).unwrap();

        if let DagNode::Internal(decoded_internal) = decoded {
            assert_eq!(decoded_internal.children, children);
        } else {
            panic!("Expected Internal node");
        }
    }

    #[test]
    fn test_entry_node() {
        let entry = EntryNode::new(
            "test.txt".to_string(),
            EntryMetadata::file(0o644, Timestamp::new(1700000000000)),
            DagRef::new([0xFF; 32]),
        );

        let node = DagNode::Entry(entry);
        let encoded = node.to_vec();
        let decoded = DagNode::from_bytes(&encoded).unwrap();

        assert_eq!(node, decoded);
    }

    #[test]
    fn test_dag_ref_computation() {
        let node1 = DagNode::Entry(EntryNode::empty_file("a.txt".to_string()));
        let node2 = DagNode::Entry(EntryNode::empty_file("b.txt".to_string()));

        let ref1 = node1.dag_ref();
        let ref2 = node2.dag_ref();

        // Different content should produce different refs
        assert_ne!(ref1, ref2);

        // Same content should produce same ref
        let node1_copy = DagNode::Entry(EntryNode::empty_file("a.txt".to_string()));
        assert_eq!(node1.dag_ref(), node1_copy.dag_ref());
    }

    #[test]
    fn test_metadata_types() {
        let file_meta = EntryMetadata::file(0o644 | 0o100000, Timestamp::now());
        assert!(file_meta.is_file());
        assert!(!file_meta.is_dir());

        let dir_meta = EntryMetadata::directory(Timestamp::now());
        assert!(dir_meta.is_dir());
        assert!(!dir_meta.is_file());
    }
}
